"""Read a Rockwell Logix 5000 L5K text export into the normalised model.

Keywords, statement shapes and attribute names follow the L5K sections of
Rockwell's Logix 5000 Controllers Import/Export Reference Manual, publication
1756-RM014D-EN-P (September 2025), read directly (PDF text) from
literature.rockwellautomation.com on 2026-11-08. The manual's printed pages are
given next to each reader below and in docs/logic-compare.md, which also lists
what is treated opaquely. What RM014 does not document is compared by hash and
reported as such, never parsed by guess.

The export is plain text and is read as hostile input: size, line and nesting
caps, no XML, nothing evaluated, every loop advances the cursor. A malformed
file produces an InputFormatError (exit 1) or an opaque "unparsed" field,
never a silently skipped block.

Entity paths follow the L5X reader (Tag:, Program:X/Routine:Y, AOI:, Task:,
Module:, DataType:) so reports read the same. An L5K is still compared only
with an L5K: RM014 spells the same attributes differently in the two formats
(Yes/No against true/false, Major against MajorRev, MODE against TestEdits,
"1 (enabled) or 0 (disabled)" against true/false, p.41) and encodes tag data
differently (value lists against decorated XML), so a cross-format comparison
would report differences that are not changes.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field

from .l5x import AOI_DOC, AOI_UNCOUNTED, CONTROLLER_MODULE, CONTROLLER_TASKING, CONTROLLER_UNCOUNTED, META_ATTRS, PROGRAM_META
from .model import DOC, FieldVal, Model, Routine, Unit, normalise_code, sha, squash, text_units
from .safexml import MAX_BYTES_DEFAULT, MAX_DEPTH_DEFAULT, InputFormatError, UnsafeInputError

FORMAT = "L5K"
MAX_LINES_DEFAULT = 2_000_000
_SNIFF_BYTES = 256 * 1024

# RM014 ch.8 "L5K RUNG structure" (p.208): rung comment RC and the rung-type table.
RUNG_TYPES = ("N", "I", "D", "IR", "rR", "R", "rI", "rN", "e", "er", "d")
# RM014 ch.9-11: LOGIC (Online_Edit_Type := Orig | Test | Pend) blocks (p.228, p.259, p.289);
# the L5X names of the same states, so both readers label edit states alike.
EDIT_STATES = {"Orig": "", "Test": "TestEdits", "Pend": "PendingEdits"}
ROUTINE_KEYWORDS = {"ROUTINE": "RLL", "ST_ROUTINE": "ST", "FBD_ROUTINE": "FBD", "SFC_ROUTINE": "SFC", "ESQ_ROUTINE": "Sequence"}
# RM014 ch.6 tag attribute tables (p.123 ff.): generic, produced, consumed and the
# safety consume attributes shown in the safety TAG examples (p.175). Attributes
# outside this set are type-specific configuration (alarm, message, axis ...),
# which the L5K chapter places in the tag statement (p.131: "tag attributes for an
# ALARM_ANALOG tag are in the tag statement").
TAG_GENERIC = {k.lower() for k in (
    "Name", "TagType", "DataType", "AliasFor", "Dimensions", "Class", "Radix", "PLCMappingFile", "PLC2Mapping",
    "ProgrammaticallySendEventTrigger", "Unicast", "UnicastPermitted", "Usage", "Sequencing", "ExternalAccess",
    "OpcUaAccess", "Max", "Min", "Constant", "PermissionSet", "TrackingGroups",
    "ProduceCount", "MinimumRPI", "MaximumRPI", "DefaultRPI", "Producer", "RemoteTag", "RemoteFile", "RPI",
    "IncludeConnectionStatus", "TimeoutMultiplier", "NetworkDelayMultiplier", "ReactionTimeLimit",
    "Required", "Visible", "Type", "DefaultData")}
TAG_DOC = {"description", "comment", "engineeringunit", "state0", "state1"}
# RM014 "Project documentation" (p.51) lists alarm messages among documentation.
ALARM_MESSAGE_PREFIXES = ("ALMMSG", "ALMSG")
_CANON = {k.lower(): k for k in (
    "Radix", "Description", "Comment", "EngineeringUnit", "State0", "State1", "DefaultData", "Max", "Min", "Constant",
    "ExternalAccess", "Usage", "Required", "Visible", "TrackingGroups", "PermissionSet", "Class", "OpcUaAccess",
    "EncodedType", "Name", "Type", "Online_Edit_Type", "RevisionNote", "AdditionalHelpText", "EndPoint1", "EndPoint2")}
_CTRL_UNCOUNTED = {k.lower() for k in CONTROLLER_UNCOUNTED}
_CTRL_MODULE = {k.lower() for k in CONTROLLER_MODULE} | {"major"}        # L5K spells MajorRev as Major (p.57)
_CTRL_TASKING = {k.lower() for k in CONTROLLER_TASKING}
_AOI_UNCOUNTED = {k.lower() for k in AOI_UNCOUNTED}
_AOI_DOC = {k.lower() for k in AOI_DOC}
_PROGRAM_META = {k.lower() for k in PROGRAM_META}
_META_ATTRS = {k.lower() for k in META_ATTRS}

_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z0-9_]+)*")
_LINE_WORD = re.compile(r"[ \t\r]*([A-Za-z_][A-Za-z0-9_]*)")
_SCAN = re.compile(r"[()\[\];\"'\n]")
_GROUP = re.compile(r"[()\[\]\"']")
_UPPER_KW = re.compile(r"[A-Z][A-Z0-9_]*")
_RUNG = re.compile(r"(RC|IR|rR|rI|rN|er|N|I|D|R|e|d)\s*:(.*)", re.S)
_STRING = re.compile(r'"(?:[^"$\n]|\$.)*"')
_LOGIC_LINE = re.compile(r"^[ \t]*LOGIC\s*\(([^)\n]*)\)", re.M)
_END_LOGIC_LINE = re.compile(r"^[ \t]*END_LOGIC\b", re.M)
_DOC_BLOCKS = re.compile(r"\b(TEXT_BOX|ATTACHMENT)\b.*?\bEND_\1\b", re.S)
_DESC_ATTR = re.compile(r"\bDescription\s*:=\s*\"(?:[^\"$\n]|\$.)*\"\s*,?")
_REMARK_LINE = re.compile(r"^[ \t]*REMARK[ \t]*,[^\n]*\n?", re.M)
_PRE_REMARK = re.compile(r"REMARK[ \t]*,[^\n]*\n?")
_PRE_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*[ \t]*:=[ \t]*[^;\n]{0,400};")
_CONTROLLER = re.compile(r"CONTROLLER\s+[A-Za-z_][A-Za-z0-9_:]*")
_WS = re.compile(r"\s+")


# ------------------------------------------------------------------ loading

@dataclass
class LoadedText:
    path: str
    text: str
    sha256: str
    size: int
    encoding: str
    lines: int
    notes: list = field(default_factory=list)


def _decode(data: bytes) -> tuple[str, str, list]:
    notes: list = []
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="strict"), "utf-8", notes
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le"), "utf-16-le", notes
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be"), "utf-16-be", notes
    try:
        return data.decode("utf-8"), "utf-8", notes
    except UnicodeDecodeError:
        # RM014 p.22: "use any text editor that supports UTF8 file format to modify the
        # project"; a file that is not UTF-8 is read as windows-1252 and the report says so.
        notes.append("file is not valid UTF-8 (RM014 names UTF8 for .L5K text); decoded as windows-1252, "
                     "so non-ASCII description text may read differently")
        return data.decode("cp1252", errors="replace"), "cp1252", notes


def sniff(path: str, size: int = _SNIFF_BYTES) -> str:
    """The decoded start of a file, for content-based format detection."""
    with open(path, "rb") as fh:
        head = fh.read(size)
    try:
        text, _, _ = _decode(head)
    except UnicodeDecodeError:
        text = head.decode("utf-8", errors="replace")
    return text


def preamble_end(text: str, max_steps: int = 2000) -> int:
    """Index of the CONTROLLER statement, or -1.

    RM014 documents no L5K file header: every L5K example in the manual begins
    at CONTROLLER (p.55). What an export writes before it (a comment banner and
    'name := value;' lines) is skipped here and kept as provenance by parse().
    Skipped before CONTROLLER: whitespace, REMARK lines (p.50), (* *) comment
    blocks and 'name := value;' lines. Anything else means not an L5K file.
    """
    i, n = 0, len(text)
    for _ in range(max_steps):
        m = _WS.match(text, i)
        if m:
            i = m.end()
        if i >= n:
            return -1
        if text.startswith("(*", i):
            j = text.find("*)", i + 2)
            if j < 0:
                return -1
            i = j + 2
            continue
        if _CONTROLLER.match(text, i):
            return i
        m = _PRE_REMARK.match(text, i) or _PRE_ASSIGN.match(text, i)
        if m is None:
            return -1
        i = m.end()
    return -1


def is_l5k(text: str) -> bool:
    return preamble_end(text) >= 0


def load(path: str, *, max_bytes: int = MAX_BYTES_DEFAULT, max_lines: int = MAX_LINES_DEFAULT) -> LoadedText:
    try:
        st = os.stat(path)
    except OSError as exc:
        raise InputFormatError(f"cannot read {path}: {exc.strerror}") from None
    if not os.path.isfile(path):
        raise InputFormatError(f"{path} is not a regular file")
    if st.st_size > max_bytes:
        raise UnsafeInputError(f"{path} is {st.st_size} bytes, over the {max_bytes}-byte limit")
    with open(path, "rb") as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UnsafeInputError(f"{path} grew past the {max_bytes}-byte limit while being read")
    digest = hashlib.sha256(data).hexdigest()
    if b"\x00" in data:
        raise InputFormatError(f"{path} contains NUL bytes; an L5K export is plain text")
    try:
        text, encoding, notes = _decode(data)
    except UnicodeDecodeError as exc:
        raise InputFormatError(f"cannot decode {path}: {exc}") from None
    del data
    lines = text.count("\n") + 1
    if lines > max_lines:
        raise UnsafeInputError(f"{path}: more than {max_lines} lines")
    return LoadedText(path=path, text=text, sha256=digest, size=st.st_size, encoding=encoding, lines=lines, notes=notes)


# ------------------------------------------------------------------ text helpers

def _string_end(s: str, i: int) -> int:
    """i is at an opening quote. Index just past the closing quote; a quote
    that is not closed on its line ends at the newline (RM014 p.50: control
    characters inside a description are written as $ escapes, so a literal
    never spans lines)."""
    q, j, n = s[i], i + 1, len(s)
    while j < n:
        c = s[j]
        if c == "$":
            j += 2
            continue
        if c == q:
            return j + 1
        if c == "\n":
            return j
        j += 1
    return n


def unescape(text: str) -> str:
    """RM014 p.50 '$' escapes inside descriptions: $$ $Q $L $N $P $R $T $xxxx."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "$" and i + 1 < n:
            d = text[i + 1]
            if d == "$":
                out.append("$")
            elif d in "Qq":
                out.append('"')
            elif d == "'":
                out.append("'")
            elif d in "LlIiNn":
                out.append("\n")
            elif d in "Pp":
                out.append("\f")
            elif d in "Rr":
                out.append("\r")
            elif d in "Tt":
                out.append("\t")
            elif re.match(r"[0-9A-Fa-f]{4}", text[i + 1:i + 5]):
                out.append(chr(int(text[i + 1:i + 5], 16)))
                i += 5
                continue
            else:
                out.append(c)
                i += 1
                continue
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def split_top(text: str, sep: str) -> list:
    """Split at a one-character separator outside quotes, parentheses and brackets."""
    parts, depth, start, j, n = [], 0, 0, 0, len(text)
    while j < n:
        c = text[j]
        if c in "\"'":
            j = _string_end(text, j)
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth = max(0, depth - 1)
        elif c == sep and depth == 0:
            parts.append(text[start:j])
            start = j + 1
        j += 1
    parts.append(text[start:])
    return parts


def _find_top(text: str, needle: str) -> int:
    """Index of needle outside quotes, parentheses and brackets, or -1. The
    needle may itself be an opening bracket."""
    depth, j, n = 0, 0, len(text)
    while j < n:
        c = text[j]
        if c in "\"'":
            j = _string_end(text, j)
            continue
        if depth == 0 and text.startswith(needle, j):
            return j
        if c in "([":
            depth += 1
        elif c in ")]":
            depth = max(0, depth - 1)
        j += 1
    return -1


def clean_value(raw: str) -> str:
    """An attribute value as exported: a single quoted string loses its quotes
    and $ escapes; anything else keeps its text with whitespace collapsed."""
    v = raw.strip()
    if len(v) >= 2 and v[0] == '"' and _string_end(v, 0) == len(v):
        return squash(unescape(v[1:-1]))
    return normalise_code(v)


def parse_attrs(raw: str) -> list:
    """'(key := value, key := value)' content -> [(key, value)] in order.
    An item without ':=' is kept as (item, '')."""
    out = []
    for item in split_top(raw, ","):
        item = item.strip()
        if not item:
            continue
        idx = _find_top(item, ":=")
        if idx < 0:
            out.append((squash(item), ""))
        else:
            out.append((squash(item[:idx]), clean_value(item[idx + 2:])))
    return out


def canon_name(key: str) -> str:
    """Attribute names appear in both cases in RM014's examples (RADIX / Radix);
    known names are reported in one spelling, others as written."""
    return _CANON.get(key.lower(), key)


def attrs_string(attrs: list, skip: tuple = ()) -> str:
    return "; ".join(f"{canon_name(k)}={v}" for k, v in sorted(attrs) if k.lower() not in {s.lower() for s in skip})


def _is_doc_key(key: str) -> bool:
    base = re.split(r"[.\[]", key, maxsplit=1)[0].lower()
    return base in TAG_DOC


def _is_alarm_message(key: str) -> bool:
    return key.upper().startswith(ALARM_MESSAGE_PREFIXES)


def edit_sections(body: str) -> list:
    """Split a routine body into (edit state, text) pairs from its LOGIC
    (Online_Edit_Type := ...) ... END_LOGIC blocks (RM014 p.226, 258, 286).
    Without LOGIC blocks the whole body is one section with state ''."""
    sections, pos, state, buf = [], 0, "", []
    for m in re.finditer(r"^[ \t]*(LOGIC\s*\(([^)\n]*)\)|END_LOGIC\b)[^\n]*", body, re.M):
        buf.append(body[pos:m.start()])
        if m.group(1).startswith("LOGIC"):
            if "".join(buf).strip():
                sections.append((state, "".join(buf)))
            attrs = dict(parse_attrs(m.group(2)))
            state = next((v for k, v in attrs.items() if k.lower() == "online_edit_type"), "?")
            buf = []
        else:
            sections.append((state, "".join(buf)))
            state, buf = "", []
        pos = m.end()
    buf.append(body[pos:])
    if "".join(buf).strip() or not sections:
        sections.append((state, "".join(buf)))
    return sections


def _strip_doc(body: str) -> str:
    """Documentation inside a graphical body: TEXT_BOX and ATTACHMENT blocks
    (RM014 p.242-243, p.274-275) and Description attributes."""
    return _DESC_ATTR.sub("", _DOC_BLOCKS.sub("", body))


def body_hash(body: str) -> str:
    return sha(normalise_code(body))


# ------------------------------------------------------------------ parser

class _Cursor:
    def __init__(self, text: str, start: int, path: str, max_depth: int):
        self.s, self.i, self.n, self.path, self.max_depth = text, start, len(text), path, max_depth
        self._block_rx: dict = {}

    def line(self) -> int:
        return self.s.count("\n", 0, self.i) + 1

    def err(self, msg: str) -> ValueError:
        return ValueError(f"line {self.line()}: {msg}")

    def _depth(self, depth: int) -> int:
        if depth > self.max_depth:
            raise UnsafeInputError(f"{self.path} line {self.line()}: nesting deeper than {self.max_depth} levels")
        return depth

    def skip_ws(self) -> None:
        m = _WS.match(self.s, self.i)
        if m:
            self.i = m.end()

    def at_end(self) -> bool:
        self.skip_ws()
        return self.i >= self.n

    def peek_word(self):
        self.skip_ws()
        m = _WORD.match(self.s, self.i)
        return m.group(0) if m else None

    def word(self) -> str:
        w = self.peek_word()
        if w is None:
            raise self.err(f"expected a name or keyword, found {self.s[self.i:self.i + 20]!r}")
        self.i += len(w)
        return w

    def peek_char(self) -> str:
        self.skip_ws()
        return self.s[self.i] if self.i < self.n else ""

    def group(self) -> str:
        """Text inside a parenthesised attribute list, cursor left after ')'."""
        self.skip_ws()
        if self.peek_char() != "(":
            raise self.err("expected '('")
        depth, j = 0, self.i
        while True:
            m = _GROUP.search(self.s, j)
            if m is None:
                raise self.err("unterminated '('")
            c, k = m.group(0), m.start()
            if c in "\"'":
                j = _string_end(self.s, k)
                continue
            if c in "([":
                depth = self._depth(depth + 1)
            else:
                depth -= 1
                if depth == 0:
                    inner = self.s[self.i + 1:k]
                    self.i = k + 1
                    return inner
            j = k + 1

    def opt_group(self) -> list:
        return parse_attrs(self.group()) if self.peek_char() == "(" else []

    def statement(self, stops: tuple = ()) -> str:
        """Text up to a ';' outside quotes and brackets (consumed), or up to a
        line that begins with END_* or a stop keyword (not consumed)."""
        self.skip_ws()
        depth, j = 0, self.i
        while True:
            m = _SCAN.search(self.s, j)
            if m is None:
                text, self.i = self.s[self.i:], self.n
                return text
            c, k = m.group(0), m.start()
            if c in "\"'":
                j = _string_end(self.s, k)
                continue
            if c in "([":
                depth = self._depth(depth + 1)
            elif c in ")]":
                depth = max(0, depth - 1)
            elif c == ";" and depth == 0:
                text, self.i = self.s[self.i:k], k + 1
                return text
            elif c == "\n":
                m2 = _LINE_WORD.match(self.s, k + 1)
                if m2 and (m2.group(1).startswith("END_") or m2.group(1) in stops):
                    text, self.i = self.s[self.i:k], k + 1
                    return text
            j = k + 1

    def has_end(self, kw: str) -> bool:
        return re.compile(rf"\bEND_{re.escape(kw)}\b").search(self.s, self.i) is not None

    def block_body(self, kw: str) -> str:
        """Text up to the matching END_<kw> (consumed). Same-keyword nesting is
        counted; quoted text and ' lines are skipped to their line end."""
        rx = self._block_rx.get(kw)
        if rx is None:
            rx = self._block_rx[kw] = re.compile(rf"[\"']|\b(END_)?{re.escape(kw)}\b")
        depth, j = 1, self.i
        while True:
            m = rx.search(self.s, j)
            if m is None:
                raise self.err(f"{kw} without END_{kw}")
            if m.group(0) in "\"'":
                j = _string_end(self.s, m.start())
                continue
            if m.group(1):
                depth -= 1
                if depth == 0:
                    body = self.s[self.i:m.start()]
                    self.i = m.end()
                    return body
            else:
                depth = self._depth(depth + 1)
            j = m.end()


class _Reader:
    def __init__(self, model: Model, path: str, max_depth: int):
        self.model, self.path, self.max_depth = model, path, max_depth
        self.unparsed: dict = {}
        self.parameter_connections: list = []
        self.quick_watch: list = []

    # ---- generic fallbacks

    def _unparsed(self, ent_path: str, text: str) -> None:
        self.unparsed.setdefault(ent_path, []).append(text)

    def _unknown(self, c: _Cursor, w: str, ent_path: str, cls: str) -> None:
        """A keyword this reader does not model: a KEYWORD ... END_KEYWORD block or
        a statement, compared by hash and named in a reader note."""
        ent = self.model.entities[ent_path]
        if _UPPER_KW.fullmatch(w) and c.has_end(w):
            name = c.peek_word()
            label = w
            if name and name != f"END_{w}" and not name.startswith("END_"):
                c.word()
                label = f"{w}:{name}"
            attrs = c.group() if c.peek_char() == "(" else ""
            body = c.block_body(w)
            ent.set(label, cls, body_hash(attrs + "\n" + body), opaque=True,
                    note=f"{w} block is not modelled from RM014 by this tool: compared by hash")
            self.model.note(f"{ent_path}: {w} block compared by hash only (not modelled)")
        else:
            self._unparsed(ent_path, w + c.statement())

    def _finish_unparsed(self) -> None:
        for ent_path, items in self.unparsed.items():
            ent = self.model.entities.get(ent_path)
            if ent is None:
                continue
            ent.set("Unparsed", ent.cls, sha("\n".join(normalise_code(t) for t in items)), opaque=True,
                    note=f"{len(items)} statement(s) this reader could not place: compared by hash")
            first = squash(items[0])[:60]
            self.model.note(f"{ent_path}: {len(items)} unparsed statement(s) compared by hash only (first: {first!r})")

    # ---- tags (RM014 ch.6 L5K TAG structure p.123, initial value p.173, examples p.175;
    #      ch.5 PARAMETERS p.103 and LOCAL_TAGS p.110 share the statement shape)

    def _tag_statement(self, stmt: str, prefix: str, kind: str, cls: str, value_cls: str):
        stmt = stmt.strip()
        if not stmt:
            return None
        idx = _find_top(stmt, ":=")
        left, right = (stmt[:idx], stmt[idx + 2:]) if idx >= 0 else (stmt, "")
        pidx = _find_top(left, "(")
        head = left[:pidx] if pidx >= 0 else left
        attrs = parse_attrs(left[pidx + 1:left.rfind(")")]) if pidx >= 0 and left.rfind(")") > pidx else []
        toks = head.split()
        if not toks or not _WORD.fullmatch(toks[0]) or _UPPER_KW.fullmatch(toks[0]) and toks[0] in ROUTINE_KEYWORDS:
            return stmt
        name, alias, typ, dims = toks[0], None, None, None
        rest = toks[1:]
        if len(rest) >= 2 and rest[0] == "OF":
            alias, rest = rest[1], rest[2:]
        if rest and rest[0] == ":" and len(rest) >= 2:
            typ, rest = rest[1], rest[2:]
        elif rest and rest[0].startswith(":") and len(rest[0]) > 1:
            typ, rest = rest[0][1:], rest[1:]
        if typ and "[" in typ:
            typ, dims = typ[:typ.index("[")], typ[typ.index("["):].strip("[]")
        ent = self.model.entity(f"{prefix}:{name}", kind, cls)
        if alias:
            ent.set("AliasFor", cls, alias)
        if typ:
            ent.set("DataType", cls, typ)
        if dims is not None:
            ent.set("Dimensions", cls, dims)
        if rest:
            ent.set("UnparsedHead", cls, " ".join(rest), note="tokens in the tag statement this reader did not expect")
        params, constant = [], False
        for k, v in attrs:
            kl = k.lower()
            if kl == "radix":
                ent.set("Radix", DOC, v, note="display style only")
            elif _is_alarm_message(k):
                ent.set(k, DOC, v, note="alarm message text")
            elif _is_doc_key(k):
                ent.set(canon_name(k), DOC, v)
            elif kl in _META_ATTRS:
                ent.set(canon_name(k), "metadata", v)
            elif kl == "defaultdata":
                ent.set("DefaultData", value_cls, v)
            elif kl in TAG_GENERIC:
                if kl == "constant":
                    constant = v.lower() in ("yes", "1", "true")
                ent.set(canon_name(k), cls, v)
            else:
                params.append(f"{k}={v}")
        if params:
            ent.set("Parameters", value_cls, "\n".join(params),
                    note="type-specific tag attributes in the tag statement (alarm, message, axis ...)")
        if right:
            parts = split_top(right, ",")
            ent.set("Value", value_cls, normalise_code(parts[0]), note="constant tag" if constant else "")
            for part in parts[1:]:
                j = _find_top(part, ":=")
                if j < 0:
                    ent.set("UnparsedValue", cls, normalise_code(part))
                    continue
                k, v = squash(part[:j]), normalise_code(part[j + 2:])
                if k.lower() == "tagforcedata":
                    ent.set("Force", value_cls, v, note="force data")
                else:
                    ent.set(k, cls, v)
        return None

    def _tag_block(self, c: _Cursor, prefix: str, kind: str, cls: str, value_cls: str, ent_path: str) -> list:
        body = c.block_body("TAG" if kind == "tag" else ("PARAMETERS" if kind == "aoi-parameter" else "LOCAL_TAGS"))
        order = []
        for stmt in split_top(body, ";"):
            if not stmt.strip():
                continue
            left = self._tag_statement(stmt, prefix, kind, cls, value_cls)
            if left is None:
                order.append(stmt.strip().split()[0])
            else:
                self._unparsed(ent_path, left)
        return order

    # ---- data types (RM014 ch.3 L5K datatype structure p.72, member structure p.74, example p.77)

    def _datatype(self, c: _Cursor) -> None:
        name = c.word()
        attrs = c.opt_group()
        ent = self.model.entity(f"DataType:{name}", "datatype", "interface")
        for k, v in attrs:
            if k.lower() in ("description", "engineeringunit"):
                ent.set(canon_name(k), DOC, v)
            else:
                ent.set(k, "interface", v)
        order = []
        for stmt in split_top(c.block_body("DATATYPE"), ";"):
            s = stmt.strip()
            if not s:
                continue
            pidx = _find_top(s, "(")
            head = s[:pidx] if pidx >= 0 else s
            mattrs = parse_attrs(s[pidx + 1:s.rfind(")")]) if pidx >= 0 and s.rfind(")") > pidx else []
            toks = head.split()
            if len(toks) >= 2 and toks[0] == "BIT":
                # BIT <BitName> <HostMemberName> : <BitPosition> [(Attributes)];
                mname = toks[1]
                host = toks[2] if len(toks) > 2 else "?"
                pos = toks[-1] if len(toks) > 3 and toks[-2] == ":" else "?"
                desc = f"DataType=BIT; Target={host}; BitNumber={pos}"
            elif len(toks) >= 2:
                typ, mname = toks[0], toks[1]
                dims = ""
                if "[" in mname:
                    mname, dims = mname[:mname.index("[")], mname[mname.index("["):].strip("[]")
                desc = f"DataType={typ}" + (f"; Dimension={dims}" if dims else "")
            else:
                self._unparsed(f"DataType:{name}", s)
                continue
            order.append(mname)
            plain = []
            for k, v in mattrs:
                kl = k.lower()
                if kl == "radix":
                    ent.set(f"Member:{mname}/Radix", DOC, v, note="display style only")
                elif kl in ("description", "engineeringunit", "state0", "state1"):
                    ent.set(f"Member:{mname}/{canon_name(k)}", DOC, v)
                else:
                    plain.append(f"{k}={v}")
            ent.set(f"Member:{mname}", "interface", "; ".join([desc] + plain))
        ent.set("MemberOrder", "interface", ", ".join(order))

    # ---- modules (RM014 ch.4 L5K MODULE structure p.80, CONNECTION p.88, example p.93)

    def _module(self, c: _Cursor) -> None:
        name = c.word()
        attrs = c.opt_group()
        path = f"Module:{name}"
        ent = self.model.entity(path, "module", "module")
        for k, v in attrs:
            if k.lower() == "description":
                ent.set("Description", DOC, v)
            else:
                ent.set(k, "module", v)
        while True:
            w = c.peek_word()
            if w is None:
                if c.at_end():
                    raise c.err("MODULE without END_MODULE")
                self._unparsed(path, c.statement(("CONNECTION",)))
                continue
            if w == "END_MODULE":
                c.word()
                return
            if w == "CONNECTION":
                c.word()
                cn = c.word()
                ent.set(f"Connection:{cn}", "module", attrs_string(c.opt_group()) or "(no attributes)")
                for stmt in split_top(c.block_body("CONNECTION"), ";"):
                    s = stmt.strip()
                    if not s:
                        continue
                    j = _find_top(s, ":=")
                    k = squash(s[:j]) if j >= 0 else ""
                    v = normalise_code(s[j + 2:]) if j >= 0 else ""
                    kl = k.lower()
                    if kl in ("inputdata", "outputdata"):
                        ent.set(f"Connection:{cn}/{canon_name(k) if kl != 'inputdata' else 'InputData'}", "value", v)
                    elif kl in ("inputforcedata", "outputforcedata"):
                        label = "InputData" if kl.startswith("input") else "OutputData"
                        ent.set(f"Connection:{cn}/{label}/Force", "value", v, note="force data")
                    else:
                        self._unparsed(path, s)
                continue
            if w in ("ConfigData", "ConfigScript", "ExtendedProp"):
                s = c.word() + c.statement(("CONNECTION", "ConfigData", "ConfigScript", "ExtendedProp"))
                j = _find_top(s, ":=")
                v = normalise_code(s[j + 2:]) if j >= 0 else ""
                if w == "ExtendedProp":
                    ent.set("ExtendedProp", "module", sha(v), opaque=True, note="profile data in XML text: compared by hash")
                else:
                    ent.set(w, "module", v)
                continue
            c.word()
            self._unknown(c, w, path, "module")

    # ---- Add-On Instructions (RM014 ch.5 structure p.97, PARAMETERS p.103, HISTORY_ENTRY p.108,
    #      LOCAL_TAGS p.110, ENCODED_DATA p.112, examples p.115-121)

    def _aoi_attrs(self, ent, attrs: list) -> None:
        for k, v in attrs:
            kl = k.lower()
            if kl in ("encodedtype", "name"):
                continue
            if kl in _AOI_UNCOUNTED:
                ent.set(canon_name(k), "metadata", v, counted=False)
            elif kl in _AOI_DOC:
                ent.set(canon_name(k), DOC, v)
            else:
                ent.set(k, "aoi", v)

    def _history(self, c: _Cursor, ent, entries: list) -> None:
        attrs = c.opt_group()
        tail = c.block_body("HISTORY_ENTRY")
        entries.append(attrs_string(attrs, skip=("Description",)))
        for k, v in attrs:
            if k.lower() == "description":
                ent.set(f"SignatureHistory[{len(entries) - 1}]/Description", DOC, v)
        if tail.strip():
            self._unparsed(ent.path, tail)

    def _aoi(self, c: _Cursor) -> None:
        name = c.word()
        attrs = c.opt_group()
        prefix = f"AOI:{name}"
        ent = self.model.entity(prefix, "aoi", "aoi")
        ent.set("Protection", "aoi", "none")
        self._aoi_attrs(ent, attrs)
        entries: list = []
        while True:
            w = c.peek_word()
            if w is None:
                if c.at_end():
                    raise c.err("ADD_ON_INSTRUCTION_DEFINITION without END_ADD_ON_INSTRUCTION_DEFINITION")
                self._unparsed(prefix, c.statement())
                continue
            if w == "END_ADD_ON_INSTRUCTION_DEFINITION":
                c.word()
                break
            c.word()
            if w == "HISTORY_ENTRY":
                self._history(c, ent, entries)
            elif w == "PARAMETERS":
                ent.set("ParameterOrder", "aoi", ", ".join(self._tag_block(c, f"{prefix}/Parameter", "aoi-parameter", "aoi", "aoi", prefix)))
            elif w == "LOCAL_TAGS":
                ent.set("LocalTagOrder", "aoi", ", ".join(self._tag_block(c, f"{prefix}/LocalTag", "aoi-localtag", "aoi", "aoi", prefix)))
            elif w in ROUTINE_KEYWORDS:
                self._routine(c, w, f"{prefix}/", "aoi")
            elif w == "ENCRYPTION_INFO":
                attrs2 = c.group() if c.peek_char() == "(" else ""
                body = c.block_body(w) if c.has_end(w) else c.statement()
                ent.set("EncryptionInfo", "aoi", body_hash(attrs2 + body), opaque=True,
                        note="license-based source protection details: compared by hash")
                self.model.note(f"{prefix}: ENCRYPTION_INFO present (protected content exported in plain text)")
            else:
                self._unknown(c, w, prefix, "aoi")
        if entries:
            ent.set("SignatureHistory", "metadata", " | ".join(entries))

    def _encoded(self, c: _Cursor, prefix: str, cls: str, ent_path: str) -> None:
        """ENCODED_DATA (EncodedType := ADD_ON_INSTRUCTION_DEFINITION | ROUTINE, Name := ..., ...)
        ... END_ENCODED_DATA (RM014 p.112 and p.201). The payload is encrypted and
        compared by hash; PARAMETERS and HISTORY_ENTRY, which RM014's example (p.115)
        shows in plain text, are read."""
        attrs = c.opt_group()
        body = c.block_body("ENCODED_DATA")
        amap = {k.lower(): v for k, v in attrs}
        etype, name = amap.get("encodedtype", "?"), amap.get("name", "?")
        if etype == "ADD_ON_INSTRUCTION_DEFINITION":
            apath = f"AOI:{name}"
            ent = self.model.entity(apath, "aoi", "aoi")
            ent.set("Protection", "aoi", "encoded")
            self._aoi_attrs(ent, attrs)
            sub = _Cursor(body, 0, self.path, self.max_depth)
            entries: list = []
            payload: list = []
            while not sub.at_end():
                w = sub.peek_word()
                if w == "HISTORY_ENTRY":
                    sub.word()
                    self._history(sub, ent, entries)
                elif w == "PARAMETERS":
                    sub.word()
                    ent.set("ParameterOrder", "aoi", ", ".join(self._tag_block(sub, f"{apath}/Parameter", "aoi-parameter", "aoi", "aoi", apath)))
                elif w == "LOCAL_TAGS":
                    sub.word()
                    ent.set("LocalTagOrder", "aoi", ", ".join(self._tag_block(sub, f"{apath}/LocalTag", "aoi-localtag", "aoi", "aoi", apath)))
                else:
                    # the encoded payload: text up to the next line that starts a keyword block
                    m = re.compile(r"^[ \t]*(HISTORY_ENTRY|PARAMETERS|LOCAL_TAGS)\b", re.M).search(sub.s, sub.i + 1)
                    end = m.start() if m else sub.n
                    payload.append(sub.s[sub.i:end])
                    sub.i = end
            if entries:
                ent.set("SignatureHistory", "metadata", " | ".join(entries))
            ent.set("EncodedContent", "aoi", sha(squash("".join(payload))), opaque=True,
                    note="encoded Add-On Instruction body: compared by hash only")
            self.model.note(f"{apath}: encoded (sealed or source-protected) Add-On Instruction body compared by hash only. "
                            "1756-RM014 does not say whether two exports of an unchanged protected AOI produce identical encoded text")
        elif etype == "ROUTINE":
            rpath = f"{prefix}Routine:{name}"
            rattrs = {k: FieldVal("metadata" if k.lower() in _META_ATTRS else cls, v)
                      for k, v in attrs if k.lower() not in ("encodedtype", "name", "type", "description")}
            doc = {canon_name(k): v for k, v in attrs if k.lower() == "description"}
            h = sha(squash(body))
            self.model.add_routine(Routine(rpath, cls, f"{amap.get('type', '?')} (encoded)", opaque_hash=h, opaque_doc_hash=h,
                                           opaque_reason="source-protected (encoded) routine: compared by hash only",
                                           attrs=rattrs, doc=doc))
            self.model.note(f"{rpath}: source-protected routine compared by hash only. 1756-RM014 does not say whether "
                            "two exports of unchanged protected content produce identical encoded text")
        else:
            ent = self.model.entities[ent_path]
            ent.set(f"EncodedData:{name}", cls, body_hash(body), opaque=True,
                    note=f"ENCODED_DATA of type {etype}: compared by hash")

    # ---- routines (RM014 ch.8 ladder p.206-211, ch.9 FBD p.223, ch.10 SFC p.257,
    #      ch.11 ST p.285, Equipment Sequence p.301)

    def _rungs(self, text: str, path: str) -> tuple:
        units, pending, other, odd = [], [], [], set()
        for stmt in split_top(text, ";"):
            s = stmt.strip()
            if not s:
                continue
            m = _RUNG.match(s)
            if m is None or (m.group(1) == "RC" and not m.group(2).lstrip().startswith('"')):
                other.append(s)
                continue
            typ, rest = m.group(1), m.group(2)
            if typ == "RC":
                pending.append(squash(" ".join(unescape(q[1:-1]) for q in _STRING.findall(rest))))
                continue
            if typ != "N":
                odd.add(typ)
            units.append(Unit(label=str(len(units)), code=normalise_code(rest), raw=squash(rest),
                              doc=squash(" ".join(pending)), attrs={"Type": typ}))
            pending = []
        if odd:
            self.model.note(f"{path}: rungs carry online-edit markers (Type {', '.join(sorted(odd))}); "
                            "the export holds pending or test edits, not only the original logic")
        return units, pending, other

    def _st_lines(self, text: str) -> tuple:
        lines, noquote, n = [], 0, 0
        for raw in text.split("\n"):
            s = raw.strip()
            if not s:
                continue
            if s.startswith("'"):
                lines.append((str(n), s[1:]))
            else:
                lines.append((str(n), s))
                noquote += 1
            n += 1
        return lines, noquote

    def _routine(self, c: _Cursor, kw: str, prefix: str, cls: str) -> None:
        name = c.word()
        attrs = c.opt_group()
        base = f"{prefix}Routine:{name}"
        doc, rattrs = {}, {}
        for k, v in attrs:
            if k.lower() == "description":
                doc["Description"] = v
            else:
                rattrs[k] = FieldVal("metadata" if k.lower() in _META_ATTRS else cls, v)
        body = c.block_body(kw)
        sections = edit_sections(body)
        states = [EDIT_STATES.get(st, st) for st, _ in sections if st]
        if states:
            self.model.note(f"{base}: export carries online edits ({', '.join(sorted(set(s or 'Original' for s in states)))}); "
                            "each edit state is compared separately")
        lang = ROUTINE_KEYWORDS[kw]
        for state, text in sections:
            edit = EDIT_STATES.get(state, state)
            path = base if edit == "" else f"{base}[{edit}]"
            sattrs = dict(rattrs)
            if kw == "ROUTINE":
                units, pending, other = self._rungs(text, path)
                sdoc = dict(doc)
                if pending:
                    sdoc["trailing comment"] = squash(" ".join(pending))
                if other:
                    sattrs["unparsed"] = FieldVal(cls, sha("\n".join(normalise_code(o) for o in other)), opaque=True,
                                                  note=f"{len(other)} statement(s) in the routine that are not rungs or rung comments: compared by hash")
                    self.model.note(f"{path}: {len(other)} statement(s) that are not rungs (for example ENCRYPTION_INFO) compared by hash only")
                self.model.add_routine(Routine(path, cls, lang, "rung", units, attrs=sattrs, doc=sdoc))
            elif kw == "ST_ROUTINE":
                lines, noquote = self._st_lines(text)
                if noquote:
                    self.model.note(f"{path}: {noquote} line(s) do not begin with the single quote RM014 requires of "
                                    "structured text lines; they were compared as written")
                units, comments = text_units(lines, comment_syntax=True)
                self.model.add_routine(Routine(path, cls, lang, "line", units, comments=comments, attrs=sattrs, doc=doc))
            else:
                self.model.add_routine(Routine(path, cls, lang, opaque_hash=body_hash(text), opaque_doc_hash=body_hash(_strip_doc(text)),
                                               opaque_reason=f"{lang} content compared by hash (layout edits also change it)",
                                               attrs=sattrs, doc=doc))

    # ---- programs (RM014 ch.7 L5K PROGRAM structure p.195, CHILD_PROGRAM p.199, example p.204)

    def _program(self, c: _Cursor) -> None:
        name = c.word()
        attrs = c.opt_group()
        prefix = f"Program:{name}"
        ent = self.model.entity(prefix, "program", "logic")
        for k, v in attrs:
            kl = k.lower()
            if kl in ("description", "revisionnote"):
                ent.set(canon_name(k), DOC, v)
            elif kl == "mode":
                ent.set("MODE", "logic", v, note="L5K name of the test-edits flag (L5X TestEdits)")
            elif kl in _PROGRAM_META:
                ent.set(k, "metadata", v)
            else:
                ent.set(k, "tasking", v)
        while True:
            w = c.peek_word()
            if w is None:
                if c.at_end():
                    raise c.err("PROGRAM without END_PROGRAM")
                self._unparsed(prefix, c.statement())
                continue
            if w == "END_PROGRAM":
                c.word()
                return
            c.word()
            if w == "TAG":
                self._tag_block(c, f"{prefix}/Tag", "tag", "interface", "value", prefix)
            elif w in ROUTINE_KEYWORDS:
                self._routine(c, w, f"{prefix}/", "logic")
            elif w == "ENCODED_DATA":
                self._encoded(c, f"{prefix}/", "logic", prefix)
            elif w == "CHILD_PROGRAMS":
                names = [t for t in re.split(r"[\s,;]+", c.block_body("CHILD_PROGRAMS")) if t]
                ent.set("ChildPrograms", "metadata", ", ".join(names))
            else:
                self._unknown(c, w, prefix, "logic")

    # ---- tasks (RM014 ch.12 L5K TASK structure p.312, example p.315)

    def _task(self, c: _Cursor) -> None:
        name = c.word()
        attrs = c.opt_group()
        ent = self.model.entity(f"Task:{name}", "task", "tasking")
        for k, v in attrs:
            if k.lower() == "description":
                ent.set("Description", DOC, v)
            else:
                ent.set(k, "tasking", v)
        programs = [squash(s) for s in split_top(c.block_body("TASK"), ";") if s.strip()]
        # "The programs are executed in the order they are specified." (p.315)
        ent.set("ScheduledPrograms", "tasking", " > ".join(programs))

    # ---- controller (RM014 ch.2 L5K CONTROLLER structure p.55, attributes p.57-61, examples p.63)

    def controller(self, c: _Cursor) -> str:
        kw = c.word()
        if kw != "CONTROLLER":
            raise c.err("expected CONTROLLER")
        name = c.word()
        attrs = c.opt_group()
        cent = self.model.entity("Controller", "controller", "metadata")
        cent.set("Name", "metadata", name)
        for k, v in attrs:
            kl = k.lower()
            if kl == "description":
                cent.set("Description", DOC, v)
            elif kl in _CTRL_MODULE:
                cent.set(k, "module", v)
            elif kl in _CTRL_TASKING:
                cent.set(k, "tasking", v)
            elif kl in _CTRL_UNCOUNTED:
                cent.set(k, "metadata", v, counted=False)
            else:
                cent.set(k, "metadata", v)
        while True:
            w = c.peek_word()
            if w is None:
                if c.at_end():
                    self.model.note("file ends without END_CONTROLLER")
                    break
                self._unparsed("Controller", c.statement())
                continue
            if w == "END_CONTROLLER":
                c.word()
                break
            c.word()
            if w == "DATATYPE":
                self._datatype(c)
            elif w == "MODULE":
                self._module(c)
            elif w == "ADD_ON_INSTRUCTION_DEFINITION":
                self._aoi(c)
            elif w == "ENCODED_DATA":
                self._encoded(c, "", "aoi", "Controller")
            elif w == "TAG":
                self._tag_block(c, "Tag", "tag", "interface", "value", "Controller")
            elif w == "PROGRAM":
                self._program(c)
            elif w == "TASK":
                self._task(c)
            elif w == "PARAMETER_CONNECTION":
                # ch.13 (p.316): PARAMETER_CONNECTION (EndPoint1 := \Program.Tag, EndPoint2 := ...)
                a = {k.lower(): v for k, v in c.opt_group()}
                tail = c.block_body("PARAMETER_CONNECTION")
                self.parameter_connections.append(f"{a.get('endpoint1', '?')} -> {a.get('endpoint2', '?')}" + (f" {squash(tail)}" if tail.strip() else ""))
            elif w == "TREND":
                # ch.14 (p.320): TREND name (attrs) Template := [...]; PEN ... END_PEN END_TREND
                tname = c.word()
                tattrs = c.opt_group()
                ent = self.model.entity(f"Trend:{tname}", "trend", "metadata")
                for k, v in tattrs:
                    if k.lower() == "description":
                        ent.set("Description", DOC, v)
                ent.set("Content", "metadata", body_hash(attrs_string(tattrs, skip=("Description",)) + "\n" + c.block_body("TREND")),
                        opaque=True, note="trend template and pens: compared by hash")
            elif w == "QUICK_WATCH":
                # ch.15 (p.329): QUICK_WATCH (attrs) WATCH_TAG (attrs); END_QUICK_WATCH
                self.quick_watch.append(c.group() if c.peek_char() == "(" else "")
                self.quick_watch.append(c.block_body("QUICK_WATCH"))
            elif w == "CONFIG":
                # ch.16 (p.332): CONFIG object_name [(attrs)] END_CONFIG
                oname = c.word()
                oattrs = c.opt_group()
                if c.peek_word() == "END_CONFIG":
                    c.word()
                else:
                    self.model.note(f"Controller: CONFIG {oname} is not closed by END_CONFIG")
                cent.set(f"Config:{oname}", "metadata", attrs_string(oattrs) or "(no attributes)")
            elif w in ("ALARM_CONDITION", "ALARM_DEFINITION"):
                # tag-based alarms (p.181) and alarm definitions (p.190), placed after the tasks
                aname = c.word()
                aattrs = c.opt_group()
                kind = "AlarmCondition" if w == "ALARM_CONDITION" else "AlarmDefinition"
                ent = self.model.entity(f"{kind}:{aname}", "alarm", "value")
                for k, v in aattrs:
                    if _is_alarm_message(k):
                        ent.set(k, DOC, v, note="alarm message text")
                    elif k.lower() == "description":
                        ent.set("Description", DOC, v)
                    else:
                        ent.set(k, "value", v)
                tail = c.block_body(w)
                if tail.strip():
                    self._unparsed(f"{kind}:{aname}", tail)
            elif w == "PRIMARY_ACTION_SET":
                pname = c.word()
                pattrs = c.group() if c.peek_char() == "(" else ""
                cent.set(f"PrimaryActionSet:{pname}", "metadata", body_hash(pattrs + c.block_body("PRIMARY_ACTION_SET")),
                         opaque=True, note="cached permissions: compared by hash")
            else:
                self._unknown(c, w, "Controller", "metadata")
        if self.parameter_connections:
            cent.set("ParameterConnections", "interface", "\n".join(sorted(self.parameter_connections)))
        if self.quick_watch:
            cent.set("QuickWatchLists", "metadata", body_hash("\n".join(self.quick_watch)), counted=False, opaque=True,
                     note="engineering watch lists: reported, not counted")
        return name


def parse(text: str, *, path: str, sha256: str, size: int, notes: tuple = (), max_depth: int = MAX_DEPTH_DEFAULT) -> Model:
    """Parse L5K text. Raises ValueError for a file that is not an L5K export
    (the caller turns it into InputFormatError) and UnsafeInputError for a
    nesting bomb."""
    remarks = [squash(m.group(0).split(",", 1)[1]) for m in _REMARK_LINE.finditer(text)]
    text = _REMARK_LINE.sub("", text)
    start = preamble_end(text)
    if start < 0:
        raise ValueError("not an L5K export (no CONTROLLER statement at the start of the file)")
    model = Model(fmt=FORMAT, path=path, sha256=sha256, size=size)
    for n in notes:
        model.note(n)
    exp = model.entity("Export", "export", "metadata")
    pre = text[:start]
    if pre.strip():
        exp.set("Preamble", "metadata", body_hash(pre), counted=False, opaque=True,
                note="text before the CONTROLLER statement (export banner, version lines): RM014 documents no L5K "
                     "file header, so it is kept as provenance and never counted")
    if remarks:
        exp.set("Remarks", DOC, " | ".join(r for r in remarks if r), note="REMARK lines are ignored on import (RM014 p.50)")
    cur = _Cursor(text, start, path, max_depth)
    reader = _Reader(model, path, max_depth)
    reader.controller(cur)
    trailer = text[cur.i:]
    if trailer.strip():
        exp.set("Trailer", "metadata", body_hash(trailer), counted=False, opaque=True,
                note="text after END_CONTROLLER: RM014 documents nothing there; kept as provenance only")
        model.note("text after END_CONTROLLER was not parsed (compared by hash, not counted)")
    reader._finish_unparsed()
    return model


def load_model(path: str, *, max_bytes: int = MAX_BYTES_DEFAULT, max_lines: int = MAX_LINES_DEFAULT,
               max_depth: int = MAX_DEPTH_DEFAULT) -> Model:
    doc = load(path, max_bytes=max_bytes, max_lines=max_lines)
    try:
        return parse(doc.text, path=path, sha256=doc.sha256, size=doc.size, notes=tuple(doc.notes), max_depth=max_depth)
    except UnsafeInputError:
        raise
    except ValueError as exc:
        raise InputFormatError(f"{path}: {exc}") from None
