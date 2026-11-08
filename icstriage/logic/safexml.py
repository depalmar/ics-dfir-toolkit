"""Load an XML export as hostile input.

Order of checks, all before any XML parser sees the document:

1. regular file, size cap (default 200 MB), SHA-256 of the exact bytes;
2. encoding: BOM or XML declaration, limited to UTF-8, UTF-16, ASCII,
   ISO-8859-1 and windows-1252 (an exotic declared encoding could hide
   markup from a byte-level scan, so it is refused);
3. markup-declaration scan on the decoded text: any ``<!`` followed by a
   letter (``<!DOCTYPE``, ``<!ENTITY``, ``<!ELEMENT``, ``<!ATTLIST``,
   ``<!NOTATION``) rejects the file, even inside a comment or CDATA. CDATA
   sections and comments themselves are allowed;
4. only then xml.etree.ElementTree, fed incrementally from the same decoded
   text (XML declaration removed so the parser cannot re-decode), with an
   element-count cap and a nesting-depth cap.

No DTD means no entity can be declared, so neither external entities nor
entity-expansion bombs can reach the parser.
"""
from __future__ import annotations

import hashlib
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

MAX_BYTES_DEFAULT = 200 * 1024 * 1024
MAX_ELEMENTS_DEFAULT = 5_000_000
MAX_DEPTH_DEFAULT = 256
_CHUNK = 1 << 20

_ALLOWED = {
    "utf-8": "utf-8", "utf8": "utf-8",
    "us-ascii": "ascii", "ascii": "ascii",
    "iso-8859-1": "latin-1", "latin-1": "latin-1", "latin1": "latin-1",
    "windows-1252": "cp1252", "cp1252": "cp1252",
}
_DECL_RE = re.compile(r"\A\s*<\?xml\b[^>]*\?>", re.S)
_ENC_RE = re.compile(rb"\A\s*<\?xml\b[^>]*?\bencoding\s*=\s*[\"']([A-Za-z0-9._-]+)[\"']", re.S)
_MARKUP_DECL_RE = re.compile(r"<!\s*[A-Za-z]")


class UnsafeInputError(ValueError):
    """The file was refused before parsing (size, encoding, DTD, limits)."""


class InputFormatError(ValueError):
    """The file is not well-formed or not a supported export format."""


@dataclass
class LoadedXML:
    path: str
    root: ET.Element
    sha256: str
    size: int
    encoding: str
    elements: int


def _decode(data: bytes) -> tuple[str, str]:
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")) or data[:4] in (b"\x00\x00\x00<", b"<\x00\x00\x00"):
        raise UnsafeInputError("UTF-32 input is not supported")
    try:
        if data.startswith(b"\xef\xbb\xbf"):
            return data[3:].decode("utf-8"), "utf-8"
        if data.startswith(b"\xff\xfe"):
            return data[2:].decode("utf-16-le"), "utf-16-le"
        if data.startswith(b"\xfe\xff"):
            return data[2:].decode("utf-16-be"), "utf-16-be"
        if data[:4] == b"<\x00?\x00":
            return data.decode("utf-16-le"), "utf-16-le"
        if data[:4] == b"\x00<\x00?":
            return data.decode("utf-16-be"), "utf-16-be"
        m = _ENC_RE.match(data[:1024])
        declared = m.group(1).decode("ascii").lower() if m else "utf-8"
        codec = _ALLOWED.get(declared)
        if codec is None:
            raise UnsafeInputError(f"declared encoding {declared!r} is not accepted (UTF-8, UTF-16, ASCII, ISO-8859-1, windows-1252 only)")
        return data.decode(codec), codec
    except UnicodeDecodeError as exc:
        raise InputFormatError(f"cannot decode file: {exc}") from None


def load(path: str, *, max_bytes: int = MAX_BYTES_DEFAULT, max_elements: int = MAX_ELEMENTS_DEFAULT,
         max_depth: int = MAX_DEPTH_DEFAULT) -> LoadedXML:
    """Read, screen and parse one export file. Raises UnsafeInputError or InputFormatError."""
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
    sha = hashlib.sha256(data).hexdigest()
    text, encoding = _decode(data)
    del data

    if not text.lstrip().startswith("<"):
        # Format detection is by content, not extension: anything that does not
        # open with markup is no XML export this tool reads.
        raise InputFormatError(f"{path} is not an XML export (it does not begin with markup); supported formats are "
                               "Rockwell L5X, PLCopen TC6 XML and Siemens SimaticML (TIA Portal Openness)")

    m = _MARKUP_DECL_RE.search(text)
    if m:
        line = text.count("\n", 0, m.start()) + 1
        raise UnsafeInputError(
            f"{path} line {line}: markup declaration ({text[m.start():m.start() + 12]!r}...) found; "
            "files containing DOCTYPE or ENTITY declarations are refused")

    decl = _DECL_RE.match(text)
    body = text[decl.end():] if decl else text

    parser = ET.XMLPullParser(events=("start", "end"))
    state = {"root": None, "count": 0, "depth": 0}

    def drain() -> None:
        for event, elem in parser.read_events():
            if event == "start":
                state["count"] += 1
                state["depth"] += 1
                if state["root"] is None:
                    state["root"] = elem
                if state["count"] > max_elements:
                    raise UnsafeInputError(f"{path}: more than {max_elements} elements")
                if state["depth"] > max_depth:
                    raise UnsafeInputError(f"{path}: nesting deeper than {max_depth} levels")
            else:
                state["depth"] -= 1

    try:
        for i in range(0, len(body), _CHUNK):
            parser.feed(body[i:i + _CHUNK])
            drain()
        parser.close()
        drain()
    except ET.ParseError as exc:
        raise InputFormatError(f"{path} is not well-formed XML: {exc}") from None
    if state["root"] is None:
        raise InputFormatError(f"{path} contains no XML element")
    return LoadedXML(path=path, root=state["root"], sha256=sha, size=st.st_size, encoding=encoding,
                     elements=state["count"])
