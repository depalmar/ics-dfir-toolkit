"""Offline tests for icstriage logic-diff. Every fixture is synthetic
(tests/fixtures/logic/), written from scratch with placeholder names."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from icstriage.logic import (DIFFERENCES, NONE_FOUND, FormatMismatch, InputFormatError,  # noqa: E402
                             UnsafeInputError, build_report, compare, load_model, to_json, to_markdown)
from icstriage.logic.safexml import load  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "logic"
L5X = FIX / "l5x"
PLC = FIX / "plcopen"
BASE = L5X / "baseline.L5X"


def run(base: Path, cur: Path) -> dict:
    b, c = load_model(str(base)), load_model(str(cur))
    return build_report(b, c, compare(b, c), generated="2026-11-08T00:00:00Z")


def counted(rep: dict) -> list:
    return [d for d in rep["differences"] if d["counted"]]


def variant(tmp_path: Path, name: str, *pairs, src: Path = BASE) -> Path:
    text = src.read_text(encoding="utf-8")
    for old, new in pairs:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ---- verdicts on the fixture pairs

def test_same_file_twice_has_no_differences():
    rep = run(BASE, BASE)
    assert rep["verdict"] == NONE_FOUND
    assert rep["differences"] == []


def test_identical_project_new_export_date_is_informational_only():
    rep = run(BASE, L5X / "current_identical.L5X")
    assert rep["verdict"] == NONE_FOUND
    assert [(d["class"], d["field"], d["counted"]) for d in rep["differences"]] == [("metadata", "ExportDate", False)]


def test_rung_change_is_logic():
    rep = run(BASE, L5X / "current_rung_changed.L5X")
    assert rep["verdict"] == DIFFERENCES
    (d,) = counted(rep)
    assert (d["class"], d["change"], d["path"], d["field"]) == (
        "logic", "changed", "Program:MainProgram/Routine:MainRoutine", "rung 1")
    assert "LES(" in d["baseline"] and "LES(" not in d["current"]
    assert d["attack_candidates"] == ["T0889"]


def test_tag_added_is_interface():
    rep = run(BASE, L5X / "current_tag_added.L5X")
    (d,) = counted(rep)
    assert (d["class"], d["change"], d["path"]) == ("interface", "added", "Tag:Example_Bypass")
    assert "DataType=BOOL" in d["current"]


def test_task_period_change_is_tasking_t0821():
    rep = run(BASE, L5X / "current_task_period.L5X")
    (d,) = counted(rep)
    assert (d["class"], d["path"], d["field"], d["baseline"], d["current"]) == ("tasking", "Task:MainTask", "Rate", "10", "50")
    assert d["attack_candidates"] == ["T0821"]


def test_aoi_revision_and_body_change_is_aoi():
    rep = run(BASE, L5X / "current_aoi_changed.L5X")
    got = {(d["class"], d["path"], d["field"]) for d in counted(rep)}
    assert got == {("aoi", "AOI:AOI_ExampleValve", "Revision"), ("aoi", "AOI:AOI_ExampleValve/Routine:Logic", "rung 0")}
    info = {d["field"] for d in rep["differences"] if not d["counted"]}
    assert "EditedDate" in info


def test_comment_only_change_is_documentation_only_and_not_counted():
    rep = run(BASE, L5X / "current_comment_only.L5X")
    assert rep["verdict"] == NONE_FOUND
    assert counted(rep) == []
    docs = {(d["path"], d["field"]) for d in rep["differences"] if d["class"] == "documentation-only"}
    assert ("Program:MainProgram/Routine:MainRoutine", "rung 0 comment") in docs
    assert ("Program:MainProgram/Routine:CalcRoutine", "comments in code") in docs
    assert ("Program:MainProgram/Routine:FbdRoutine", "content (documentation elements only)") in docs
    assert ("Tag:Example_Run", "Description") in docs
    assert ("Tag:Example_Run", "Radix") in docs


# ---- finer behaviour

def test_inserted_rung_is_one_addition_not_a_cascade(tmp_path):
    text = BASE.read_text(encoding="utf-8")
    head, rest = text.split('<Routine Name="MainRoutine"', 1)
    main, tail = rest.split('<Routine Name="CalcRoutine"', 1)
    for n in (3, 2, 1):
        main = main.replace(f'<Rung Number="{n}"', f'<Rung Number="{n + 1}"')
    main = main.replace('<Rung Number="2" Type="N">',
                        '<Rung Number="1" Type="N">\n<Text>\n<![CDATA[XIC(Example_Run)OTE(StartDelayDone);]]>\n</Text>\n</Rung>\n'
                        '<Rung Number="2" Type="N">', 1)
    p = tmp_path / "inserted.L5X"
    p.write_text(head + '<Routine Name="MainRoutine"' + main + '<Routine Name="CalcRoutine"' + tail, encoding="utf-8")
    rep = run(BASE, p)
    assert [(d["class"], d["change"], d["field"]) for d in counted(rep)] == [("logic", "added", "rung 1")]


def test_st_logic_change_is_reported_by_line(tmp_path):
    p = variant(tmp_path, "st.L5X", ("Example_Pump1.SpeedSP := Example_HighLimit; (* clamp *)",
                                     "Example_Pump1.SpeedSP := Example_HighLimit * 2.0; (* clamp *)"))
    (d,) = counted(run(BASE, p))
    assert (d["class"], d["path"], d["field"]) == ("logic", "Program:MainProgram/Routine:CalcRoutine", "line 2")


def test_value_change_names_the_member_t0836(tmp_path):
    p = variant(tmp_path, "value.L5X",
                ("<Data>00 00 00 00 88 13 00 00 00 00 00 00</Data>", "<Data>00 00 00 00 01 00 00 00 00 00 00 00</Data>"),
                ('<DataValueMember Name="PRE" DataType="DINT" Radix="Decimal" Value="5000"/>',
                 '<DataValueMember Name="PRE" DataType="DINT" Radix="Decimal" Value="1"/>'))
    (d,) = counted(run(BASE, p))
    assert (d["class"], d["path"], d["field"]) == ("value", "Tag:Example_Timer", "Value")
    assert "PRE: 5000 -> 1" in d["note"]
    assert d["attack_candidates"] == ["T0836"]


def test_force_data_added_is_value(tmp_path):
    p = variant(tmp_path, "force.L5X", ('<Data>00</Data>\n<Data Format="Decorated">\n<DataValue DataType="BOOL" Radix="Decimal" Value="0"/>\n</Data>\n</Tag>\n<Tag Name="Example_HighLimit"',
                                        '<Data>00</Data>\n<ForceData>01 01</ForceData>\n<Data Format="Decorated">\n<DataValue DataType="BOOL" Radix="Decimal" Value="0"/>\n</Data>\n</Tag>\n<Tag Name="Example_HighLimit"'))
    (d,) = counted(run(BASE, p))
    assert (d["class"], d["change"], d["path"], d["field"]) == ("value", "added", "Tag:Example_Run", "Force")


def test_value_formats_with_nothing_in_common_are_not_evaluated(tmp_path):
    b = variant(tmp_path, "b.L5X", ('<Data Format="Decorated">\n<DataValue DataType="REAL" Radix="Float" Value="90.0"/>\n</Data>\n', ""))
    c = variant(tmp_path, "c.L5X", ("<Data>00 00 B4 42</Data>\n", ""))
    rep = run(b, c)
    assert rep["verdict"] == NONE_FOUND
    assert any("Tag:Example_HighLimit" in n and "not compared" in n for n in rep["not_evaluated"])
    assert "Not evaluated is not passed" in to_markdown(rep)


def test_online_edit_rung_marker_is_logic_and_noted(tmp_path):
    p = variant(tmp_path, "edit.L5X", ('<Rung Number="3" Type="N">', '<Rung Number="3" Type="I">'))
    rep = run(BASE, p)
    (d,) = counted(rep)
    assert (d["class"], d["field"]) == ("logic", "rung 3 Type")
    assert any("online-edit markers" in n for n in rep["notes"])


def test_source_protected_routine_compared_by_hash_only(tmp_path):
    enc = ('<EncodedData EncodedType="Routine" Name="FbdRoutine" Type="FBD" EncryptionConfig="2">\n'
           '<Description>\n<![CDATA[placeholder]]>\n</Description>\nQUJDREVGR0g=\n</EncodedData>\n</Routines>')
    start = BASE.read_text(encoding="utf-8")
    fbd = start[start.index('<Routine Name="FbdRoutine"'):start.index("</Routines>\n</Program>") + len("</Routines>")]
    b = variant(tmp_path, "enc_b.L5X", (fbd, enc))
    c = variant(tmp_path, "enc_c.L5X", ("QUJDREVGR0g=", "SUpLTE1OT1A="), src=b)
    rep = run(b, c)
    (d,) = counted(rep)
    assert (d["class"], d["path"], d["field"], d["opaque"]) == ("logic", "Program:MainProgram/Routine:FbdRoutine", "content", True)
    assert any("source-protected" in n for n in rep["notes"])


# ---- PLCopen TC6 XML

def test_plcopen_identical():
    rep = run(PLC / "baseline.xml", PLC / "baseline.xml")
    assert rep["verdict"] == NONE_FOUND and rep["differences"] == []


def test_plcopen_changes_are_classified():
    rep = run(PLC / "baseline.xml", PLC / "current_changed.xml")
    assert rep["verdict"] == DIFFERENCES
    got = {(d["class"], d["path"], d["field"]) for d in counted(rep)}
    assert ("logic", "POU:PLC_PRG/Body", "line 3") in got
    assert ("aoi", "POU:FB_ExampleValve/Body", "line 1") in got
    assert ("aoi", "POU:FB_ExampleValve/Var:Bypass", "variable") in got
    assert ("tasking", "Task:ExampleConfig/ExampleResource/MainTask", "interval") in got
    assert ("value", "POU:PLC_PRG/Var:HighLimit", "initialValue") in got
    doc = [d for d in rep["differences"] if d["class"] == "documentation-only"]
    assert [d["path"] for d in doc] == ["POU:PLC_PRG/Var:Run"]


def test_plcopen_comment_only(tmp_path):
    p = variant(tmp_path, "c.xml", ("(* permissive required *)", "(* permissive is required *)"),
                ("// Example speed clamp", "// Example speed clamp (reviewed)"), src=PLC / "baseline.xml")
    rep = run(PLC / "baseline.xml", p)
    assert rep["verdict"] == NONE_FOUND
    assert {d["class"] for d in rep["differences"]} == {"documentation-only"}


def test_mixed_formats_are_refused():
    b, c = load_model(str(BASE)), load_model(str(PLC / "baseline.xml"))
    with pytest.raises(FormatMismatch):
        compare(b, c)


# ---- hostile input

def test_doctype_and_entity_file_rejected():
    with pytest.raises(UnsafeInputError, match="DOCTYPE or ENTITY"):
        load_model(str(L5X / "doctype_entity.L5X"))


def test_utf16_doctype_rejected(tmp_path):
    p = tmp_path / "u16.L5X"
    p.write_bytes(b"\xff\xfe" + (L5X / "doctype_entity.L5X").read_text(encoding="utf-8").replace(
        'encoding="UTF-8"', 'encoding="UTF-16"').encode("utf-16-le"))
    with pytest.raises(UnsafeInputError):
        load(str(p))


def test_utf16_clean_file_parses(tmp_path):
    p = tmp_path / "u16ok.L5X"
    p.write_bytes(b"\xff\xfe" + BASE.read_text(encoding="utf-8").replace('encoding="UTF-8"', 'encoding="UTF-16"').encode("utf-16-le"))
    rep = run(BASE, p)
    assert rep["verdict"] == NONE_FOUND


def test_exotic_declared_encoding_rejected(tmp_path):
    p = tmp_path / "u7.xml"
    p.write_bytes(b'<?xml version="1.0" encoding="UTF-7"?><RSLogix5000Content/>')
    with pytest.raises(UnsafeInputError, match="encoding"):
        load(str(p))


def test_size_element_and_depth_caps(tmp_path):
    with pytest.raises(UnsafeInputError, match="limit"):
        load(str(BASE), max_bytes=1000)
    with pytest.raises(UnsafeInputError, match="elements"):
        load(str(BASE), max_elements=50)
    deep = tmp_path / "deep.xml"
    deep.write_text("<a>" * 300 + "</a>" * 300, encoding="utf-8")
    with pytest.raises(UnsafeInputError, match="nesting"):
        load(str(deep))


def test_unknown_root_and_malformed_rejected(tmp_path):
    other = tmp_path / "other.xml"
    other.write_text("<notAProject/>", encoding="utf-8")
    with pytest.raises(InputFormatError, match="unrecognised"):
        load_model(str(other))
    bad = tmp_path / "bad.L5X"
    bad.write_text("<RSLogix5000Content><Controller></RSLogix5000Content>", encoding="utf-8")
    with pytest.raises(InputFormatError, match="well-formed"):
        load_model(str(bad))


# ---- report and CLI

def test_report_states_hashes_limits_and_never_calls_anything_clean():
    rep = run(BASE, L5X / "current_comment_only.L5X")
    md, js = to_markdown(rep), to_json(rep)
    for f in (BASE, L5X / "current_comment_only.L5X"):
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        assert digest in md and digest in js
    for limit in rep["limits"]:
        assert limit in md
    assert "new, empty project" in md and "TRITON" in md and "content hash" in md
    assert not re.search(r"\bclean\b", md + js, re.I)
    assert json.loads(js)["verdict"] in (DIFFERENCES, NONE_FOUND)


def cli(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "icstriage", *args], cwd=ROOT, capture_output=True, text=True)


def test_cli_exit_codes(tmp_path):
    same = cli("logic-diff", "--baseline", str(BASE), "--current", str(L5X / "current_identical.L5X"))
    assert same.returncode == 0 and "NO-DIFFERENCES-FOUND" in same.stdout
    diff = cli("logic-diff", "--baseline", str(BASE), "--current", str(L5X / "current_rung_changed.L5X"), "--format", "json")
    assert diff.returncode == 10 and json.loads(diff.stdout)["verdict"] == DIFFERENCES
    bad = cli("logic-diff", "--baseline", str(BASE), "--current", str(L5X / "doctype_entity.L5X"))
    assert bad.returncode == 1 and "refused" in bad.stderr
    mixed = cli("logic-diff", "--baseline", str(BASE), "--current", str(PLC / "baseline.xml"))
    assert mixed.returncode == 1
    out = tmp_path / "r.md"
    wrote = cli("logic-diff", "--baseline", str(BASE), "--current", str(L5X / "current_task_period.L5X"), "--out", str(out))
    assert wrote.returncode == 10 and out.read_text(encoding="utf-8").startswith("# Logic comparison report")
    clobber = cli("logic-diff", "--baseline", str(BASE), "--current", str(BASE), "--out", str(BASE))
    assert clobber.returncode == 1
    usage = cli("logic-diff", "--baseline", str(BASE))
    assert usage.returncode == 1
