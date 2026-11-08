"""Offline tests for icstriage logic-diff. Every fixture is synthetic
(tests/fixtures/logic/), written from scratch with placeholder names."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
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
SML = FIX / "simaticml"
BASE = L5X / "baseline.L5X"
SBASE = SML / "baseline"


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


# ---- Siemens SimaticML (TIA Portal Openness exports)

def sml_dir(tmp_path: Path, edits: dict, src: Path = SBASE, name: str = "current") -> Path:
    """Copy a fixture directory and apply exact, single-occurrence edits per file."""
    dst = tmp_path / name
    shutil.copytree(src, dst)
    for fname, pairs in edits.items():
        p = dst / fname
        text = p.read_text(encoding="utf-8")
        for old, new in pairs:
            assert text.count(old) == 1, old
            text = text.replace(old, new)
        p.write_text(text, encoding="utf-8")
    return dst


def keyset(rep: dict, flag: bool = True) -> set:
    return {(d["class"], d["change"], d["path"], d["field"]) for d in rep["differences"] if d["counted"] is flag}


def test_siemens_same_directory_twice_has_no_differences():
    rep = run(SBASE, SBASE)
    assert rep["verdict"] == NONE_FOUND and rep["differences"] == []
    assert rep["inputs"]["baseline"]["format"] == "SimaticML"


def test_siemens_identical_project_new_export_time_is_informational_only():
    rep = run(SBASE, SML / "current_identical")
    assert rep["verdict"] == NONE_FOUND and counted(rep) == []
    assert {(d["class"], d["field"]) for d in rep["differences"]} == {("metadata", "sha256")}
    assert all(d["path"].startswith("File:") for d in rep["differences"])


def test_siemens_scl_network_change_in_ob_is_logic(tmp_path):
    cur = sml_dir(tmp_path, {"Main.xml": [(
        '<Access Scope="GlobalVariable" UId="22"><Symbol><Component Name="Example_Speed" /></Symbol></Access>',
        '<Access Scope="LiteralConstant" UId="22"><Constant><ConstantValue>0.0</ConstantValue></Constant></Access>')]})
    rep = run(SBASE, cur)
    assert rep["verdict"] == DIFFERENCES
    (d,) = counted(rep)
    assert (d["class"], d["change"], d["path"], d["field"]) == ("logic", "changed", "Block:Main/Networks", "network 2 line 1")
    assert '"Example_Speed"' in d["baseline"] and "0.0" in d["current"]
    assert d["attack_candidates"] == ["T0889"]


def test_siemens_scl_change_in_fb_is_reusable_module_class(tmp_path):
    cur = sml_dir(tmp_path, {"FB_ExampleValve.xml": [('<ConstantValue UId="67">1</ConstantValue>',
                                                      '<ConstantValue UId="67">5</ConstantValue>')]})
    (d,) = counted(run(SBASE, cur))
    assert (d["class"], d["path"], d["field"]) == ("aoi", "Block:FB_ExampleValve/Networks", "network 1 line 4")
    assert d["baseline"] == "#OpenCount := #OpenCount + 1;" and d["current"] == "#OpenCount := #OpenCount + 5;"


def test_siemens_interface_member_added_is_interface(tmp_path):
    cur = sml_dir(tmp_path, {"FB_ExampleValve.xml": [(
        '<Member Name="Limit" Datatype="Real" Accessibility="Public">',
        '<Member Name="Bypass" Datatype="Bool" Accessibility="Public" />\n'
        '            <Member Name="Limit" Datatype="Real" Accessibility="Public">')]})
    rep = run(SBASE, cur)
    assert keyset(rep) == {("interface", "added", "Block:FB_ExampleValve/Static.Bypass", "member"),
                           ("interface", "changed", "Block:FB_ExampleValve", "MemberOrder:Static")}


def test_siemens_start_value_changes_are_value_t0836(tmp_path):
    cur = sml_dir(tmp_path, {"DB_ExampleData.xml": [("<StartValue>90.0</StartValue>", "<StartValue>150.0</StartValue>"),
                                                    ("<StartValue>20</StartValue>", "<StartValue>25</StartValue>")],
                             "FB_ExampleValve.xml": [("<StartValue>1000</StartValue>", "<StartValue>1</StartValue>")]})
    rep = run(SBASE, cur)
    assert keyset(rep) == {("value", "changed", "Block:DB_ExampleData/Static.Limit", "StartValue"),
                           ("value", "changed", "Block:DB_ExampleData/Static.Steps", "StartValue[1]"),
                           ("value", "changed", "Block:FB_ExampleValve/Constant.MaxCount", "StartValue")}
    assert all(d["attack_candidates"] == ["T0836"] for d in counted(rep))
    const = [d for d in counted(rep) if d["path"].endswith("MaxCount")][0]
    assert const["note"] == "constant"


def test_siemens_ob_priority_change_is_tasking_t0821(tmp_path):
    cur = sml_dir(tmp_path, {"Main.xml": [('<PriorityNumber ReadOnly="true">1</PriorityNumber>',
                                           '<PriorityNumber ReadOnly="true">2</PriorityNumber>')]})
    (d,) = counted(run(SBASE, cur))
    assert (d["class"], d["path"], d["field"], d["baseline"], d["current"]) == ("tasking", "Block:Main", "PriorityNumber", "1", "2")
    assert d["attack_candidates"] == ["T0821"]


def test_siemens_ob_without_tasking_attributes_is_not_evaluated(tmp_path):
    strip = [('      <PriorityNumber ReadOnly="true">1</PriorityNumber>\n', ""),
             ("      <SecondaryType>Example_ProgramCycle</SecondaryType>\n", "")]
    b = variant(tmp_path, "b.xml", *strip, src=SBASE / "Main.xml")
    c = variant(tmp_path, "c.xml", *strip, src=SBASE / "Main.xml")
    rep = run(b, c)
    assert rep["verdict"] == NONE_FOUND
    assert any("OB tasking was not compared" in n for n in rep["not_evaluated"])


def test_siemens_lad_network_change_is_opaque_logic(tmp_path):
    cur = sml_dir(tmp_path, {"Main.xml": [('<Component Name="Example_Run" />', '<Component Name="Example_Bypass" />')]})
    (d,) = counted(run(SBASE, cur))
    assert (d["class"], d["path"], d["field"], d["opaque"]) == ("logic", "Block:Main/Networks", "network 1", True)
    assert "not shown" in d["note"] and "sha256" in d["current"]


def test_siemens_lad_wire_order_alone_is_not_a_difference(tmp_path):
    w25 = '<Wire UId="25"><Powerrail /><NameCon UId="23" Name="in" /></Wire>'
    w26 = '<Wire UId="26"><IdentCon UId="21" /><NameCon UId="23" Name="operand" /></Wire>'
    cur = sml_dir(tmp_path, {"Main.xml": [(w25 + "\n                " + w26,
                                           w26.replace('"26"', '"25"') + "\n                " + w25.replace('"25"', '"26"'))]})
    rep = run(SBASE, cur)
    assert rep["verdict"] == NONE_FOUND and counted(rep) == []


def test_siemens_uid_renumbering_in_scl_is_not_a_difference(tmp_path):
    cur = sml_dir(tmp_path, {"FB_ExampleValve.xml": [('<Token Text="IF" UId="23" />', '<Token Text="IF" UId="923" />')]})
    assert counted(run(SBASE, cur)) == []


def test_siemens_documentation_only_changes_are_not_counted(tmp_path):
    cur = sml_dir(tmp_path, {"FB_ExampleValve.xml": [
        ("<Text> Example valve permissive</Text>", "<Text> Example valve permissive (reviewed)</Text>"),
        ("<Text>Valve logic</Text>", "<Text>Valve logic, rev B</Text>"),
        ('<MultiLanguageText Lang="en-US">Open command</MultiLanguageText>',
         '<MultiLanguageText Lang="en-US">Open command from HMI</MultiLanguageText>'),
        ("<Text>Example valve block (synthetic)</Text>", "<Text>Example valve block</Text>")]})
    rep = run(SBASE, cur)
    assert rep["verdict"] == NONE_FOUND and counted(rep) == []
    docs = {(d["path"], d["field"]) for d in rep["differences"] if d["class"] == "documentation-only"}
    assert docs == {("Block:FB_ExampleValve/Networks", "comments in code"),
                    ("Block:FB_ExampleValve/Networks", "network 1 title"),
                    ("Block:FB_ExampleValve/Input.Open", "Comment"),
                    ("Block:FB_ExampleValve", "Comment")}


def test_siemens_stl_statements_compared_and_empty_statements_skipped(tmp_path):
    m = load_model(str(SBASE / "FC_ExampleScale.xml"))
    assert [u.code for u in m.routines["Block:FC_ExampleScale/Networks"].units] == ["L #In", "L Int#10", "*I", "T #Out"]
    cur = sml_dir(tmp_path, {"FC_ExampleScale.xml": [("<ConstantValue>10</ConstantValue>", "<ConstantValue>100</ConstantValue>")]})
    (d,) = counted(run(SBASE, cur))
    assert (d["class"], d["field"], d["current"]) == ("aoi", "network 1 statement 2", "L Int#100")


def test_siemens_know_how_protected_interface_only_is_not_evaluated():
    rep = run(SBASE, SBASE)
    assert any("FC_ExampleProtected" in n and "not compared" in n for n in rep["not_evaluated"])
    assert any("only the public block interface will be exported" in n for n in rep["notes"])


def test_siemens_know_how_protected_content_compared_by_hash(tmp_path):
    body = ('      <SW.Blocks.CompileUnit ID="3" CompositionName="CompileUnits">\n'
            '        <AttributeList><NetworkSource><StructuredText><Access Scope="LocalVariable"><Symbol>'
            '<Component Name="Y" /></Symbol></Access><Token Text=":=" /><Access Scope="LocalVariable"><Symbol>'
            '<Component Name="X" /></Symbol></Access><Token Text=";" /></StructuredText></NetworkSource>'
            '<ProgrammingLanguage>SCL</ProgrammingLanguage></AttributeList>\n      </SW.Blocks.CompileUnit>\n'
            '    </ObjectList>\n  </SW.Blocks.FC>')
    b = variant(tmp_path, "khp_b.xml", ("    </ObjectList>\n  </SW.Blocks.FC>", body), src=SBASE / "FC_ExampleProtected.xml")
    c = variant(tmp_path, "khp_c.xml", ('<Token Text=":=" />', '<Token Text=":= -" />'), src=b)
    rep = run(b, c)
    (d,) = counted(rep)
    assert (d["class"], d["path"], d["field"], d["opaque"]) == ("aoi", "Block:FC_ExampleProtected/Code", "content", True)
    assert "know-how-protected" in d["note"]


def test_siemens_tag_table_changes(tmp_path):
    cur = sml_dir(tmp_path, {"Example_Tags.xml": [
        ("<LogicalAddress>%Q0.0</LogicalAddress>", "<LogicalAddress>%Q0.1</LogicalAddress>"),
        ("<Value>1500</Value>", "<Value>3000</Value>"),
        ('      <SW.Tags.PlcUserConstant ID="6"',
         '      <SW.Tags.PlcTag ID="9" CompositionName="Tags">\n        <AttributeList>\n'
         '          <DataTypeName>Bool</DataTypeName>\n          <LogicalAddress>%M10.0</LogicalAddress>\n'
         '          <Name>Example_Bypass</Name>\n        </AttributeList>\n      </SW.Tags.PlcTag>\n'
         '      <SW.Tags.PlcUserConstant ID="6"')]})
    rep = run(SBASE, cur)
    assert keyset(rep) == {("interface", "changed", "TagTable:Example_Tags/PlcTag:Example_MotorOn", "LogicalAddress"),
                           ("interface", "added", "TagTable:Example_Tags/PlcTag:Example_Bypass", "tag"),
                           ("value", "changed", "TagTable:Example_Tags/PlcUserConstant:Example_MaxSpeed", "Value")}


def test_siemens_block_missing_from_directory_is_removed(tmp_path):
    cur = sml_dir(tmp_path, {})
    (cur / "FC_ExampleScale.xml").unlink()
    rep = run(SBASE, cur)
    got = keyset(rep)
    assert ("aoi", "removed", "Block:FC_ExampleScale", "FC") in got
    assert ("aoi", "removed", "Block:FC_ExampleScale/Networks", "routine") in got
    assert ("metadata", "removed", "File:FC_ExampleScale.xml", "file") in keyset(rep, False)


def test_siemens_single_files_and_scope_note():
    f = SBASE / "FB_ExampleValve.xml"
    assert run(f, f)["differences"] == []
    rep = run(f, SBASE)
    assert any("export scopes differ" in n for n in rep["notes"])


def test_siemens_doctype_refused_in_file_and_directory(tmp_path):
    with pytest.raises(UnsafeInputError, match="DOCTYPE or ENTITY"):
        load_model(str(SML / "doctype_entity.xml"))
    d = sml_dir(tmp_path, {})
    shutil.copy(SML / "doctype_entity.xml", d / "zz_hostile.xml")
    with pytest.raises(UnsafeInputError):
        load_model(str(d))


def test_siemens_directory_lists_what_it_could_not_read(tmp_path):
    d = sml_dir(tmp_path, {})
    shutil.copy(BASE, d / "other.xml")
    (d / "README.txt").write_text("placeholder", encoding="utf-8")
    rep = run(SBASE, d)
    assert any("other.xml: not a SimaticML PLC export" in n for n in rep["not_evaluated"])
    assert any("README.txt" in n for n in rep["not_evaluated"])


def test_siemens_duplicate_object_in_directory_refused(tmp_path):
    d = sml_dir(tmp_path, {})
    shutil.copy(d / "FB_ExampleValve.xml", d / "FB_copy.xml")
    with pytest.raises(InputFormatError, match="defined twice"):
        load_model(str(d))


def test_siemens_unknown_scl_element_is_kept_and_noted(tmp_path):
    b = variant(tmp_path, "u_b.xml", ('<Token Text="END_IF" UId="86" />', '<Token Text="END_IF" UId="86" /><Placeholder Kind="a" />'),
                src=SBASE / "FB_ExampleValve.xml")
    c = variant(tmp_path, "u_c.xml", ('<Placeholder Kind="a" />', '<Placeholder Kind="b" />'), src=b)
    rep = run(b, c)
    (d,) = counted(rep)
    assert d["field"] == "network 1 line 7" and 'Kind="b"' in d["current"]
    assert any("Placeholder" in n for n in rep["notes"])


def test_siemens_interface_snapshot_values(tmp_path):
    doc = ('<?xml version="1.0" encoding="utf-8"?>\n<Document>\n<Engineering version="V19" />\n'
           '<SW.Blocks.InterfaceSnapshot ID="0"><AttributeList><Name>DB_ExampleData</Name><Snapshot ReadOnly="true">'
           '<SnapshotValues><Value Path="Speed" Type="Real">{v}</Value></SnapshotValues></Snapshot>'
           '<SnapshotDate ReadOnly="true">{t}</SnapshotDate></AttributeList></SW.Blocks.InterfaceSnapshot>\n</Document>\n')
    b, c = tmp_path / "s_b.xml", tmp_path / "s_c.xml"
    b.write_text(doc.format(v="12.5", t="2026-01-01T00:00:00Z"), encoding="utf-8")
    c.write_text(doc.format(v="99.0", t="2026-11-08T00:00:00Z"), encoding="utf-8")
    rep = run(b, c)
    assert keyset(rep) == {("value", "changed", "Snapshot:DB_ExampleData", "Value:Speed")}
    assert ("metadata", "changed", "Snapshot:DB_ExampleData", "SnapshotDate") in keyset(rep, False)


def test_format_is_detected_by_content_not_extension(tmp_path):
    for src, name, fmt in ((BASE, "export.dat", "L5X"), (PLC / "baseline.xml", "project.bin", "PLCopen TC6 XML"),
                           (SBASE / "FB_ExampleValve.xml", "block.txt", "SimaticML")):
        dst = tmp_path / name
        shutil.copy(src, dst)
        assert load_model(str(dst)).fmt == fmt
    text = tmp_path / "notxml.L5X"
    text.write_text("placeholder text, not markup\n", encoding="utf-8")
    with pytest.raises(InputFormatError, match="not an XML export"):
        load_model(str(text))
    hmi = tmp_path / "hmi.xml"
    hmi.write_text('<Document><Hmi.Screen.Screen ID="0" /></Document>', encoding="utf-8")
    with pytest.raises(InputFormatError, match="HMI"):
        load_model(str(hmi))


def test_siemens_compared_with_l5x_is_refused():
    with pytest.raises(FormatMismatch):
        compare(load_model(str(SBASE)), load_model(str(BASE)))


def test_siemens_report_limits_and_no_clean_wording(tmp_path):
    cur = sml_dir(tmp_path, {"Main.xml": [('<PriorityNumber ReadOnly="true">1</PriorityNumber>',
                                           '<PriorityNumber ReadOnly="true">2</PriorityNumber>')]})
    rep = run(SBASE, cur)
    md, js = to_markdown(rep), to_json(rep)
    assert "know-how-protected" in md and "Upload from device (software)" in md and "WithReadOnly" in md
    assert not re.search(r"\bclean\b", md + js, re.I)


def test_siemens_cli_exit_codes(tmp_path):
    same = cli("logic-diff", "--baseline", str(SBASE), "--current", str(SML / "current_identical"))
    assert same.returncode == 0 and "NO-DIFFERENCES-FOUND" in same.stdout
    cur = sml_dir(tmp_path, {"Main.xml": [('<Component Name="Example_Run" />', '<Component Name="Example_Bypass" />')]})
    diff = cli("logic-diff", "--baseline", str(SBASE), "--current", str(cur), "--format", "json")
    assert diff.returncode == 10 and json.loads(diff.stdout)["verdict"] == DIFFERENCES
    bad = cli("logic-diff", "--baseline", str(SBASE / "Main.xml"), "--current", str(SML / "doctype_entity.xml"))
    assert bad.returncode == 1 and "refused" in bad.stderr
    inside = cli("logic-diff", "--baseline", str(SBASE), "--current", str(cur), "--out", str(cur / "report.md"))
    assert inside.returncode == 1 and "inside an input directory" in inside.stderr


def test_siemens_hostile_counts_and_nesting(tmp_path):
    # a huge NewLine/Blank count is capped, and deep token nesting is refused cleanly, never a traceback
    b = variant(tmp_path, "n.xml", ('<NewLine UId="22" />', '<NewLine Num="4000000000" UId="22" /><Blank Num="99999999" />'),
                src=SBASE / "FB_ExampleValve.xml")
    assert counted(run(SBASE / "FB_ExampleValve.xml", b)) == []
    deep = "".join('<Access Scope="LocalVariable"><Symbol><Component Name="a">' for _ in range(80))
    deep += "".join("</Component></Symbol></Access>" for _ in range(80))
    d = variant(tmp_path, "deep.xml", ('<Token Text="END_IF" UId="86" />', '<Token Text="END_IF" UId="86" />' + deep),
                src=SBASE / "FB_ExampleValve.xml")
    try:
        load_model(str(d))
    except UnsafeInputError as exc:
        assert "nest" in str(exc)
