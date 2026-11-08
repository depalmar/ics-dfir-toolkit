# Logic comparison: `icstriage logic-diff`

Does the logic in this controller match the known-good copy? In OT response
that question comes first, and this repository's rule is that a controller
whose logic was not compared with a known-good copy has not been shown to be
unmodified. CISA AA26-097A reports the reason, quoted in ICS-0001:

> After the actors extracted device project files, the FBI and CISA
> identified the modification and deletion of project file logic, to include
> Add-On Instructions (AOIs) and data manipulation on HMI and SCADA displays

`logic-diff` answers the question **offline**, from two exported project files
an engineer has already produced: a baseline (known-good) and a current
export (under review). It is standard-library Python, reads the files as
hostile input, and never connects to a controller, a network or a vendor tool.
Running it is a `passive` method: it works on copies only. Producing the
current export usually is not passive; see [Producing the exports](#producing-the-exports-safely).

## Quick start

```bash
python -m icstriage logic-diff --baseline good.L5X --current suspect.L5X              # Markdown to stdout
python -m icstriage logic-diff --baseline good.L5X --current suspect.L5X --format json --out report.json
python -m icstriage logic-diff --baseline good.xml --current suspect.xml               # PLCopen TC6 XML
```

| Exit | Meaning |
| --- | --- |
| 0 | `NO-DIFFERENCES-FOUND`: no counted difference in the elements compared |
| 10 | `DIFFERENCES-FOUND`: at least one counted difference |
| 1 | error: input refused (size, encoding, DTD), not well-formed, unrecognised format, L5X compared with PLCopen, bad arguments |

The format is detected from the root element: `RSLogix5000Content` is
Rockwell L5X; `project` in a `http://www.plcopen.org/xml/tc6...` namespace is
PLCopen TC6 XML. Both inputs must be the same format. `--max-size-mb`
(default 200) caps input size. `--out` refuses to overwrite either input.

## Producing the exports safely

The process outranks the investigation. Every step that touches a live
controller is at least `online-vendor-tool` and needs operations approval;
the platform records are the authority for each vendor path.

| Platform | Baseline export | Current export | Impact of producing the current export |
| --- | --- | --- | --- |
| Rockwell Logix 5000 ([ICS-0001](../artifacts/catalog/ICS-0001-rockwell-logix-5000.yml)) | Open a **copy** of the change-managed ACD offline; File > Save As, then from the Save as type list select .L5X (1756-RM014, "Export a Project to an .L5X XML File") | Upload the running project with Studio 5000 Logix Designer **into a new, empty ACD**, then export that file to L5X offline | `online-vendor-tool` (ICS-0001). Do not switch the controller to RUN until the project is validated: CISA warns a mode change locks in the project on the device |
| CODESYS V3 runtimes ([ICS-0009](../artifacts/catalog/ICS-0009-codesys-v3-runtime-controllers.yml)) | Project → Export PLCopenXML from the known-good project | Export PLCopenXML from the project under review. Source Upload of Archive.prj is `online-vendor-tool` and, per ICS-0009, "Returns the archive someone last placed there with Source Download, not a reconstruction of the running code" | A PLCopen export never shows the running application. For that, use ICS-0009's "Login without any change" and Application Information (`online-vendor-tool`) |
| Siemens S7-1200/1500 ([ICS-0003](../artifacts/catalog/ICS-0003-siemens-s7-1200-1500.yml)) | not supported | not supported | Use TIA Portal "Upload from device (software)" into a new project and its online/offline comparison (`online-vendor-tool`, ICS-0003). No TIA Portal export format was read for this tool |

Practical rules:

- **Upload into a new, empty project.** ICS-0001: "Upload into a new file so
  the investigator's copy cannot be downloaded by mistake." An export of the
  project file on an engineering workstation shows that file, not the
  controller - and the workstation may be the compromised host.
- **Never export from the only copy of the baseline.** 1756-RM014: "The
  application automatically saves any unsaved edits when you select OK." Work
  on a copy and record the SHA-256 of the original before and after.
- **Use the same export settings on both sides.** Rockwell exports
  source-protected content encrypted by default (1756-RM014: "By default,
  source-protected content is now exported in an encrypted format to prevent
  viewing or modifying components in the system."); CODESYS can add plain-text
  declarations as a schema extension. Mismatched settings produce noise.
- **Know where the baseline came from.** A backup taken after compromise
  reinstalls - and here, validates - the attacker's logic. Use the
  change-managed repository copy or an offline backup from before the period
  of concern.

## Reading the report

The report states the verdict, the SHA-256 of both inputs, what was compared
(counts of tags, programs, routines by language, routines compared by hash),
every difference, items not evaluated, reader notes and the limits. It never
calls a controller clean; the best verdict is `NO-DIFFERENCES-FOUND` with the
limits stated.

| Class | What it covers | Counted |
| --- | --- | --- |
| `logic` | Rung, ST/IL line or graphical body added, removed or changed; routine added or removed; program added; rung edit-state markers; vendor data inside a program POU | yes |
| `aoi` | Add-On Instruction (Rockwell) or IEC function / function block (PLCopen) changed: revision, parameters, local tags, defaults, routines, encoded body. AA26-097A's "reusable code modules" | yes |
| `tasking` | Task type, rate/interval, priority, watchdog, inhibit, event trigger, scheduled programs and their order; program disable, main and fault routine; controller power-loss and major-fault programs; SFC execution options | yes |
| `interface` | Tag, variable or data type added, removed, retyped; external access, constant flag, alias, produce/consume; parameter connections | yes |
| `value` | Stored or initial value, force data, module I/O tag data | yes |
| `module` | Module identity, catalog number, revision, keying, ports, inhibit, configuration data; controller processor type and firmware revision | yes |
| `metadata` | Controller settings (security, change-detection mask, redundancy, safety), AOI signature history, child-program grouping | yes |
| `metadata` (provenance) | Export date and options, exporting software revision, project creation and modification dates, AOI edit date and editor, communication path | **no** - reported only |
| `documentation-only` | Descriptions, rung comments, comments inside ST/IL, FBD/SFC text boxes, engineering units, state names, display radix | **no** - reported only |

Each counted `logic`/`aoi` difference carries ATT&CK for ICS candidate T0889
(Modify Program), `tasking` T0821 (Modify Controller Tasking) and `value`
T0836 (Modify Parameter). These are techniques for a reviewer to consider, not
findings: a difference is not by itself evidence of an adversary. Compare
each counted difference with the change records before drawing a conclusion.

How differences are found:

- **Ladder rungs and ST/IL lines** are compared as sequences, so an inserted
  rung is one addition, not a cascade of renumbered changes. Rung text is the
  neutral text Rockwell exports, compared after collapsing whitespace outside
  string literals; instruction semantics are not interpreted. ST/IL comments
  (`//`, `(* *)`, `/* */`) are removed before comparison and compared
  separately as documentation. Comments are not treated as nested; the only
  effect is that a comment edit could show as a logic change, never that a
  logic change is hidden.
- **Opaque bodies** (FBD, SFC, LD, encrypted or encoded content, vendor
  `addData`, unmodelled elements) are compared by SHA-256 of a canonical
  serialisation. A second hash with documentation elements removed lets a
  text-box-only edit show as `documentation-only`; any other change, including
  moving a block, is a `logic` difference marked opaque.
- **Values** are compared in the best format both exports carry (L5X
  decorated, then string, L5K, raw); the report names the members that
  changed. If two exports share no data format, the value is listed under
  **Not evaluated** - not evaluated is not passed.

## Limits

Every report repeats these.

- An export reflects the project file it was produced from. It shows the
  running controller only if the engineer uploaded from the controller into a
  new, empty project and exported that.
- Firmware-level or memory-only modifications (for example TRITON-style
  implants in controller memory) are not visible in a project export.
- Opaque sections are compared by hash only: a hash difference says that
  something changed, not what.
- Encrypted or encoded content: neither vendor document read says whether two
  exports of unchanged protected content produce identical encoded text, so an
  opaque difference there cannot be interpreted without the source key.
- Stored values are a snapshot at export or upload time; value differences
  between an offline baseline and an uploaded project are expected for live
  process data.
- Rung comments and descriptions reach a Logix controller only if the
  project downloads documentation (RM014 attribute
  `DownloadProjectDocumentationAndExtendedProperties`), so an uploaded project
  can differ from its source in documentation only. This is a toolkit
  inference from the attribute, not a Rockwell statement.
- `NO-DIFFERENCES-FOUND` means no counted difference in the elements this
  tool compares. It does not show that the controller is uncompromised.

## Formats and elements covered

### Rockwell Logix 5000 L5X

Source: Rockwell Automation, *Logix 5000 Controllers Import/Export Reference
Manual*, publication 1756-RM014D-EN-P, September 2025,
<https://literature.rockwellautomation.com/idc/groups/literature/documents/rm/1756-rm014_-en-p.pdf>,
read directly (PDF parse) on 2026-11-08. Page numbers are the manual's printed
pages.

| Component (RM014) | Elements and attributes read | Treatment |
| --- | --- | --- |
| Root, ch.1 ".L5X file structure" (p.37) | `RSLogix5000Content` @SchemaRevision, @SoftwareRevision, @TargetName, @TargetType, @ContainsContext, @Owner, @ExportDate, @ExportOptions | provenance, not counted; TargetType other than Controller is noted as a partial export |
| Data formats (p.42) | `Data` raw (no @Format), @Format="L5K", "Decorated", "String"; decorated `DataValue`, `Structure`, `DataValueMember`, `Element` via @Name, @Index, @Value, @ForceValue; `ForceData` | value; @Radix ignored as display style |
| Controller, ch.2 (p.53-61) | `Controller` @Name, @ProcessorType, @MajorRev, @MinorRev (module), @PowerLossProgram, @MajorFaultProgram, @SFCExecutionControl, @SFCRestartPosition, @SFCLastScan (tasking), other attributes (metadata); `RedundancyInfo`, `Security` (@Code, @ChangesToDetect, ...), `SafetyInfo` and `SafetyTagMap` (metadata); `Description` (documentation) | @ProjectCreationDate and @LastModifiedDate appear in RM014's L5X controller example, not its attribute table; read as provenance |
| Datatype, ch.3 (p.72) | `DataType` @Name, @Family, @Class; `Members/Member` @Name, @DataType, @Dimension, @Hidden, @Target, @BitNumber, @ExternalAccess, @Min, @Max, member order; `Description`, `EngineeringUnit`, `State0`, `State1` | interface; documentation for descriptive children and @Radix |
| Module, ch.4 (p.79) | `Module` @CatalogNumber, @Vendor, @ProductType, @ProductCode, @Major, @Minor, @ParentModule, @ParentModPortId, @Inhibited, @MajorFault and other attributes; `EKey` @State; `Ports/Port` @Id, @Address, @Type, @Upstream; `ConfigTag`/`ConfigData` data; `Connections/Connection` attributes; `InputTag`/`OutputTag` data | module; I/O tag data is value; `ExtendedProperties` and other children by hash |
| Add-On Instruction, ch.5 (p.96-121) | `AddOnInstructionDefinition` @Revision, @RevisionExtension, @Vendor, @Class, @ExecutePrescan, @ExecutePostscan, @ExecuteEnableInFalse, @IsEncrypted; `Parameters/Parameter` and `LocalTags/LocalTag` (@TagType, @DataType, @Dimensions, @Usage, @Required, @Visible, @Constant, @ExternalAccess, @AliasFor, `DefaultData`); `Routines/Routine` (Logic, Prescan, Postscan, EnableInFalse); `SignatureHistory/HistoryEntry` @User, @Timestamp, @SignatureID (metadata); @CreatedDate, @CreatedBy, @EditedDate, @EditedBy, @SoftwareRevision (provenance); `Description`, `RevisionNote`, `AdditionalHelpText` (documentation); `EncodedData` @EncodedType="AddOnInstructionDefinition" | aoi; encoded body and `EncryptionInfo`/`EncryptedAOIContent` by hash |
| Tag, ch.6 (p.122-179) | `Tag` @TagType, @DataType, @Dimensions, @AliasFor, @Class, @ExternalAccess, @OpcUaAccess, @Constant, @Usage, @Sequencing; `ProduceInfo`, `ConsumeInfo`; `Mins`, `Maxes`; `Description`, `Comments/Comment` @Operand, `EngineeringUnits`, `State0s`, `State1s` (documentation); `Data`, `ForceData` (value) | interface and value; alarm configuration and other children by hash |
| Program, ch.7 (p.194-205) | `Program` @Type, @Class, @MainRoutineName, @FaultRoutineName, @Disabled, @UseAsFolder and phase/sequence attributes (tasking), @TestEdits (logic); `ChildPrograms/ChildProgram` (metadata); `Tags`; `Routines`; `EncodedData` @EncodedType="Routine" @Type | source-protected routines by hash |
| Ladder, ch.8 (p.206-222) | `Routine` @Name, @Type="RLL"; `RLLContent/Rung` @Number, @Type; `Text`; `Comment` (documentation) | rung types other than N (insert, delete, replace and pending markers in RM014's rung-type table) are compared and noted |
| FBD, ch.9 (p.223) and SFC, ch.10 (p.256) | `FBDContent`, `SFCContent` | opaque; documentation hash drops `TextBox`, `Attachment` ("The attachment blocks identify the attachments from text boxes to other function block elements."), `Description`, `Comment` |
| Structured text, ch.11 (p.285) | `STContent` @OnlineEditType, `Line` @Number | line comparison; each online-edit state compared separately |
| Locked routines (ch.8-11 element tables) | `EncryptionInfo`, `EncryptedContent`, `EncryptedSegments` | by hash |
| Task, ch.12 (p.312-315) | `Task` @Type, @Class, @Rate, @Priority, @Watchdog, @DisableUpdateOutputs, @InhibitTask, @SynchronizeRedundancyDataDisabled; `EventInfo` attributes; `ScheduledPrograms/ScheduledProgram` @Name in order ("The programs are executed in the order they are specified.") | tasking |
| Other controller children (ch.13-17) | `ParameterConnections` (interface), `QuickWatchLists` (not counted), `Trends`, controller configuration objects and anything else | by hash |

Not read at all: the L5K text format and the binary ACD project file.

RM014 statements the treatment relies on:

- "Raw data format is a hex dump of the data and includes hidden (config)
  data." Decorated data is therefore preferred when both exports carry it.
- "If the decorated data for a tag exceeds 100 KB, the decorated data format
  will not be exported. In this case, the raw data format will preserve the
  data values of the tag."
- "When you change an Add-On Instruction by manually editing an.L5X file using
  a text editor and you do not change the EditedDate attribute, the
  application does not overwrite the Add-On Instruction when you import the
  file." An edited AOI that was imported should therefore carry a new
  EditedDate; the report always lists EditedDate changes, though as
  provenance they do not decide the verdict.

### PLCopen TC6 XML

Source: PLCopen, *Schema TC6_XML_V201.xsd* (schema documentation PDF),
<https://www.plcopen.org/download_file/force/5087ac70-cfa8-4ff6-ae33-ae67a71fd0b2/342/>,
namespace `http://www.plcopen.org/xml/tc6_0201`, read directly on 2026-11-08.
Elements are matched by local name.

| Schema element | Read | Treatment |
| --- | --- | --- |
| `project/fileHeader` | @companyName, @productName, @productVersion, @productRelease, @creationDateTime, @contentDescription | provenance |
| `project/contentHeader` | @name, @version, @organization, @language (metadata); @modificationDateTime, @author (provenance); `coordinateInfo` (provenance, hash) | metadata |
| `types/dataTypes/dataType` | @name; `baseType` rendered from elementary types, `derived` @name, `array`/`dimension` @lower @upper, `string`/`wstring` @length, `enum`, `struct`, `subrange*`, `pointer`; `initialValue` | interface; initial value is value |
| `types/pous/pou` | @name, @pouType (function, functionBlock, program) | program POUs are `logic`; function and function-block POUs are `aoi` |
| `pou/interface` | `returnType`, `inputVars`, `outputVars`, `inOutVars`, `localVars`, `tempVars`, `externalVars`, `globalVars`, `accessVars`; varList @name, @constant, @retain, @nonretain, @persistent, @nonpersistent; `variable` @name, @address, `type`, `initialValue`, `documentation`; declaration order | interface (or aoi); `initialValue` via `simpleValue` @value, `arrayValue/value` @repetitionValue, `structValue/value` @member |
| `pou/body`, `actions/action`, `transitions/transition` | `body` @WorksheetName; `ST`, `IL` (formattedText) | line comparison with comments removed |
| | `FBD`, `LD`, `SFC` | opaque; documentation hash drops `documentation` and `comment` |
| `instances/configurations/configuration/resource/task` | `task` @name, @interval, @priority, @single; `pouInstance` @name, @typeName, in order; resource-level `pouInstance`; configuration and resource `globalVars` | tasking; variables are interface |
| `addData` anywhere, `accessVars`/`configVars` of a configuration | | by hash |

CODESYS (V3.5 SP22 online help, read directly 2026-11-08) produces the export
with **Command: Export PLCopenXML** - "The command opens a dialog for
exporting objects from a project to an XML file PLCopen format." Its options
page ("Dialog: Options: PLCopenXML") explains two behaviours the comparison
sees:

- "By default, CODESYS splits declaration parts into individual variables
  according to the PLCopenXML scheme, and therefore loses the formatting and
  some comment information."
- With "Additionally export declarations as plain text" enabled, "CODESYS
  writes the plain text of the exported declaration part to the PLCopenXML
  file and therefore extends the PLCopenXML scheme." That text lands in vendor
  data compared by hash, so with this option a comment-only declaration edit
  shows as an opaque difference.

No other tool's PLCopen export was checked.

## Untrusted input

Export files are treated as hostile. Before any XML parser sees a document:

1. it must be a regular file under the size cap (default 200 MB); its SHA-256
   is taken from the exact bytes read;
2. the encoding must come from a BOM or the XML declaration and be UTF-8,
   UTF-16, ASCII, ISO-8859-1 or windows-1252 (an exotic declared encoding
   could hide markup from the scan); UTF-32 is refused;
3. the decoded text is scanned for markup declarations: any `<!` followed by
   a letter (`<!DOCTYPE`, `<!ENTITY`, `<!ELEMENT`, `<!ATTLIST`, `<!NOTATION`)
   refuses the file, even inside a comment or CDATA. With no DTD, no entity
   can be declared, so external entities and expansion bombs never reach the
   parser;
4. `xml.etree.ElementTree` then parses the same decoded text incrementally,
   with the XML declaration removed, under an element-count cap (5,000,000)
   and a nesting-depth cap (256).

Nothing from an input is executed, imported or evaluated. Names and values
from the file are printed in the Markdown report as code spans with backticks
replaced, so a hostile name cannot inject Markdown.

## Tests and fixtures

`tests/test_logic_compare.py` runs offline against synthetic fixtures in
`tests/fixtures/logic/` (written from scratch with placeholder names and
192.0.2.0/24 addresses; no vendor sample was copied): identical pair, new
export date only, rung changed, tag added, task period changed, AOI revision
and body changed, comment-only change, a DOCTYPE/ENTITY file, and a PLCopen
pair. Further cases are built in temporary files: inserted rung, ST change,
member value change, force data, value formats with nothing in common,
online-edit rung marker, source-protected routine, UTF-16 and exotic
encodings, size/element/depth caps, malformed and unknown files, and the CLI
exit codes.
