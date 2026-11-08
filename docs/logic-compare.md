# Logic comparison: `icstriage logic-diff`

Does the logic in this controller match the known-good copy? In OT response
that question comes first, and this repository's rule is that a controller
whose logic was not compared with a known-good copy has not been shown to be
unmodified. CISA AA26-097A reports the reason, quoted in ICS-0001:

> After the actors extracted device project files, the FBI and CISA
> identified the modification and deletion of project file logic, to include
> Add-On Instructions (AOIs) and data manipulation on HMI and SCADA displays

`logic-diff` answers the question **offline**, from two exported projects an
engineer has already produced: a baseline (known-good) and a current export
(under review). It reads Rockwell L5X, PLCopen TC6 XML and Siemens SimaticML
(the XML that TIA Portal Openness exports, one file per block, PLC data type
or tag table, read as a single file or a directory). It is standard-library Python, reads the files as
hostile input, and never connects to a controller, a network or a vendor tool.
Running it is a `passive` method: it works on copies only. Producing the
current export usually is not passive; see [Producing the exports](#producing-the-exports-safely).

## Quick start

```bash
python -m icstriage logic-diff --baseline good.L5X --current suspect.L5X              # Markdown to stdout
python -m icstriage logic-diff --baseline good.L5X --current suspect.L5X --format json --out report.json
python -m icstriage logic-diff --baseline good.xml --current suspect.xml               # PLCopen TC6 XML
python -m icstriage logic-diff --baseline good_blocks/ --current suspect_blocks/       # SimaticML directories
python -m icstriage logic-diff --baseline good/FB10.xml --current suspect/FB10.xml     # one SimaticML file
```

| Exit | Meaning |
| --- | --- |
| 0 | `NO-DIFFERENCES-FOUND`: no counted difference in the elements compared |
| 10 | `DIFFERENCES-FOUND`: at least one counted difference |
| 1 | error: input refused (size, encoding, DTD, nesting), not well-formed, unrecognised format, two different formats, a duplicated object in a SimaticML directory, bad arguments |

The format is detected from the content, never the file extension: root
element `RSLogix5000Content` is Rockwell L5X; `project` in a
`http://www.plcopen.org/xml/tc6...` namespace is PLCopen TC6 XML; `Document`
holding `SW.*` objects is SimaticML. A file that does not begin with markup is
refused as "not an XML export". A directory is read as SimaticML: every `.xml`
file in it (recursively, symbolic links not followed) is screened and parsed,
and objects are matched by name across files, so file names and folder layout
do not matter. Both inputs must be the same format. `--max-size-mb`
(default 200) caps each input (for a directory, the total of its XML files).
`--out` refuses to overwrite either input or to write inside an input
directory.

## Producing the exports safely

The process outranks the investigation. Every step that touches a live
controller is at least `online-vendor-tool` and needs operations approval;
the platform records are the authority for each vendor path.

| Platform | Baseline export | Current export | Impact of producing the current export |
| --- | --- | --- | --- |
| Rockwell Logix 5000 ([ICS-0001](../artifacts/catalog/ICS-0001-rockwell-logix-5000.yml)) | Open a **copy** of the change-managed ACD offline; File > Save As, then from the Save as type list select .L5X (1756-RM014, "Export a Project to an .L5X XML File") | Upload the running project with Studio 5000 Logix Designer **into a new, empty ACD**, then export that file to L5X offline | `online-vendor-tool` (ICS-0001). Do not switch the controller to RUN until the project is validated: CISA warns a mode change locks in the project on the device |
| CODESYS V3 runtimes ([ICS-0009](../artifacts/catalog/ICS-0009-codesys-v3-runtime-controllers.yml)) | Project → Export PLCopenXML from the known-good project | Export PLCopenXML from the project under review. Source Upload of Archive.prj is `online-vendor-tool` and, per ICS-0009, "Returns the archive someone last placed there with Source Download, not a reconstruction of the running code" | A PLCopen export never shows the running application. For that, use ICS-0009's "Login without any change" and Application Information (`online-vendor-tool`) |
| Siemens S7-1200/1500 ([ICS-0003](../artifacts/catalog/ICS-0003-siemens-s7-1200-1500.yml)) | Open a **copy** of the change-managed TIA Portal project offline and export blocks, PLC data types and tag tables to files with TIA Portal Openness (`PlcBlock.Export`, `PlcTagTable.Export`; the manual's "Exporting blocks" lists "PLC is not online" as a requirement) | "Upload from device (software)" **into a new, empty project**, disconnect, then export that project offline the same way, with the same ExportOptions and TIA Portal version | `online-vendor-tool` for the upload (ICS-0003: possible in RUN or STOP; "Operations approval required; same session risks as any online connection"). The Openness export itself runs on the offline copy. TIA Portal's own online/offline comparison is the vendor alternative, same impact |

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
- **Siemens: same ExportOptions and the same TIA Portal version.** What a
  SimaticML file holds depends on the options (manual 6.1.5:
  `ExportOptions.WithReadOnly` - "The write-protected values are also
  exported."); OB priority and event attributes are read-only, so without
  WithReadOnly they are absent and OB tasking is listed as not evaluated. Use
  `ExportOptions.WithDefaults | ExportOptions.WithReadOnly` on both sides.
  "The SimaticML file version for export always corresponds with the used TIA
  Portal version, regardless which Openness API version is used" (6.1.3), and
  "The export format is internal and valid exclusively for the current version
  of TIA Portal Openness. The export format may change in future versions."
  (6.1.1) - export baseline and current with the same TIA Portal version.
- **Siemens know-how protection.** "If the block is exported without
  unlocking, only the public block interface will be exported." (6.4.2.4) The
  same topic documents unlocking with the password through
  `PlcBlockProtectionProvider` before export. Do that only on a copy of the
  project, by the password holder, and record it; otherwise the report lists
  the block's code as not evaluated.
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
| `logic` | Rung, ST/IL line or graphical body added, removed or changed; routine added or removed; program added; rung edit-state markers; vendor data inside a program POU; Siemens OB network (SCL line, STL statement, LAD/FBD/GRAPH network hash), OB added or removed | yes |
| `aoi` | Add-On Instruction (Rockwell), IEC function / function block (PLCopen) or Siemens FB / FC changed: revision, parameters, local tags, defaults, routines, networks, encoded or know-how-protected body. AA26-097A's "reusable code modules" | yes |
| `tasking` | Task type, rate/interval, priority, watchdog, inhibit, event trigger, scheduled programs and their order; program disable, main and fault routine; controller power-loss and major-fault programs; SFC execution options; Siemens OB attributes (`PriorityNumber`, `EventClass`, `SecondaryType`, cycle and time attributes) | yes |
| `interface` | Tag, variable or data type added, removed, retyped; external access, constant flag, alias, produce/consume; parameter connections; Siemens block-interface members (data type, remanence, accessibility, member attributes, order), PLC data types, tag-table tags (`DataTypeName`, `LogicalAddress`, external access), instance-DB source | yes |
| `value` | Stored or initial value, force data, module I/O tag data; Siemens `StartValue` (including array `Subelement` paths and the Constant section), tag-table constant `Value`, interface-snapshot values | yes |
| `module` | Module identity, catalog number, revision, keying, ports, inhibit, configuration data; controller processor type and firmware revision | yes |
| `metadata` | Controller settings (security, change-detection mask, redundancy, safety), AOI signature history, child-program grouping; Siemens block attributes (`Number`, `HeaderVersion`, `MemoryLayout`, `IsConsistent`, ...) and unmodelled SimaticML objects | yes |
| `metadata` (provenance) | Export date and options, exporting software revision, project creation and modification dates, AOI edit date and editor, communication path; SimaticML `DocumentInfo`, `Engineering` version, block timestamps (`ModifiedDate`, `CompileDate`, ...), per-file hashes in a directory | **no** - reported only |
| `documentation-only` | Descriptions, rung comments, comments inside ST/IL, FBD/SFC text boxes, engineering units, state names, display radix; Siemens block and network titles and comments, member comments, SCL/STL comments | **no** - reported only |

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
- **Siemens networks.** A code block's compile units are one sequence, so an
  inserted network is an addition, not a cascade. SCL networks are rendered
  from the documented token elements into canonical text and compared line by
  line (labels such as `network 2 line 3` count lines of that rendering, not
  necessarily the editor's); STL networks are compared statement by
  statement. LAD, FBD and GRAPH networks are one unit each, compared by a
  hash of the network content with the children of `Wires` sorted first,
  because Siemens says "But the order of wires and references is still not
  reliable." (7.6.4.5). `ID` and `UId` values are XML-local keys and are not
  compared as content (FAQ 109480446: IDs "can be freely assigned"; 7.6.4.5:
  "From TIA Portal point of view the UIds in the XML are keys, without any
  additional meaning besides identifying an element."); elements flagged
  `Informative="true"` are derived data and are skipped ("Attributes with the
  attributes "ReadOnly=True" and "Informative=True" are not imported.",
  6.4.2.12).

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
- Siemens: a know-how-protected block exported without unlocking holds only
  its interface; its code is listed as not evaluated. A start value is written
  only "if the default value of the tag or constant is set by the user"
  (6.4.2.1), so a change to or from a default shows as an added or removed
  `StartValue`. F-blocks (`ProgrammingLanguage` prefixed `F_`) are compared
  like standard blocks; the safety program's own signatures were not read.
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

Not read at all: the L5K text format and the binary ACD project file. L5K
was considered and not implemented: a reader would need the L5K material of
1756-RM014 re-read first, and that read was not done. It is not built from
memory; an L5K file is refused as "not an XML export".

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

### Siemens SimaticML (TIA Portal Openness)

Sources, all read directly on 2026-11-08 (the PDF through Firecrawl's PDF
parser, the online topics by scraping; figures in the online topics were
cross-checked against the PDF's text rendering of the same examples):

- Siemens, *SIMATIC TIA Portal Openness: API for automation of engineering
  workflows*, System Manual, 11/2023 (TIA Portal V19),
  <https://support.industry.siemens.com/cs/attachments/109826886/TIAPortalOpenness_enUS_en-US.pdf>.
  Sections used, with the manual's printed pages: 6.1.1 Basic principles of
  importing/exporting (p.1207), 6.1.3 Version Specific Simatic ML Import
  (p.1210), 6.1.5 Exporting configuration data (p.1211), 6.3.1.1 Structure of
  an XML file (p.1221), 6.4.2.1 XML structure of the block interface section
  (p.1295), 6.4.2.2 Changes of the object model and XML file format (p.1305),
  6.4.2.3 Exporting DBs with snapshots (p.1307), 6.4.2.4 Exporting blocks with
  know-how protection (p.1309), 6.4.2.5-6.4.2.8 SCL blocks, structured types,
  call blocks and multilingual comments (p.1309-1347), 6.4.2.9 Exporting
  failsafe blocks, 6.4.2.11 GRAPH multi-language text (p.1348), 6.4.2.12
  Importing block, 6.4.2.13 Exporting blocks (p.1351), 6.4.2.30-6.4.2.31 UDT,
  DB, Array and Instance DB (p.1389-1395), 6.4.4.1-6.4.4.3 Tag tables
  (p.1426-1427), 7.6.2 and 7.6.4 Major changes in V14 SP1 (p.1646-1676).
- The same manual's V20 online edition (publication date 01/2025),
  docs.tia.siemens.cloud, topics "Exporting blocks", "XML structure of the
  block interface section", "Changes of the object model and XML file format",
  "Exporting blocks with know-how protection", "Export/Import of SCL blocks",
  "Exporting PLC tag tables", "Export/Import of UDT & DB" and "Export/Import of
  Array & Instance DB".
- Siemens Industry Online Support FAQ 109480446, "How is the XML file
  structured for blocks (Export/Import in TIA Portal Openness V13 SP1)?",
  <https://support.industry.siemens.com/cs/document/109480446/>.

| Component (source) | Elements and attributes read | Treatment |
| --- | --- | --- |
| Document (6.3.1.1, 6.4.2.30 examples) | `Document`; `Engineering` @version; `DocumentInfo` `Created`, `ExportSetting`, `InstalledProducts` | provenance, not counted; differing `ExportSetting` noted |
| Objects (6.4.2.3, 6.4.2.30-31, 7.6.4.5 examples) | children of `Document` named `SW.Blocks.*` (documented: `SW.Blocks.FB`, `SW.Blocks.GlobalDB`, `SW.Blocks.ArrayDB`, `SW.Blocks.InstanceDB`, `SW.Blocks.InterfaceSnapshot`), `SW.Types.*` (`SW.Types.PlcStruct`), `SW.Tags.*` (`SW.Tags.PlcTag`); the block type is the suffix after `SW.Blocks.`, so FC and OB are read the same way. Objects are matched by `AttributeList/Name` | other `SW.*` objects by hash (metadata) |
| Block attributes (6.4.2.13 attribute tables) | `AttributeList` children: `Name`, `Number`, `ProgrammingLanguage`, `IsKnowHowProtected`, `Interface`, OB attributes (`ApplicationCycle` ... `TransformationDBNumber`, including `EventClass`, `PriorityNumber`, `SecondaryType`), `InstanceOfName`/`InstanceOfType`/`InstanceOfNumber`, the DateTime attributes (`CodeModifiedDate`, `CompileDate`, `CreationDate`, `InterfaceModifiedDate`, `ModifiedDate`, `ParameterModified`, `StructureModified`), every other child by name | OB attributes `tasking`; DateTime attributes provenance; `ProgrammingLanguage` and `IsKnowHowProtected` in the block's class; instance source `interface`; the rest `metadata`; a child with sub-elements by hash |
| Block interface (6.4.2.1, 7.6.4.3) | `Interface/Sections/Section` @Name; `Member` @Name, @Datatype, @Remanence, @Accessibility, @Version, @Informative; member `AttributeList` `BooleanAttribute`/`StringAttribute`/... by @Name; `StartValue`; `Comment/MultiLanguageText` @Lang; nested `Member` and `Sections` (UDT in a member, section `None`); `Subelement` @Path with `StartValue` and `Comment`; `AssignedProDiagFB` | `interface`; `StartValue` `value`; comments documentation |
| Object list (FAQ 109480446) | `ObjectList/MultilingualText` @CompositionName (`Comment`, `Title`) with `MultilingualTextItem/AttributeList/Culture`, `Text`; compile units recognised by structure: an `ObjectList` child whose `AttributeList` holds `NetworkSource` and/or `ProgrammingLanguage` (FAQ: "The XML area "AttributeList" includes the XML area "NetworkSource" and the XML area "ProgrammingLanguage".") | titles and comments documentation; other children by hash |
| SCL networks (6.4.2.5-6.4.2.8) | `Token` @Text, `Blank`, `NewLine` @Num, `LineComment` (@Inserted, `Text`), `Comment` (`MultiLanguageText`), `Text`, `Access` @Scope with `Symbol`, `Component` @Name (`BooleanAttribute` HasQuotes / HasHash), `Constant` @Name, `ConstantValue`, `ConstantType`, `Address`, `CallInfo` @Name, `Instance`, `Instruction` @Name, `TemplateValue`, `Parameter` @Name, `NamelessParameter`, `Label`, `PredefinedVariable`, `DataType` | rendered and compared line by line; comments documentation; any other element kept inline as canonical XML and named in a reader note |
| STL networks (7.6.4.4-7.6.4.5) | `StlStatement`, `StlToken` @Text and the same `Access` vocabulary; statements whose only token is `EMPTY_LINE` or `COMMENT` are skipped (the manual's examples: "Declaration of an empty statement", "Declaration of a statement with only comments") | compared statement by statement |
| LAD/FBD (FAQ, 7.6.4.5 `FlgNet` examples), GRAPH (6.4.2.11) and any other language | whole network content | by hash, `Wires` children sorted, wire `UId` dropped |
| Know-how protection (6.4.2.4, 6.1.1 Table 6-2) | `IsKnowHowProtected` = true | anything in the block besides titles and comments by one hash; nothing there means not evaluated |
| Tag tables (6.4.4, 7.6.4.5) | any `SW.Tags.*` object; entries are the `SW.Tags.*` objects inside it with an `AttributeList` (documented example `SW.Tags.PlcTag` with `DataTypeName`, `LogicalAddress`, `Name`); attribute names from 6.4.4.3 (`ExternalAccessible`, `ExternalVisible`, `ExternalWritable`, `Value`, `DataTypeName`, `IsSafety`); entry `ObjectList/MultilingualText` | `interface`; constant `Value` is `value`; comments documentation |
| Interface snapshot (6.4.2.3) | `SW.Blocks.InterfaceSnapshot`: `Snapshot/SnapshotValues/Value` @Path @Type; `SnapshotDate`, `StructureModified` | values `value`; dates provenance |

Names the documentation read does **not** show in text, and how the reader
copes without guessing them:

- the V14-and-later element name of a compile unit (the V13 SP1 FAQ calls it
  `SW.CompileUnit`): compile units are recognised by their documented
  `AttributeList/NetworkSource`/`ProgrammingLanguage` structure;
- the container element inside `NetworkSource` for SCL and STL: the language
  comes from the compile unit's `ProgrammingLanguage`, and the container's
  children are read; STL statements are found by the documented
  `StlStatement` name;
- the element names of the tag-table object and of user constants: any
  `SW.Tags.*` object is accepted and its entries are read generically.

The synthetic fixtures use `SW.Blocks.CompileUnit`, `StructuredText`,
`StatementList`, `SW.Tags.PlcTagTable` and `SW.Tags.PlcUserConstant` as
placeholders for those positions; the reader does not depend on any of them.

Statements the treatment relies on:

- "If the block is exported without unlocking, only the public block
  interface will be exported." and "The attribute list of the block indicates
  that the relevant block is know-how protected." (6.4.2.4)
- "The XML files always consist of two major parts:" Interface and Compile
  unit (6.4.2.2).
- "One XML file is exported per PLC tag table." (6.4.4.1)
- "The value of the attribute LogicalAddress is always exported in
  international mnemonics now." (7.6.2)
- "It will be imported as standard block if you remove the prefixes "F_" from
  the value of all attributes "ProgrammingLanguage"." (6.4.2.9)

Not read: TIA Portal project files, the SIMATIC SD document export
("Exporting program block as document"), GRAPH and LAD/FBD internals beyond
hashing, technology objects, HMI objects (a SimaticML document without `SW.*`
objects is refused), and safety-program signatures.

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

A file that does not begin with markup is refused before step 3. In a
SimaticML directory every `.xml` file goes through the same steps (one refused
file refuses the directory), the size cap applies to the total, at most 50,000
files are read, and symbolic links are not followed. SCL `Blank` counts are
not expanded and `NewLine` counts are capped at 10, so a hostile count cannot
inflate memory; a file nested too deeply to render is refused, never a crash.

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

SimaticML fixtures (`tests/fixtures/logic/simaticml/`): a baseline directory
of seven files (an OB with a LAD and an SCL network, an SCL FB, an STL FC, a
know-how-protected FC exported interface-only, a global DB, a PLC data type
and a tag table), the same directory with only the export time changed, and a
DOCTYPE/ENTITY file. Cases built from them: SCL change in the OB (`logic`)
and the FB (`aoi`), interface member added, start values changed (including
an array element and a constant), OB priority changed (`tasking`), OB without
read-only attributes (not evaluated), LAD change (opaque), LAD wire order and
SCL `UId` renumbering (no difference), comment and title edits
(documentation-only), STL change and skipped empty statements,
know-how-protected block interface-only (not evaluated) and with content
(hash), tag-table address, constant and added tag, a block missing from the
directory, single file against directory, DOCTYPE in a file and in a
directory, unreadable files listed, duplicate objects refused, an unknown SCL
element, interface snapshot values, format detection by content, SimaticML
against L5X, hostile counts and nesting, and the CLI exit codes.
