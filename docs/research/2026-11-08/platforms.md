# Platform catalog research notes (2026-11-08)

Stream: platform catalog - forensic artifacts per controller family and OT host
role. Records written: ICS-0001, ICS-0003, ICS-0004, ICS-0005, ICS-0006,
ICS-0007, ICS-0010, ICS-0011, ICS-0013. Not written: ICS-0002, ICS-0008,
ICS-0009, ICS-0012, ICS-0014, ICS-0015 (reasons at the end).

All pages were fetched with Firecrawl on 2026-11-08. "Direct" means the quote
was copied from the rendered markdown of the page (for the Rockwell, Siemens,
CISA AA26-097A, Schneider and Tricon pages the saved markdown was checked
programmatically: every `quote` in those records is a whitespace-normalised
substring of the fetched text). "Summariser" means the text came from a
Firecrawl query/extraction or a search snippet and must be re-read before the
record can rest on it; records mark those items `unverified: true`.

Impact ratings for collection methods are this project's, following
CLAUDE.md. Where a vendor documents a read path as a display (Siemens web
server diagnostics buffer, Sierra/Teltonika log download, Ignition gateway
Status page) it is `read-only`; going online with engineering software is
`online-vendor-tool`; anything requiring STOP, card removal from a running
controller, third-party protocol tools, or live triage on a host that may hold
live controller sessions is `process-risk`.

---

## ICS-0001 Rockwell Logix 5000

Sources read (direct):

- Rockwell 1756-PM015 *Logix 5000 Controllers Information and Status*
  (Sept 2025), https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm015_-en-p.pdf
- 1756-UM900 *Change Detection* page, https://www.rockwellautomation.com/en-pl/docs/technical/logix5000/_online/1756-um900/controllogix-5590-controller-user-manual-ditamap/develop-secure-applications/change-detection.html
- 1756-UM900 *Controller Logging* page, https://www.rockwellautomation.com/en-pl/docs/technical/logix5000/_online/1756-um900/controllogix-5590-controller-user-manual-ditamap/develop-secure-applications/controller-logging.html
- CISA AA26-097A (updated 22 July 2026), https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a

Key quotes:

- PM015: "A controller log is a record of interactions that occurred in the
  controller due to physical conditions such as keywitches, changes to
  removable media, fault conditions, and programming changes configured in the
  application." (sic, "keywitches")
- PM015: "For the Compact GuardLogix 5370, CompactLogix 5370, ControlLogix
  5570, and GuardLogix 5570 controllers, the controller keeps up to 100 log
  entries buffered in its internal memory." and the 500-entry statement for the
  5380/5480/5580/5590 families (the manual's own text alternates "5460" and
  "5480").
- PM015: "If the removable media is not present, is full, or if the controller
  is not configured to automatically write buffered entries to the removable
  media, and the internal buffer becomes full, entries are saved in the buffer
  in a circular fashion. As new entries are stored, the oldest entries are
  discarded."
- PM015: "When a log file is written to the CompactFlash card, it is stored at
  \\Logix\\XXXXXXXX\\Logs\\VYY_ZZ, where XXXXXXXX is the eight-digit serial
  number of the controller and YY_ZZ is the revision number of the firmware"
  (heading text, rendered with markdown escapes) and "The log file is formatted
  in UTF-16, and has a file extension of txt."
- PM015: "In Logix Designer versions 30 and later, audit log entries also
  appear in the controller log."
- PM015 entry table: "Mode changed through keyswitch ... Entry Description:
  Keyswitch mode change ... UserName: Local"; "Mode changed through Logix
  Designer ... Entry Description: Remote mode change".
- PM015: "Use a Set System Value (SSV) instruction to set it to a known value."
  (Total Entry Count).
- PM015 ChangesToDetect bit 32: "Including the Correlation Affected event
  updates the audit value for these types of changes, even if other similar
  events (such as Online edits modified controller program or Task properties
  modified) are masked."
- UM900 Change Detection: "When the controller is offline, the Audit Value box
  is blank."
- UM900 Controller Logging: "The controller log stores various security-related
  events that can be written to a memory card or accessed via FactoryTalk®
  AssetCentre or a third-party syslog collector."
- AA26-097A: "For Rockwell Automation devices, place the physical mode switch on
  the controller into run position."; "Prior to switching the device to run
  mode, review and validate project files, as changing modes will lock in the
  current project file downloaded to the device."; "check the AOIs for any
  anomalous modifications."

Considered and rejected:

- Controller webpages (5069-UM001 snippet: "Controller webpages are read-only"
  and disabled by default from some Logix Designer version) - snippet only,
  version truncated; not listed.
- Logix Designer Compare Tool - only practitioner forum mentions; no Rockwell
  page read.
- FactoryTalk AssetCentre Getting Results Guide (FTAC-GR002) - not read; the
  PM015 statement that AssetCentre 4.1+ reads the controller log was enough.
- DFRWS EU 2022 ControlLogix 1756-L61 memory forensics paper - research
  instrumentation, not a customer acquisition path; noted, not used.
- SECURE-RM001 System Security Design Guidelines - cited by CISA, not read.

Behind logins: Rockwell Knowledgebase articles on controller-log syslog
configuration (5590) were not found publicly.

## ICS-0003 Siemens S7-1200 / S7-1500

Sources read (direct):

- Operating mode transitions, S7-1500/ET 200MP manual collection V20,
  https://docs.tia.siemens.cloud/r/simatic_s7_1500_et_200mp_manual_collection_enus_20/basic-information/automation-system/commissioning/operating-modes/operating-mode-transitions
  (the rendered page also contained memory-reset, backup-type and STOP-cause
  tables)
- CPU diagnostics buffer (diagnostics function manual, ET 200eco PN collection,
  English text), https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_zhcn_20/function-manuals/diagnostics-function-manuals/diagnostics/configuring-and-determining-system-diagnostics/options-for-displaying-system-diagnostics/diagnostics-information-in-step-7/cpu-diagnostics-buffer?contentId=iRtCUO9d12wi6MtwQSzXWg
- Syslog introduction (S7-1500), STEP 7 V21,
  https://docs.tia.siemens.cloud/r/en-us/v21/functional-description-of-s7-1500-cpus-s7-1500/setting-the-operating-behavior-s7-1500/protection-security-s7-1500/syslog-s7-1500/introduction-s7-1500
- What you should know about the access levels (S7-1500), STEP 7 V20,
  https://docs.tia.siemens.cloud/r/en-us/v20/functional-description-of-s7-1500-cpus-s7-1500/setting-the-operating-behavior-s7-1500/protection-security-s7-1500/settings-for-access-levels-s7-1500/what-you-should-know-about-the-access-levels-s7-1500

Key quotes:

- "The 500 newest entries in the diagnostics buffer are retained." (POWER ON
  and STOP-to-STARTUP rows)
- "The diagnostics buffer, time of day, and IP address are retained." (memory
  reset)
- Backup types table: "Entries in the diagnostics buffer" is "--" for every
  backup type; "Backup possible in operating mode | STOP | RUN, STOP | RUN, STOP
  | RUN, STOP" (Backup from online device needs STOP).
- STOP causes: "Via STP instruction, mode selector switch/button, display, STEP
  7, HMI, web server or SAT tool".
- "The following security events (event types) result in an entry in the
  diagnostics buffer." followed by: going online with correct/incorrect
  password; manipulated communications data; manipulated data on memory card;
  manipulated firmware update file; changed protection level downloaded;
  password legitimization restricted/enabled; online access denied (too many
  attempts); idle online-connection timeout; web server logon correct/incorrect;
  creating a backup; restoring the CPU configuration.
- "To prevent the diagnostics buffer being "swamped" by large numbers of
  identical security events, you can set parameters so that these events are
  entered in the diagnostics buffer as a group alarm."
- "The browser displays the content of the diagnostics buffer on the
  "Diagnostics buffer" Web page."
- Syslog: "Each CPU as of FW version V3.1 saves syslog messages in a local
  cache. ... use the Web API of the web server (API method `Syslog.Browse`).";
  transfer via "Properties > Protection & Security > Syslog > Syslog server",
  TLS port 6514 or UDP 514; "The content of the messages is based on IEC
  62443-3-3."
- Access levels: Read access permits "changing the operating state (RUN/STOP)";
  "The default access level is "No access (complete protection)"."; checksum
  comparison "requires the "read access" access level".

Considered and rejected:

- S7-1200-specific buffer size and security events - not read; record says so.
- TIA Portal project checksum / "compare online/offline" as a separate
  integrity feature - covered via the access-levels page; the Siemens
  compare-editor documentation was not read.
- Siemens support entry 109823696 (syslog message overview) - linked from the
  syslog page, not read (SIOS entries often need a login for downloads).
- Siemens Industrial Security operational guidelines (cited by AA26-097A) - not
  read.

## ICS-0004 Siemens S7-300 / S7-400

Sources read:

- Diagnostics buffer (S7-300, S7-400), STEP 7 V21 functional description,
  https://docs.tia.siemens.cloud/r/en-us/v21/functional-description-of-s7-300/400-cpus-s7-300-s7-400/memory-areas-s7-300-s7-400/contents-of-work-and-system-memory-s7-300-s7-400/diagnostics-buffer-s7-300-s7-400 (direct)
- Symantec *W32.Stuxnet Dossier* v1.4 (Feb 2011), National Security Archive
  copy, https://nsarchive2.gwu.edu/NSAEBB/NSAEBB424/docs/Cyber-044.pdf (direct,
  69 pages)
- Siemens S7-300 CPU 31xC/31x technical specifications - search-result
  rendering only (mode selector RUN/STOP/MRES), https://cache.industry.siemens.com/dl/files/906/12996906/att_70325/v1/s7300_cpu_31xc_and_cpu_31x_manual_en-US_en-US.pdf

Key quotes:

- Siemens: "The entries in the diagnostics buffer cannot be deleted; the content
  of the diagnostics buffer is retained even after a memory reset."; "The
  diagnostics buffer is designed as a ring buffer. The maximum number of entries
  depends on the module; for example, the S7-300 CPU 314 can have 100 entries.";
  "With some CPUs, it is possible to assign the length of the diagnostics
  buffer."; events include "User-defined diagnostics events using system
  function SFC 52".
- Symantec: "once Stuxnet executes, it renames the original s7otbxdx.dll file to
  s7otbxsx.dll. It then replaces the original .dll file with its own version.";
  "The intercepted exports are the routines to read, write, and enumerate code
  blocks on the PLC, among others."; "Victims attempting to verify the issue
  would not see any rogue PLC code as Stuxnet hides its modifications."; "One can
  recognize an infected PLC in a clean environment by examining blocks OB1 and
  OB35."; targets "CPUs 6ES7- 315-2 (series 300)" and "the 6ES7-417 family".

Deliberately not reproduced: the STL instruction sequences Symantec prints for
infected OB1/OB35 (detection signatures belong in a YARA/pack record if anyone
writes one, not in the catalog).

Considered and rejected: Langner's Stuxnet analysis (second source) - not read
this pass, so Stuxnet-specific artifacts stay `low` + `unverified`.

## ICS-0005 Schneider Electric Modicon

Sources read:

- Modicon Controller Systems Cybersecurity User Guide EIO0000001999.12, read
  directly from a distributor-hosted copy,
  https://docs.rs-online.com/7a9a/A700000012779990.pdf (170 pages). The official
  link https://www.se.com/ww/en/download/document/EIO0000001999/ returned a
  country selector to the fetcher.
- CISA ICSA-23-227-01 - search-result text only (summariser); used as a
  reference that cites EIO0000001999 and its "CPU Memory Protection section".
- CISA AA26-097A (direct).

Key quotes (direct):

- "The events related to cybersecurity are logged locally and sent to a remote
  server using Syslog protocol."; "Syslog exchanges are done with TCP
  protocol."; "Events are lost in case of device reset (except for Modicon M580
  controller firmware ≥ 4.0)."
- Control Expert setup: "Click Tools > Project Settings." / "Click Project
  Settings > General > PLC diagnostics." / "Select Event Logging check box
  (cleared by default)."
- "The memory protection prohibits the transfer of a project into the
  controller and modifications in online mode, regardless of the communication
  channel." and "It is a good practice to activate the controller memory
  protection whenever possible."
- M580 FW 4.10 event table rows quoted in the record (UMAS login problem,
  OPERATING_MODE_CHANGE, invalid firmware). Note Schneider's naming: BACKUP is
  "Download of application from the controller"; RESTORE is "Upload of
  controller Application/ Configuration inside the controller" - the reverse
  of Rockwell/Siemens upload/download wording.
- M340 services table: event logging and integrity checks "-" for every BMX P34
  CPU.

Considered and rejected:

- M580 Hardware Reference Manual (EIO0000001578) "Event Log ... Download File"
  web page - search snippet only; recorded as a lead in notes.
- M221/M241/M251/M258 (SoMachine/Machine Expert) - not researched.

## ICS-0006 Unitronics Vision / Samba

Sources read (direct):

- CISA AA23-335A (rev. 18 Dec 2024), https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a
- Claroty Team82, *From Exploits to Forensics: Unraveling the Unitronics
  Attack* (7 Aug 2024), https://claroty.com/team82/research/from-exploits-to-forensics-unraveling-the-unitronics-attack
- Unitronics, *Cyber Protection - Vision and Samba Series*,
  https://www.unitronicsplc.com/cyber_security_vision-samba/

Key quotes:

- AA23-335A: "The actors did not burn their ladder logic file to the device,
  preventing the retrieval of the ladder logic file from the device."; "The
  actors changed the default port number for communicating remotely with the
  PLC device (from `20256` to `20257`)"; "The actors set the software version of
  their ladder logic file to an older version"; "The PLCs may be rebranded and
  appear as originating from different manufacturers and companies."
- Claroty: "This log contains a list of all the interactions that users
  performed with the PLC." (signature log); "Our client allows users to connect
  to their Unitronics PLC, extract its exact version, name and type, as well as
  read/write its raw memory." (why PCOMClient is rated process-risk).
- Unitronics: PCOM levels "Blocked Access", "Operator: Viewing and updating
  data.", "Technician: Troubleshooting, changing controller settings, and
  updating versions."

Considered and rejected:

- Unitronics VisiLogic help for burn / upload password / SB 314 MFA - not read.
- PCOM function codes listed by Claroty - deliberately not reproduced (protocol
  command detail not needed for defence here).

## ICS-0007 Schneider Electric Triconex

Sources read:

- *Technical Product Guide for Tricon v10 Systems*, distributor-hosted copy,
  https://www.rms-dcs.com/uploads/8312.pdf (all 35 pages; direct)
- Mandiant, *Attackers Deploy New ICS Attack Framework "TRITON"* (14 Dec 2017),
  https://cloud.google.com/blog/topics/threat-intelligence/attackers-deploy-new-ics-attack-framework-triton (direct)
- FBI PIN 20220324-001, https://www.ic3.gov/CSA/2022/220325.pdf (direct)

Key quotes:

- Tricon guide: "The keyswitch setting is readable by Tricon controllers,
  TriStation 1131 software, and the control programs."; RUN "Normal operation
  with readonly capability."; REMOTE "Allows writes to program variables by
  TriStation 1131 and external hosts. (Download All and Download Changes by
  TriStation 1131 are not allowed.) Modification of program logic is not
  allowed."
- Mandiant: "If this failed, trilog.exe attempted to write a small ‘dummy’
  program to memory. We assess that this was an anti-forensics technique to
  hide the presence of the attacker code on the Triconex controller."
- FBI: "Operator stations should be configured to display an alarm whenever the
  SIS safety controller key switch is in the “PROGRAM” mode."

Considered and rejected / not reached:

- NRC-hosted TriStation 1131 v4.1 manual (https://www.nrc.gov/docs/ml0932/ml093290419.pdf)
  - fetch timed out at 60 s; read next.
- CyOTE TRITON case study (INL) - snippet only ("After verification of PROGRAM
  mode on the Triconex controller, the script downloads...") - not used.
- Schneider Triconex security notification and CISA MAR HatMan - not read.
- Whether keyswitch changes are logged persistently on the controller - no
  source found; the record says so.

## ICS-0010 Windows engineering workstation

Sources read (direct unless noted):

- NVISO Labs (Olaf Schwarz), *Investigating an engineering workstation* parts
  1-3 (2022), https://blog.nviso.eu/2022/03/15/investigating-an-engineering-workstation-part-1/ ,
  https://blog.nviso.eu/2022/03/30/investigating-an-engineering-workstation-part-2/ ,
  https://blog.nviso.eu/2022/04/20/investigating-an-engineering-workstation-part-3/
- Chan and Chow, *Forensic Analysis of a Siemens Programmable Logic Controller*
  (IFIP, HAL), https://inria.hal.science/hal-01614856/file/434671_1_En_7_Chapter.pdf
  - search snippet only (summariser)
- Schneider EIO0000001999.12 (Control Expert event logging), Claroty Team82
  (VisiLogic project database), Mandiant TRITON (trilog.exe), CISA AA26-097A
  (.ACD), Microsoft event 4624 and Sysmon pages.

Key quotes:

- NVISO P1: "The Prefetch artifact, if enabled on the system, would be written
  for “SIEMENS.AUTOMATION.PORTAL.EXE” and can be parsed like any other prefetch
  file."; "If a project is created and saved in the TIA Portal it will not show
  up in the Jump List." Jump List AppID 4c28c7c161e44256.
- NVISO P2: Settings.xml path (V15.1) C:\Users\$USERNAME\AppData\Roaming\Siemens\Portal V15_1\Settings\ ;
  "The file is written as part of the tasks performed when the TIA Portal is
  closed normally."; "As demonstrated in the screenshot the “OamAddress” node can
  give us information like the IP-Address and subnet-mask used to reach the PLC."
- NVISO P3: "The file we are actually looking for is named “PEData.plf” and
  located in the “System” folder stored within the “root” folder of the
  project."; "Currently we believe that only 4 “DownloadLog” entries, showing new
  download activity, are added to the “PEData.plf” file."
- Chan and Chow (snippet): "The PEData.plf project file is generated by the
  Siemens TIA Portal."
- Microsoft 4624 type 10: "A user logged on to this computer remotely using
  Terminal Services or Remote Desktop."
- Sysmon: "The network connection event logs TCP/UDP connections on the machine.
  It is disabled by default."

Confidence: TIA Portal Settings.xml and Windows-artifact behaviour rest on one
researcher (NVISO, V15.1 only) and are `low` + `unverified` per CLAUDE.md. NVISO
also published a KAPE target (SiemensTIA.tkape) - same author, not counted as
independent.

Considered and rejected:

- Studio 5000 / RSLinx / FactoryTalk Linx workstation logs and recent-project
  lists - searched; only release notes and forum posts found. Not listed.
- NVISO part 4 (network traffic) - not read.
- RDP-specific channels (TerminalServices-LocalSessionManager 21/24/25) - only a
  third-party blog (Elcomsoft) surfaced; Microsoft page not read; not listed.

## ICS-0011 Windows HMI / SCADA server

Sources read:

- Ignition 8.1 *Audit Log and Profiles*, https://www.docs.inductiveautomation.com/docs/8.1/platform/audit-log-and-profiles (direct)
- Rockwell FTALK-WP003 *Guidelines for applying FactoryTalk View SE in a 21 CFR
  Part 11 environment*, https://literature.rockwellautomation.com/idc/groups/literature/documents/wp/ftalk-wp003_-en-e.pdf
  (Firecrawl query extraction - summariser)
- CISA AA26-097A; Microsoft 4624 (direct)

Key quotes:

- Ignition: "Ignition's built-in auditing system automatically records certain
  actions that occur in the system, such as a Tag writes or User Source
  authentication, into a SQL database table."; "The only way to interact with
  the Internal Audit Profile is via the Status page of the Gateway webpage.";
  retention "Default is 90 days."
- FTALK-WP003 (summariser): "FactoryTalk View SE provides an audit trail for
  actions performed that is minimally comprised of a time and date stamp,
  operator ID and full name, and the action taken."; Diagnostics Setup: "Leave
  the Logging path at its default. Make sure the maximum log size is large, for
  example 25,600 KB. Overwrite events as needed."
- AA26-097A: "Additionally, the changes disabled critical shutdown and alarm
  logic, allowing systems to enter unsafe conditions without notifying operators
  of the anomalies."

Not researched: WinCC (Classic/Unified audit trail), iFIX, InTouch.

## ICS-0013 Cellular and remote-access gateways

Sources read:

- Sierra Wireless Source, *Logging - AirLink OS RX55-5.1*,
  https://source.sierrawireless.com/airlinkos/RX55-5.1/reference/system/howto/logs/ (direct)
- Teltonika wiki *RUT230 Logs* and *RUT230 Events Log* (direct),
  https://wiki.teltonika-networks.com/view/RUT230_Logs ,
  https://wiki.teltonika-networks.com/view/RUT230_Events_Log
- Teltonika wiki *TRB143 Maintenance* (query extraction - summariser),
  https://wiki.teltonika-networks.com/view/TRB143_Maintenance
- CISA AA26-097A; Unitronics cyber protection page (direct)

Key quotes:

- Sierra: "Note: Neither factory resetting nor reflashing will erase the logs.
  There is no current method to erase either of the logs."; "Audit logs contain
  all the device changes since date of manufacture."; "The AirLink logs do not
  contain any passwords."
- Teltonika: "In the Events Log window you can view records of events such as
  logins, reboots, resets, connections, configuration changes and more."
- Teltonika TRB143 (summariser): "Save log in | RAM memory | Flash memory;
  default: RAM memory | Specifies which type of memory to use for storing system
  logs."; "System log file size ... default: 128".
- AA26-097A: Dropbear SSH on victim modems via port 22; "Enable logs for
  connected modems and regularly review for suspicious activity".

Not researched: ALEOS (Sierra's older OS) and its Secure Deployment and
Operation Guide (listed on source.sierrawireless.com), Moxa, Digi.

---

## Platforms not written, and why

- ICS-0002 Rockwell MicroLogix 1100/1400 - no vendor or researcher source on
  on-controller logging or integrity features was found in one search; academic
  PLC memory-forensics results returned were for ControlLogix and Modicon M221.
  Writing a record would mean guessing. Placeholder removed.
- ICS-0008 OMRON NJ/NX, ICS-0009 CODESYS, ICS-0012 historian, ICS-0014
  RTU/IED, ICS-0015 OPC UA servers - not reached in this pass's scrape budget.
  Leads: Mandiant/Dragos INCONTROLLER (PIPEDREAM) reports for OMRON and CODESYS;
  DFRWS "Towards generic memory forensic framework for PLCs" (Modicon M221);
  AVEVA PI audit documentation for historians.

## Documentation behind logins or not fetchable

- Rockwell Knowledgebase (controller-log syslog setup for 5590; AssetCentre
  procedures) - customer login.
- Siemens SIOS support entries (e.g. 109823696 syslog message overview) - not
  attempted; downloads commonly require a login.
- Schneider se.com document downloads - returned a country selector to the
  fetcher; distributor copy used instead.
- NRC-hosted TriStation 1131 v4.1 manual - public but timed out.
