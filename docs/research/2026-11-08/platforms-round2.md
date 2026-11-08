# Platform catalog research notes, round 2 (2026-11-08)

Stream: the six platform records other records referenced but nobody had
written. Records written: ICS-0014, ICS-0002, ICS-0009, ICS-0008, ICS-0015,
ICS-0012. Round 1 notes: `platforms.md` in this directory.

All pages were fetched with Firecrawl on 2026-11-08. "Direct" means the quote
was copied from the rendered page. Large PDFs and long pages were saved from
the fetch result and every quote taken from them was checked programmatically
(whitespace-normalised substring match): CERT Polska PDF, Hitachi Energy 670
guideline, SIPROTEC 5 operation manual, MicroLogix 1400 user manual, CODESYS
SP22 release notes, OMRON W503 (first 90 pages), OMRON NX1P2 specification,
OPC 10000-5 6.4, AVEVA PI pages. Quotes from short pages returned inline
(CERT Polska blog, CISA alerts and AA22-103A, FBI PSA, Rockwell SD1790,
Hitachi Energy RTU500 page, ESET Industroyer whitepaper, CODESYS help pages,
Mandiant INCONTROLLER, OPC 10000-3 9.5 and 10000-12 7.10.12) were compared by
eye with the rendered text. No record rests on a summariser read except where
marked.

Collection impact ratings follow CLAUDE.md and round 1: reading a device's own
front panel or a vendor-documented web/diagnostic page is `read-only`; going
online with engineering software is `online-vendor-tool`; physical switch
manipulation on a running controller, root shells on controllers, logging in
where CODESYS warns of safety-controller interruption, and active discovery
sweeps are `process-risk`.

---

## ICS-0014 Substation RTU and protection IED

- **CERT Polska, Energy Sector Incident Report (PDF)** -
  https://cert.pl/uploads/docs/CERT_Polska_Energy_Sector_Incident_Report_2025.pdf
  (direct; the blog page was read too). Names Hitachi RTU560 (firmware
  12.6.6.0, 12.7.3.0, 13.1.1.0, 13.5.2.0; "Default" account; corrupted ELF
  firmware reporting 13.5.3.0; 240 bytes of 0xFF at entry point; reboot loop),
  Mikronika Linux RTUs (root SSH, files deleted, command not in
  .bash_history, partial logs recovered showing scanning on 25 December),
  Hitachi Relion 650 v1.1 (FTP enabled by default, system files deleted),
  Mikronika Syndis HMIs, Moxa NPort 6xxx (factory reset, password and IP
  changed). Prints an RTU event log excerpt: columns Seq. No., Timestamp, User
  name, Event id, Severity, Source, Event text, Extra info; IDs 1110, 2240,
  13400, 5110, 5160. Secure update introduced 13.2.1, opt-in, none enabled;
  CVE-2024-2617 bypass fixed 13.7.7. Hitachi Energy PSIRT confirmed.
- **CISA alert, 10 February 2026** (direct): firmware verification and
  inoperative-device planning.
- **Hitachi Energy 670 series v2.2 Cybersecurity deployment guideline
  (1MRK 511 399-UEN)** (direct): security event fields, 10240-event store,
  no resend after server outage, up to six syslog/CEF servers (all Off by
  default), PCM600 Event Viewer, SECAUD role, full event-number table
  (1110 ... 14520), disturbance records only over clear-text FTP. The same
  numbers and texts appear in CERT Polska's RTU560 excerpt - recorded as a
  toolkit inference, not a vendor statement.
- **Siemens SIPROTEC 5 Operation manual V08.83** (direct, cache.industry.
  siemens.com): log overview; security log (2048, not user-deletable, menu
  paths); setting-history log (200, not deletable, "DCF uploaded"); initial
  start after a software update deletes operational, fault, setting-history
  and other logs (security log not listed); COMTRADE export; fault-log
  deletion resets counters to 0.
- **Hitachi Energy RTU500 function and software page** (direct): archives on
  CompactFlash incl. security events and relay disturbance files; web-server
  and file-transfer access.
- **ESET Win32/Industroyer whitepaper** (direct): wiper targets .scl/.cid/.scd
  and ABB files; 61850 module subnet sweep on TCP 102 and MMS enumeration of
  CSW nodes; SIPROTEC DoS (CVE-2015-5374, UDP 50000). Packet bytes were not
  copied into the record.

Not read / failed: Hitachi Energy "RTU cybersecurity solutions" PDF on
publisher.hitachienergy.com (all fetch engines failed); RTU500 cybersecurity
deployment guideline and syslog configuration; Relion 650 v1.1 manuals;
SIPROTEC 4 (Industroyer's actual DoS target); any Mikronika documentation;
Dragos Poland blog (not needed beyond the incident record). A Scribd copy of
an RTU500 security overview was seen in search and rejected.

## ICS-0002 Rockwell MicroLogix 1100 / 1400

- **MicroLogix 1400 User Manual 1766-UM001P-EN-P (March 2024)** (direct):
  LCD mode switch (PROGRAM/REMOTE/RUN, shown on every screen), ENET Cfg
  Status (MAC and IP), Fault Code (not shown automatically), System
  Information (OS series, firmware), memory module 1766-MM1 (one program,
  Program Compare via S:2/9, permanent write protection), embedded web server
  (FRN3 added data-file write), EtherNet/IP with Modbus TCP or DNP3, "ST file
  type for all PCCC commands".
- **Rockwell SD1790 rev. 5.0** (direct, public trust-center page): campaign
  set passwords "where no passwords were previously set"; recovery erases
  program, data and IP configuration (1400: battery removal; 1100: firmware
  update over DF1 serial); FRN 21.002 Enhanced Password Security; also covers
  Micro820/850 (out of scope).
- **FBI/EPA PSA I-073026-PSA** (direct) and **CISA alert 30 July 2026**
  (direct).

Still no source for any on-controller audit log, change-detection value or
syslog on either model; the record says so and stays thin. Not read:
1763-UM001 (MicroLogix 1100), 1766-RM001 (master password semantics; a
Scribd copy and forum posts were seen and rejected). Third-party blogs giving
LCD default passwords were rejected and no default credential is reproduced.

## ICS-0009 CODESYS V3 runtime-based controllers

- **CODESYS Online Help V3.5 SP22**: Tab: Log (PlcLog contents; AuditLog
  logger records download/start/stop/breakpoints with user name and failed
  attempts; XML export; UTC option), Command: Login (unchanged / changed /
  unknown application; Application Information comparison; "Login without
  any change"; safety-controller interruption warning; one instance per
  application from SP17; programming ports), Downloading Source Code to and
  from the PLC (Archive.prj). All direct.
- **Release Notes CODESYS V3.5 SP22** (direct): audit files renamed
  .Audit.log -> .AuditLog.csv; login success/failure, user-locked and expiry
  audit events; OPC UA AuditEvent forwarding (writes and method calls not
  yet audited); [CmpLog] Logger.N.Name path examples.
- **Mandiant INCONTROLLER** (direct) and **CISA AA22-103A** (direct): CODECALL
  file listing/deletion, credential brute force over UDP 1740.

Rejected: forge.codesys.com forum posts and industrialmonitordirect.com blogs
(runtime config file name, default log paths, PlcLogic paths) - user posts and
third-party blogs, not vendor documentation; the record names no default path.
Not read: CODESYS advisory on INCONTROLLER (customers.codesys.com tokenised
download), CODESYS Security Whitepaper (cited only through ICS-PROTO-0015).

## ICS-0008 OMRON Sysmac NJ / NX

- **OMRON NJ/NX-series Troubleshooting Manual W503** (direct, first 90 of 1282
  pages): event-log concept; storage (battery-backed NX701, non-volatile
  NX502/NX102/NX1P2); CSV export from Sysmac Studio or HMI; Event Log Viewer;
  System and Access event log tabs with Save and Clear; information events
  such as Memory All Cleared.
- **OMRON NX1P2 specification page** (direct): event-log maxima (576/528/512
  with CPU/NX split), Sysmac Studio backup/restore/verify, SD card backup via
  DIP switch, CPU Unit name check, write protection, "User Program Transfer
  with no Restoration Information", FTP server on the SD card.
- **Mandiant INCONTROLLER** and **CISA AA22-103A** (direct): OMSHELL telnet
  activation, program-memory wipe and reset, agent over HTTP/HTTPS, file
  backup/restore; target list.

Gap: the access-event list (which operations are logged) is in later W503
chapters and W501, not read. NJ-series and NX701/NX5 datasheet capacities
(distributor and OMRON PDFs) were seen only in search snippets and not used.

## ICS-0015 OPC UA servers

- **OPC 10000-3 9.5 AuditEventType** (direct): audit events for accepted and
  security-rejected actions; AuditEntryId; persistence optional, delivery to
  subscribers mandatory.
- **OPC 10000-5 6.4** (direct): audit event type catalogue (headings only;
  tables not quoted).
- **OPC 10000-12 7.10.12 GetRejectedList** (direct): rejected-certificate
  list, SecurityAdmin role, no defined retention.
- **CISA AA22-103A**, **Mandiant INCONTROLLER** (direct): TAGRUN behaviour and
  audit-review guidance; application authentication and trust lists.
- **CODESYS SP22 release notes** (direct) as an example of partial
  implementation.

Not read: any vendor OPC UA server manual (Kepware, Prosys, Unified
Automation, Siemens, Schneider); OPC Foundation security best-practices PDF.

## ICS-0012 OT historian (AVEVA PI)

- **AVEVA PI Data Archive reference** (all direct): Audit Database overview
  (scope; normal interface data not audited; three files in PI\log), PI
  AuditViewer (search/filter/export; records "cannot be altered" per AVEVA;
  download from the customer portal), PI Message Subsystem log messages
  (pigetmsg in PI\adm), Client connection log messages (pinetmgr examples
  with IDs 7004, 7039, 7082, 7076, 7138, 7096; examples dated 2009, partly
  PI API 1.6.8-specific).
- Round 1's summariser read of the AuditViewer page is superseded by this
  direct read (ICS-DS-0011 still marks it summariser; not edited here).

Not read: EnableAudit page (cited through ICS-DS-0011), PITRUST/PIIDENTMAP,
connection history and pigetmsg option pages; interface-node message log
(seen only in a search snippet); any non-AVEVA historian.

---

## Documentation behind logins or not fetchable

- AVEVA customer portal (PI AuditViewer download).
- Hitachi Energy publisher: "RTU cybersecurity solutions" brochure failed to
  fetch; other publisher PDFs (670 guideline) did fetch.
- CODESYS customer download of the INCONTROLLER advisory (tokenised link).
- Rockwell Knowledgebase articles referenced from SD1790 (answer IDs 494865,
  1085012) - not attempted; support.rockwellautomation.com usually needs a
  login.

## Open questions for a later round

1. Does the Relion 650 v1.1 (and RTU500) use the same security event numbers
   as the 670 v2.2 guideline? Read their own manuals.
2. Which NJ/NX access-log events record downloads, mode changes, Clear All
   Memory and online connections (W501 / later W503 chapters)?
3. MicroLogix 1100 specifics (1763-UM001) and the 1766-RM001 password model.
4. Default CODESYS AuditLog and logger file locations per major OEM.
5. Persisted audit-log names and retention for the common OPC UA server
   products.
