# Visibility blind spots - research notes (2026-11-08)

Stream: close the MAPPINGS.md "Blind spots" list - ATT&CK techniques that a
recorded malware family, actor or incident uses but that no
`artifacts/visibility/` record maps to an event (`mappings.coverage()` counts a
technique as *seen* only when it sits in an `events[].attack` list).

Result: **60 blind spots before, 10 after.** Only `events` and `sources` of
`artifacts/visibility/ICS-DS-0001..0013` were edited; ICS-DS-0014 needed no
change. MAPPINGS.md is not regenerated here.

## Method

- Every one of the 60 technique pages on attack.mitre.org was read on
  2026-11-08 with Firecrawl (markdown, `onlyMainContent`, restricted with
  `includeTags` to the page heading and the Detection table). Quotes below and
  in the records' `sources` are copied from that rendering: `read: direct`,
  `kind: standard`.
- **ATT&CK has changed shape.** The live site (v20, pages "Last Modified: 13
  October 2026") no longer prints a "Data Source / Data Component" table. Each
  technique page has a **Detection Strategy** table (DET id, analytic AN id,
  analytic description). Mappings below rest on the analytic description,
  which names the telemetry (ICS protocol traffic, NetFlow, a Windows process,
  a field device event log, and so on). The data components themselves sit on
  the detection-strategy pages, which were not read.
- Two Microsoft pages needed for new events were read with the Microsoft Learn
  fetch (full page converted to markdown, as in `datasources.md`): Sysmon
  v15.22 (Event ID 10) and 4778(S).
- A technique was mapped only where the event records the activity the
  analytic describes. Where the analytic needs a correlation the event cannot
  supply alone (an independent measurement, a USB insertion record), the
  mapping is kept and the gap is stated below.
- Existing events keep their `basis` (it describes where the event's own
  description comes from, mostly vendor documentation). The ATT&CK basis for
  each added id is the MITRE source appended to that record and listed here.
  The two new events are `basis: vendor` because their text is Microsoft's.

### ATT&CK ids that now redirect or are deprecated

These ids are still used by intel records, so they were mapped, but the
records that use them may want migrating (not done here - outside this
stream):

| Id used in records | Live page | Note |
| --- | --- | --- |
| T0812 Default Credentials | T1694.001 Insecure Credentials: Default Credentials | Firecrawl followed a redirect from /T0812/ |
| T0855 Unauthorized Command Message | T1692.001 Unauthorized Message: Command Message | redirect |
| T0857 System Firmware | T1693.001 Modify Firmware: System Firmware | redirect |
| T0807 Command-Line Interface | T0807 | "Deprecation Warning"; no Detection Strategy table |
| T0853 Scripting | T0853 | deprecated (noindex); no Detection Strategy table |

T0807 and T0853 have no MITRE analytic. They are mapped on the vendor basis the
record already carries: Security 4688 records "Process Command Line" when the
group policy is enabled, and PowerShell 4104 "records the content of all
scriptblocks that it processes" (ICS-DS-0006's existing Microsoft sources).

## Mapped (50 techniques)

Analytic text is verbatim from the technique page's Detection Strategy table
(shortened with "..." only here; the record sources carry the full sentence).

### Controller logic, mode and firmware

| Technique | Data source -> event | MITRE analytic |
| --- | --- | --- |
| T0821 Modify Controller Tasking | DS-0001 `s7comm_upload_download.log` | AN1874: "an Industrial Control System (ICS) protocol write to a controller's task/organization-block configuration from a source not in the approved engineering workstation list" |
| T0843 Program Download | DS-0001 `s7comm_upload_download.log`; DS-0007 Control Expert "Transfer project to PAC"; DS-0008 "Project download"; DS-0013 M580 "Restore operation." (same event entry as "Backup operation.") | AN1884: "an Industrial Control System (ICS) protocol session consistent with a program download to a field device from a source not in the approved engineering workstation list" |
| T0845 Program Upload | DS-0001 `s7comm_upload_download.log`; DS-0007 "Transfer project from PAC"; DS-0013 M580 "Backup operation." | AN1893: "an Industrial Control System (ICS) protocol session reading back the user program from a field device" |
| T0889 Modify Program | DS-0001 `s7comm_upload_download.log`; DS-0007 "Build online run/stop", Logix audit-log entries, project file differences; DS-0008 "Online edits modified controller program", audit-log entries, AuditValue; DS-0013 S7-1500 syslog | AN1915: "an Industrial Control System (ICS) protocol write to an existing program block ... correlated against post-modification program hash comparison" |
| T0858 Change Operating Mode | DS-0007 "Start stop or initialize the PAC"; DS-0008 "Remote mode change"; DS-0009 operating mode transitions; DS-0013 M580 "Operating mode change", S7-1500 syslog | AN1887: "an Industrial Control System (ICS) protocol mode-change command targeting a field device from a source not in the approved engineering workstation list" |
| T0857 System Firmware (T1693.001) | DS-0008 "Firmware update"; DS-0013 M580 "Firmware update", S7-1500 syslog | AN1864: "a field device entering firmware update mode and receiving a large data transfer ... followed by a device reboot, with post-reboot firmware hash not matching the authorized inventory" |
| T0872 Indicator Removal on Host | DS-0006 unexpected clearing of logs; DS-0008 "Log Collected Data Cleared" | AN1882: "an audit log clearing event or deletion/truncation of an Industrial Control System (ICS) vendor application log file"; AN2245: "Industrial Control System (ICS) field device event logs being cleared via ICS protocol commands" |

### ICS protocol commands, reads and discovery (passive network)

| Technique | Data source -> event | MITRE analytic |
| --- | --- | --- |
| T0801 Monitor Process State | DS-0001 `modbus_detailed.log`; DS-0002 eve `modbus`; DS-0003 flow record | AN1860: "a source issuing read-only Industrial Control System (ICS) protocol requests to multiple field devices at a polling rate exceeding the legitimate ... baseline"; AN2169: "NetFlow showing a host generating an anomalously high volume of short-duration flows to multiple field device IPs" |
| T0836 Modify Parameter | DS-0001 `modbus_detailed.log`; DS-0002 Modbus write rules; DS-0011 setpoint time series; DS-0007/DS-0008 Logix audit-log "changes to tag values"; DS-0010 Ignition AUDIT_EVENTS tag writes | AN1908: "an Industrial Control System (ICS) protocol write to a parameter/setpoint register ... correlated with subsequent historian tag drift" (DS-0007/0008/0010 rest on their vendor sources, which name tag-value changes and tag writes) |
| T0855 Unauthorized Command Message (T1692.001) | DS-0001 `modbus_detailed.log`, `dnp3.log`/`dnp3_control.log`, `iec104_ctrl.log`; DS-0002 Modbus write and DNP3 rules | AN2212: "a control/command message arriving at a field device from a source not in the approved control server list" |
| T0835 Manipulate I/O Image | DS-0001 `modbus_detailed.log` | AN1905: "protocol write to output register addresses on a field device ... correlated with a discrepancy between the value reported by the Input/Output (I/O) image and an independent measurement" |
| T0877 I/O Image | DS-0001 `modbus_detailed.log` | AN1906: "a single Industrial Control System (ICS) protocol session reading the complete Input/Output (I/O) image from a field device" |
| T0861 Point & Tag Identification | DS-0001 `modbus_detailed.log`, `opcua_binary.log`; DS-0003 flow record | AN1920: "protocol session that systematically enumerates a device's full tag/object namespace"; AN2177: "NetFlow showing a source making sequential connections to multiple field device Internet Protocol (IP) addresses" |
| T0888 Remote System Information Discovery | DS-0001 `modbus_read_device_identification.log`, `s7comm_read_szl.log`, `cip_identity.log` (enip/cip entry); DS-0002 ENIP/CIP rules | AN2249: "protocol requests targeting device identification and system metadata objects from a source not in the approved control server list" |
| T0846 Remote System Discovery | DS-0001 enip/cip logs; DS-0002 ENIP/CIP rules; DS-0003 flow record | AN2171: "ICS discovery broadcasts or sequential connection attempts across the full IP range of a device subnet ... Documented in the PIPEDREAM/INCONTROLLER toolset's CODECALL module for EtherNet/IP device discovery." |
| T0871 Execution through API | DS-0001 `opcua_binary.log` | AN2289: "network traffic to ... API ports such as 4840 used in the Open Platform Communications (OPC) Unified Architecture (UA) ... consistent with write/control method invocations" |
| T0893 Data from Local System | DS-0001 `s7comm_upload_download.log` | AN2244: "protocol sessions that bulk-read configuration data, program blocks, or data record objects from field devices" |
| T0814 Denial of Service | DS-0002 `modbus.flooded`; DS-0003 flow record; DS-0006 System 7034/7036 | AN1856: "a sustained spike in malformed or high-volume Industrial Control System (ICS) protocol traffic directed at a single field device"; AN2268: "an ... ICS Windows service ... becoming unresponsive ... correlated with watchdog timeout or service crash events" |
| T0819 Exploit Public-Facing Application | DS-0002 eve `alert`; DS-0006 Sysmon 1 | AN2173: "exploit-pattern HTTP/HTTPS traffic targeting an ICS DMZ application"; AN1873: "web Human-Machine Interface (HMI) ... process spawning an unexpected child process" |
| T1595.002 Vulnerability Scanning | DS-0002 eve `alert`; DS-0004 inbound OT-port sessions | AN1999: "packet inspection associated to protocol(s) that do not follow the expected protocol standards"; "Monitor network data for uncommon data flows." |
| T0869 Standard Application Layer Protocol | DS-0003 outbound beaconing; DS-0004 outbound sessions; DS-0006 Sysmon 3 and 22 | AN2223: "an embedded field device or gateway initiating outbound connections on standard application-layer protocol ports" and "implementable from session/flow metadata"; AN2281 (Windows outbound HTTP/HTTPS/DNS); AN1931 (DNS queries to external resolvers) |
| T1041 Exfiltration Over C2 Channel | DS-0003 outbound beaconing; DS-0004 outbound sessions; DS-0006 Sysmon 3 | AN0988: "suspicious outbound traffic volume mismatches from processes that typically do not generate network activity" |

### Access and credentials

| Technique | Data source -> event | MITRE analytic |
| --- | --- | --- |
| T0812 Default Credentials (T1694.001) | DS-0010 Ignition AUDIT_EVENTS (User Source authentication); DS-0012 gateway administrative logins; DS-0013 M580 "Successful connection" / "Connection problem" | AN1888 (HMI, historian, SCADA authentication), AN2193 (network device management interfaces), AN2218: "successful authentication to a field device using credentials matching documented vendor-default values" |
| T1694 Insecure Credentials | same three events | AN2219: "successful authentication to an Industrial Control System (ICS) device or application using credentials that are either documented vendor defaults (T1694.001) or extracted from configuration files/firmware"; AN2203 (network device management interfaces) |
| T0859 Valid Accounts | DS-0005 VPN authentication; DS-0006 4624; DS-0010 AUDIT_EVENTS; DS-0013 M580 connection | AN1857: "ICS-role account authenticating via interactive or remote logon from a workstation not in the approved host inventory"; AN2217 (field device access with an engineering account's credentials) |
| T1078.001 Default Accounts | DS-0006 4624; DS-0012 gateway administrative logins | AN1283: "default account usage such as Guest or Administrator performing interactive or remote logons"; AN1287: "Login activity from default admin credentials ... on routers, firewalls, and switches." |
| T1110 Brute Force | DS-0005 VPN authentication; DS-0007 Control Expert password events; DS-0010 Ignition lockouts; DS-0013 M580 "Connection problem" | AN1275: "High volume of failed logon attempts followed by a successful one"; AN1276: "Multiple authentication failures for valid or invalid users followed by success from same IP/user" |
| T1110.003 Password Spraying | DS-0005 VPN authentication | AN1336: "A high volume of authentication failures using a single password (or small set) across many different user accounts" |
| T1133 External Remote Services | DS-0005 VPN authentication, vendor session start/end | AN1004: "Unusual or unauthorized external remote access attempts (e.g., RDP, VPN, Citrix)" |
| T0823 Graphical User Interface | DS-0004 inbound VNC 5900-5910; DS-0005 VNC/RDP sessions to HMIs | AN1904 (RDP, VNC or vendor console to an HMI from outside the approved subnet); AN2251: "Virtual Network Computing (VNC) or proprietary remote console sessions to embedded Human-Machine Interface (HMI) panels" |
| T0892 Change Credential | DS-0007 Control Expert Password Action ("Firmware Password Modified"); DS-0010 Ignition user/role edits | AN2262: "a password change event for an Industrial Control System (ICS) service or operator account performed by an account not in the authorized credential administration role" |
| T1531 Account Access Removal | DS-0010 Ignition user/role create/edit/delete | AN0334: "Correlated user account modification (reset, disable, deletion) events" |
| T1563 Remote Service Session Hijacking | DS-0006 **new** Security 4778 event; DS-0006 4624 | AN0216: "service session takeovers without corresponding successful logon events"; Microsoft: 4778 "is generated when a user reconnects to an existing Terminal Services session" |

### Windows EWS / HMI host

| Technique | DS-0006 event | MITRE analytic |
| --- | --- | --- |
| T0807 Command-Line Interface | 4688, Sysmon 1 | deprecated - vendor basis (see above) |
| T0853 Scripting | PowerShell 4104 | deprecated - vendor basis (see above) |
| T0840 Network Connection Enumeration | 4688, Sysmon 1 | AN1902: "execution of network enumeration commands (netstat, arp -a, Get-NetTCPConnection)" |
| T0847 Replication Through Removable Media | 4688, Sysmon 1 | AN1866: "USB storage device insertion event ... immediately followed by process execution from the removable drive's path" |
| T1560 Archive Collected Data | Sysmon 1, Sysmon 11 | AN1458: "execution of compression/encryption utilities ... with subsequent creation of large compressed or encrypted files" |
| T0873 Project File Infection; T0873.001 Siemens Project File Format | Sysmon 11 | AN1898: "Sysmon FileCreate events can corroborate writes/overwrites but do not report generic file-open/read activity"; AN2049: "a write to a Siemens project file by a process that is not the Siemens ... TIA Portal or Step7 engineering software" |
| T1491.001 Internal Defacement | Sysmon 11 | AN0229: "creating or altering content files using scripts or unauthorized access" |
| T0851 Rootkit | Sysmon 6 | AN2167: "unexpected kernel driver loads from unexpected paths" |
| T1014 Rootkit | Sysmon 6, Sysmon 7 | AN1061: "Unauthorized or anomalous loading of kernel-mode drivers or DLLs" |
| T1553.002 Code Signing | Sysmon 6 (signature information) | AN0643: "execution of binaries signed with unusual or recently issued certificates ... abnormal publisher metadata" |
| T1561.001 Disk Content Wipe | Sysmon 6 | AN0882: "loading of third-party drivers (e.g., RawDisk) that enable disk overwrite" |
| T0874 Hooking | Sysmon 7 | AN1855: "loading a Dynamic Link Library (DLL) not present in the vendor's signed module baseline" |
| T1499 Endpoint Denial of Service | System 7034/7036 | AN0584: "Excessive resource exhaustion or service crash" |
| T1003.001 LSASS Memory | **new** Sysmon Event ID 10 ProcessAccess | AN1030: "attempts to open a handle with full access (0x1F0FFF) to lsass.exe"; Microsoft: "This enables detection of hacking tools that read the memory contents of processes like Local Security Authority (Lsass.exe)" |

### Historian

| Technique | DS-0011 event | MITRE analytic |
| --- | --- | --- |
| T1565 Data Manipulation; T1565.001 Stored Data Manipulation | PI Audit Database - editing and deleting time-series data | AN0162: "abnormal changes to structured data (e.g., database files, logs, financial records)"; AN0555: "unauthorized creation, deletion, or modification of business-critical stored data such as ... database files" |
| T0836 Modify Parameter | setpoint time series | AN1908: "correlated with subsequent historian tag drift" |

## New events (ICS-DS-0006)

- **Security 4778 - A session was reconnected to a Window Station** (needs
  "Audit Other Logon/Logoff Events"). Source: Microsoft Learn 4778(S) -
  "This event is generated when a user reconnects to an existing Terminal
  Services session, or when a user switches to an existing desktop using Fast
  User Switching." Fields from the same page: Account Name, Logon ID, Session
  Name, Client Name, Client Address. Mapped to T1563.
- **Sysmon Event ID 10 - ProcessAccess.** Source: Sysmon v15.22 - "This
  enables detection of hacking tools that read the memory contents of
  processes like Local Security Authority (Lsass.exe) in order to steal
  credentials for use in Pass-the-Hash attacks." and "it generally should only
  be done so with filters that remove expected accesses." Mapped to T1003.001.

## Partial captures (mapped, with the gap stated)

- **T0835** - DS-0001 sees the write to the output register; the analytic also
  needs "an independent measurement of the actual physical output state", which
  no visibility record supplies (a historian fed through the same controller is
  not independent).
- **T0847** - 4688/Sysmon 1 show execution from a removable drive's path; the
  USB insertion record the analytic pairs it with is in no record.
- **T0873 / T0873.001** - MITRE's collection requirement is Security 4663 with
  object-access auditing and SACLs on project folders; no record lists 4663
  yet. Sysmon 11 only corroborates writes.
- **T0893** - the Windows half of the analytic (AN1881, 4663 on ICS data paths)
  is likewise uncovered; only the ICS-protocol half maps.
- **T1561.001** - Sysmon 6 sees the driver load; raw writes to
  `PhysicalDrive` are not recorded by any listed event (Sysmon Event ID 9 logs
  raw *reads* only, per the Sysmon page).
- **T1491.001** - Sysmon 11 covers defacement of a Windows-hosted HMI. The
  recorded case (CyberAv3ngers on Unitronics HMIs) changed an embedded panel,
  which no visibility record logs.
- **T0812 / T1694 / T1078.001** - the events record the authentication and the
  account; recognising a vendor-default credential needs the vendor's default
  list, which the logs do not carry.
- **T0807 / T0853** - deprecated in ATT&CK; mapped on vendor basis only.

## Left open (10)

| Technique | Used by | Why it stays a blind spot |
| --- | --- | --- |
| T0813 Denial of Control | MAL-0004, MAL-0006, MAL-0008 | AN1918: "No standard detection method currently exists for this technique." |
| T0828 Loss of Productivity and Revenue | MAL-0011, MAL-0012, TA-0010 | AN1889: same words |
| T0829 Loss of View | MAL-0009, MAL-0010, TA-0010 | AN1895: same words |
| T0831 Manipulation of Control | INC-0007, MAL-0004/0006/0007/0008/0009, TA-0001, TA-0010 | AN1880: same words. The commands that cause it are covered under T0855/T0836. |
| T0832 Manipulation of View | MAL-0001, MAL-0007 | AN1917: same words. A historian fed from the manipulated path records what the operator saw, so DS-0011 cannot show it on its own; MITRE's T0835 analytic says an independent check needs "a separately trusted sensor/historian/measurement path". |
| T0837 Loss of Protection | MAL-0005 | AN1907: same words |
| T0880 Loss of Safety | MAL-0005 | AN1911: same words |
| T1587.004 Develop Capabilities: Exploits | INC-0013 | AN2026: "Much of this activity will take place outside the visibility of the target organization" |
| T1588.007 Obtain Capabilities: Artificial Intelligence | INC-0013 | AN1974: same words. No adversary-side data source exists in the repository. |
| T1596.005 Scan Databases | INC-0013 | AN1990: "potentially taking place outside the visibility of the target organization". ICS-DS-0014 shows the owner what the scan databases hold; it does not see who searched them. |

Process data (DS-0011) and the alarm journal (DS-0010) would show the physical
effects of the impact techniques, but neither MITRE nor those records' own
sources say so. Mapping them would be this project's inference, so they are
left open for a decision.

## Follow-ups (not done here)

- Read the T0835 description: if MITRE names forcing, DS-0008 "I/O forces
  enabled, disabled, removed, or modified" maps to T0835 too. It was not read
  because the Firecrawl credit ran out.
- Add Security 4663 (object access on project and ICS data folders) to
  ICS-DS-0006 from Microsoft's page. That closes the gaps in T0873 and T0893.
- Migrate the intel records' T0812 / T0855 / T0857 / T0807 / T0853 ids to the
  current ATT&CK ids.
- Regenerate MAPPINGS.md.
