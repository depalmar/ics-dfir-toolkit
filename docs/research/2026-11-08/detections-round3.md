# Detection backlog, round 3 - research notes (2026-11-08)

Stream: work down the MAPPINGS.md "Gaps" table (techniques that recorded
malware, actors or incidents use, with nothing hunting or detecting them).
New files only: hunts `ICS-HUNT-0013..0017`, packs `ICS-PACK-0005..0006`,
11 Sigma rules in `01-engineering-workstations/`, one Suricata file in
`02-ot-network/` (sids 9000015-9000018), and these notes. No existing record,
README, registry or MAPPINGS.md was edited.

Method: Firecrawl scrape (markdown, `onlyMainContent`; the CERT Polska PDF
with the PDF parser) and Microsoft Learn fetch. Quotes in hunts are copied
from the rendered page text (`read: direct`) or reused verbatim from platform
and data-source records that read the same URL directly. A Microsoft Learn
search excerpt was used only to find pages; the reboot page quoted in
ICS-HUNT-0013 was fetched in full. Every `accessed` date is 2026-11-08.

Gap count (`coverage()` in `artifacts/scripts/mappings.py`): **40 before,
16 after.** MAPPINGS.md was not regenerated; `test_mappings_file_is_current`
fails until it is.

## What each new detection closes

| File or id | Closes | Primary basis | Evidence it reads |
| --- | --- | --- | --- |
| ICS-HUNT-0013 | T0816, T0814, T0813, T0881 | CISA AA22-103A ("Investigate symptoms of a denial of service ..."; "packet of death"); CERT Polska (RTU damage caused loss of communication with the DSO; T0816 in its ATT&CK table); Dragos EKANS (historian check for endpoints that stop reporting together); AVEVA PI I/O Timeout and Stale; Microsoft reboot event IDs; ICSA-15-202-01; Siemens S7 mode-transition causes | Historian, alarm journal, controller logs (DS-0008/0009/0013), relay/RTU security logs, Windows System log, Zeek/flow |
| ICS-HUNT-0014 | T0855 (also T0831) | Mandiant 2023 Sandworm/MicroSCADA (scilc.exe, mapped by Mandiant to T0855); CISA TA17-163A (Industroyer breaker toggling); Ignition audit; OPC 10000-3 audit events; Mandiant INCONTROLLER OPC UA audit guidance | Commanded states in historian/SCADA event list vs operator, OPC UA, controller and protection records |
| ICS-HUNT-0015 | T0880, T0828 | Mandiant TRITON (failed-safe trip; MP diagnostic failure); FBI PIN 20220324-001 (key-switch alarm); Tricon SOE; Dragos EKANS (manual-mode cost); CISA AA21-131A (Colonial precautionary OT disconnect) | SIS trips and SOE, alarm history, historian, EWS logs |
| ICS-HUNT-0016 | T0812, T1694 | CERT Polska (RTU500 "Default" account; Relion built-in FTP account; HMI default local-admin password); AA26-231A (T1694 "Insecure Credentials"); AA22-103A (change defaults; CODESYS brute force against defaults); AA24-038A (default OT vendor credentials); AA25-343A | Authentication records on HMIs, relays, RTUs, controllers, OPC UA, PI, gateways |
| ICS-HUNT-0017 | T1003.001, T0866, T1563, T1560, T1133 | AA24-038A (comsvcs MiniDump; PuTTY stored sessions for OT; renamed rar.exe; VPN sessions); Microsoft 2023 Volt Typhoon (password-protected archives; sign-ins from unusual IPs); AA22-103A (ASRock driver) | Windows process/driver events, EDR, VPN and remote-access logs |
| ICS-PACK-0005 | T0809, T1561.001, T1053.005 (also T0881, T0816, T0853, T0812, T1490) | CERT Polska, ESET DynoWiper, Talos PathWiper, Microsoft GigaWiper, Dragos EKANS, Mandiant 2023 (TANKTRAP), ESET Industroyer2, MITRE T0809, Microsoft Sysmon/4698/reboot pages | Sysmon and Security/System logs; disk images; Suricata on FTP; RTU500 event log |
| ICS-PACK-0006 | T0821, T0857 (also T0834, T0849, T0843, T0889) | AA26-231A (firmware vs gold copy; ladder logic online/offline); AA24-038A (logic integrity checks vs known-good); AA22-103A (hash firmware and configuration); CERT Polska (RTU560 firmware 13.5.3.0 vs fleet); Mandiant TRITON (appended program); Rockwell 1756-PM015; Schneider EIO0000001999 | Logic comparison (`logic_compare`), AuditValue, firmware inventory, controller logs, Sysmon image loads |
| `ews_hmi_shadow_copy_or_backup_deleted.yml` | T0809 (T1490, T1485) | MITRE T0809 ("destroy data backups"; SDelete); CERT Polska ("vssadmin delete shadows"); Mandiant (TANKTRAP with SDELETE); Microsoft vssadmin/wbadmin docs | Sysmon 1 / 4688 |
| `ews_hmi_file_shredding_blocked.yml` | T0809 | Sysmon Event ID 28 (Microsoft) | Sysmon 28 |
| `ews_hmi_scheduled_task_created.yml` | T1053.005 | Microsoft 4698 ("monitoring all scheduled task creation events, especially on critical computers"); ESET, Mandiant, CERT Polska, Microsoft GigaWiper | Security 4698 |
| `ews_hmi_service_terminated_unexpectedly.yml` | T0881 | Microsoft 7034/7036 troubleshooting text; Dragos EKANS kill list; ESET Industroyer2; Microsoft GigaWiper | System 7034 |
| `ews_hmi_service_or_process_stop_command.yml` | T0881 | Same families; built-in-tool route only | Sysmon 1 / 4688 |
| `ews_hmi_restart_or_unexpected_shutdown.yml` | T0816 | Microsoft 1074/41/6008/1001; CERT Polska (DynoWiper ExitWindowsEx); Microsoft GigaWiper (zero-delay reboot, BSOD) | System log |
| `ews_hmi_lsass_dump_via_comsvcs_minidump.yml` | T1003.001 | AA24-038A | Sysmon 1 / 4688 |
| `ews_hmi_windows_script_host_execution.yml` | T0853 | Mandiant (lun.vbs; T0853); Talos (WScript uacinstall.vbs) | Sysmon 1 / 4688 |
| `scada_microscada_scilc_program_executed.yml` | T0807, T0871, T0855 | Mandiant (command fragment, -do flag, ATT&CK mapping, monitoring advice) | Sysmon 1 / 4688 |
| `ews_hmi_asrock_vulnerable_driver_loaded.yml` | T0866 | AA22-103A | Sysmon 6 |
| `ews_snap7_library_loaded.yml` | T0834, T0849 | AA26-231A (snap7.dll; T0834 and T0849 mapping; "Monitor for Python processes with snap7.dll library imports") | Sysmon 7 |
| `relay_and_rtu_service_sessions.rules` (sids 9000015-9000018) | via HUNT-0013, HUNT-0016, PACK-0005 | ICSA-15-202-01 ("Monitor traffic to affected devices on Port 50000/UDP with an intrusion detection system (IDS)"); CERT Polska (Relion FTP deletion) | Suricata on passive capture, port level |

## Sources read directly this round, and what they supplied

### Government

- **CISA AA22-103A** (APT Cyber Tools Targeting ICS/SCADA Devices) - DoS
  symptoms to investigate; "packet of death"; ASRock `AsrDrv103.sys` and the
  driver-monitoring recommendation; changing default passwords "to give
  defender monitoring systems opportunities to detect common attacks";
  CODESYS brute force "against defaults or a dictionary word list"; known-good
  backups with "hashing and integrity checks on firmware and controller
  configuration files". Its tables map the Schneider tool to T0857, T0814,
  T0809, T0816, T0855 and the OMRON tool to T0821, T0881.
- **CISA AA26-231A** (Siemens S7) - snap7 tooling, T0834/T0849/T0821/T1694
  mapping (ATT&CK v19), "Snap7.dll library usage outside approved engineering
  workstations", "Monitor for Python processes with snap7.dll library imports
  on engineering workstations", "Verify current firmware versions ... against
  backup gold copy", "Evaluate for ladder logic changes in online/offline
  modes".
- **CISA AA24-038A** (Volt Typhoon) - comsvcs `MiniDump` of LSASS with an
  outdated DLL in a non-standard folder; PuTTY stored-session enumeration and
  OT profiles (T1563); zipped files and renamed `rar.exe` (T1560); VPN
  sessions (T1133); "default OT vendor credentials"; "Implement integrity
  checks of controller process logic against a known good baseline."
- **CISA ICSA-15-202-01** (SIPROTEC) - UDP 50000 DoS needing a manual
  reboot; "Monitor traffic to affected devices on Port 50000/UDP with an
  intrusion detection system (IDS)."
- **CERT Polska Energy Sector Incident Report** (PDF, 46 pages, and the blog
  post) - Relion 650 FTP with a built-in default account deleting files so
  the IED shut down and would not restart; Mikronika HMIs with a default
  local-administrator password reached over RDP, DynoWiper as C:\Source.exe;
  HMIs with different passwords survived failed guessing; RTU damage as the
  cause of lost DSO communication; `vssadmin delete shadows`; the GPO
  ScheduledTask running as SYSTEM that deletes itself; DynoWiper version A's
  ExitWindowsEx; its own ATT&CK for ICS table (T0809, T0816, T0857, T0812).
- **CISA AA21-131A** (Colonial Pipeline), **CISA TA17-163A**, **FBI PIN
  20220324-001** - reused from the incident, malware and platform records
  that read them directly.

### Vendor and researcher

- **Microsoft Learn** - 4698 (fields, subcategory, monitoring
  recommendations); unexpected-reboot event IDs 1074 (User32), 41
  (Kernel-Power), 6008 (EventLog), 1001 (WER-SystemErrorReporting), with the
  normal/unexpected sequences; Event ID 41 article (1074 "is logged when an
  application is responsible for the system shutdown or restart"; shutdown.exe
  writes 1074); Sysmon v15.22 (Event IDs 6, 7 - disabled by default, 9, 10,
  23, 26, 28 FileBlockShredding); vssadmin delete shadows, wbadmin delete
  catalog / systemstatebackup (search excerpts of the command reference);
  SCM 7034 and 7036 message texts and the "terminated by using Task Manager"
  example, fetched in full from the Always On failover troubleshooting
  article; the 7040 text was seen only in a search excerpt and is not used in
  any rule.
- **Microsoft Threat Intelligence** - GigaWiper (raw-disk wipe and
  IOCTL_DISK_CREATE_DISK; zero-delay reboot; BSOD command; "OneDrive Update"
  task; event-log clearing; .candy rename) and Volt Typhoon 2023
  (password-protected archives; unusual-IP sign-ins). The GigaWiper commands
  that disable recovery and take ownership of boot files are shown only as
  images, so no rule was written from them.
- **Mandiant** - Sandworm 2022 MicroSCADA attack (wscript lun.vbs, cmd n.bat,
  `C:\sc\prog\exec\scilc.exe -do pack\scil\s1.txt`, TANKTRAP scheduled tasks,
  ATT&CK mapping T0847/T0807/T0871/T0853/T0872/T0809/T0855/T0831,
  monitoring advice). Mandiant's own Sigma and YARA rules on that page carry
  no licence statement; they were not copied (the scilc rule is written from
  the prose).
- **Cisco Talos** - PathWiper loader command line and the NTFS structures it
  overwrites.
- **Dragos** - EKANS (WMI shadow-copy deletion; kill list in Appendix A;
  historian check; loss-of-view and manual-mode cost). The URL in
  ICS-MAL-0012 (`/blog/responding-to-solarwinds-compromise-in-industrial-environments/`)
  is odd but does serve the EKANS article; the older
  `/blog/industry-news/ekans-ransomware-and-ics-operations/` returns 404.
- **AVEVA** - PI "Find and view stale and bad points" (I/O Timeout, Stale).
- **MITRE ATT&CK** - T0809 page (backups clause; SDelete and KillDisk as
  examples; C0063 Poland procedure).

## Gaps deliberately left open (16) and why

| Technique | Used by | Why no detection |
| --- | --- | --- |
| T0801 Monitor Process State | ICS-MAL-0009 (FrostyGoop) | Only visible as protocol reads; rules on function codes are out of scope. ICS-HUNT-0002 already covers the new talker; its record could add T0801 if the owner agrees. |
| T0819 Exploit Public-Facing Application | ICS-MAL-0003 | BlackEnergy's HMI exploits are historical CVEs; no host or log evidence was read this round. Exposure is ICS-HUNT-0012. |
| T0835, T0877 (I/O image), T0851, T0874, T1014, T1553.002, T0873.001 | ICS-MAL-0001 (Stuxnet) | All controller-internal or 2010-era EWS artefacts. The only host lead in the repository (s7otbxsx.dll in ICS-0010) is rated low/unverified, and no Stuxnet primary source was read. A logic comparison from a clean workstation (ICS-PACK-0006) is the right test, but tagging it with these techniques would be inference beyond the sources. |
| T0840 Network Connection Enumeration | ICS-MAL-0002 | CERT Polska saw netstat run through Impacket on a Poland HMI, but a netstat rule on its own is noise and the parent-process pattern for Impacket was not read from a primary source. |
| T0847 Replication Through Removable Media | ICS-TA-0001 | Mandiant's ISO-as-CD-ROM vector; the Windows events for an optical or virtual-disk mount were not read. ICS-HUNT-0014's script-host rule catches the next step. |
| T0861 Point & Tag Identification | ICS-MAL-0002, ICS-MAL-0007 | OPC browse and read are not among the audit events documented in ICS-0015; OPC DA (DCOM) enumeration has no documented log. |
| T1587.004, T1588.007, T1596.005, T1595.002 | ICS-INC-0013, ICS-TA-0010 | Adversary capability development and internet-wide scanning happen outside the owner's data. ICS-HUNT-0012 covers what the owner can see (its own exposure). |

## Rejected or deferred this round

- **Protocol command signatures** (IEC-104 ASDU types, Modbus writes, S7
  PUT/GET, TriStation program transfer, MMS operate): out of scope; T0855 is
  handled from process data and host logs instead.
- **TriStation, FINS and CODESYS port rules**: TriStation's UDP 1502 is
  low/unverified in ICS-PROTO-0016; a session to these ports would close no
  gap that HUNT-0002 and the controller-side detections do not already cover.
- **GigaWiper recovery-disabling and boot-file ownership commands**: shown
  only in images on Microsoft's page; no strings were guessed.
- **EKANS kill-list rule on process termination**: Sysmon Event ID 5 does not
  say who ended a process, so a list match would fire on every legitimate
  stop; the 7034 rule and the historian check in ICS-HUNT-0013 replace it.
- **System 7040 (start type changed to disabled)**: field layout not read
  from Microsoft; left as a hunt step.
- **Renamed-archiver rule** (OriginalFileName vs Image): the original file
  names of rar.exe and 7-Zip builds were not read; left as a hunt step in
  ICS-HUNT-0017.
- **Sysmon 10 LSASS access rule**: the access masks to match were not read
  from Microsoft; the comsvcs rule rests on AA24-038A's own description.
- **Relion 670 event-ID log_regex** (1680, 1687, 1710): the forwarded
  syslog/CEF text format was not read; named as hunt steps instead.
- **Flood or scan thresholds on controller ports for T0814**: the recorded
  DoS cases are single crafted packets (SIPROTEC, Schneider "packet of
  death"), not floods, so a flood rule would not match the evidence.

## Tool verification

- `sigma convert -t lucene --without-pipeline` (sigma-cli in the scratch
  virtualenv) succeeds for all 11 new Sigma files.
- `suricata -T -v -S 02-ot-network/relay_and_rtu_service_sessions.rules -c
  /etc/suricata/suricata.yaml`: 4 rules loaded, 0 failed, 0 inspect the
  application layer; only default variables (HOME_NET, EXTERNAL_NET,
  FTP_PORTS).
- `python3 artifacts/scripts/validate.py`: OK, 0 warnings (hunts=17,
  packs=6).
- `python3 -m pytest -q tests/`: 7 passed, 1 failed -
  `test_mappings_file_is_current`, expected until MAPPINGS.md is regenerated.
- `check_quotes.py --only` on each new hunt: every source "could not be
  fetched" (the proxy refuses the checker's plain fetches, as in round 1).
  Quotes from the CERT Polska PDF, AA24-038A and the AVEVA page were instead
  matched mechanically with the checker's own `norm()` against the saved
  Firecrawl text (14 of 14 matched); the rest were checked by hand against
  the scraped text.

## Suggested follow-ups for record owners (not edited by this stream)

- **docs/ID_REGISTRY.md**: record ICS-HUNT-0013..0017 and
  ICS-PACK-0005..0006 (next free ICS-HUNT-0018, ICS-PACK-0007) and sids
  9000015-9000018 (next free 9000019).
- **01-engineering-workstations/README.md and 02-ot-network/README.md**: add
  rows for the 11 Sigma files and the new Suricata file; note that Sysmon
  Event IDs 6, 7 and 28 need configuration.
- **Malware `detections`** (each currently `[]` with a `gap`):
  ICS-MAL-0013 DynoWiper -> `destruct-file-overwrite-or-rename-burst`,
  `destruct-host-restart-or-crash`, `destruct-scheduled-task-on-ews-hmi`;
  ICS-MAL-0014 LazyWiper -> `destruct-file-overwrite-or-rename-burst`;
  ICS-MAL-0015 PathWiper -> `destruct-disk-structures-destroyed`,
  `destruct-script-host-on-ews-hmi`;
  ICS-MAL-0016 GigaWiper -> `destruct-disk-structures-destroyed`,
  `destruct-host-restart-or-crash`, `destruct-scheduled-task-on-ews-hmi`;
  ICS-MAL-0012 EKANS -> `destruct-ot-service-terminated`,
  `destruct-file-overwrite-or-rename-burst`;
  ICS-MAL-0006 Industroyer2 -> `destruct-scheduled-task-on-ews-hmi`,
  `destruct-ot-service-terminated`;
  ICS-MAL-0004 Industroyer -> `02-ot-network/relay_and_rtu_service_sessions.rules`;
  ICS-MAL-0007 INCONTROLLER -> `01-engineering-workstations/ews_hmi_asrock_vulnerable_driver_loaded.yml`,
  `integrity-running-logic-differs-from-known-good`;
  ICS-MAL-0005 TRITON -> `integrity-sis-execution-table-extra-program`.
- **Incident `hunts` / `packs`**: ICS-INC-0008 -> ICS-HUNT-0013, -0016;
  ICS-PACK-0005, -0006. ICS-INC-0002 -> ICS-HUNT-0013, -0014; ICS-PACK-0005.
  ICS-INC-0004 -> ICS-HUNT-0014; ICS-PACK-0005. ICS-INC-0003 -> ICS-HUNT-0015;
  ICS-PACK-0006. ICS-INC-0013 -> ICS-HUNT-0016; ICS-PACK-0006. ICS-INC-0006 ->
  ICS-HUNT-0014. ICS-INC-0007 -> ICS-HUNT-0016. ICS-INC-0011 -> ICS-HUNT-0015.
- **Actor `packs`**: ICS-TA-0001, -0002, -0016, -0017 -> ICS-PACK-0005;
  ICS-TA-0004, -0018, -0005 -> ICS-PACK-0006.
- **ICS-INC-0008 chain**: CERT Polska's own ATT&CK for ICS table maps T0809,
  T0816, T0857 and T0812 for the renewable-energy sites; the owner may want
  them on the chain steps.
- **ICS-DS-0006 events**: 4698, System 1074/41/6008/1001, SCM 7034, and Sysmon
  6, 7 and 28 are now read from Microsoft and could be added with their ATT&CK
  ids, which would shrink the "Blind spots" list.
