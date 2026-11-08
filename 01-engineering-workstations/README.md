# 01-engineering-workstations/ - Windows engineering workstations and HMI/SCADA hosts

Platforms: `ICS-0010` (engineering workstation), `ICS-0011` (HMI / SCADA server).
Data source: `ICS-DS-0006` (Windows Security, Sysmon and PowerShell logs).
Detection packs: `ICS-PACK-0002`, `ICS-PACK-0004`. Hunts: `ICS-HUNT-0002`,
`ICS-HUNT-0004`, `ICS-HUNT-0008`, `ICS-HUNT-0011`.

## Rules

| File | Event | Detects | Rests on |
|---|---|---|---|
| `ews_hmi_rdp_logon_from_public_address.yml` | Security 4624, LogonType 10 | Remote desktop logon from a non-private address | AA26-097A device control list; AA25-343A |
| `hmi_inbound_vnc_from_public_address.yml` | Sysmon 3, inbound 5900-5910 | VNC connection to the host from a non-private address | AA25-343A |
| `ews_hmi_remote_access_tool_started.yml` | Sysmon 1 / 4688 | AnyDesk, ScreenConnect, UltraVNC or a TeamViewer incoming session | AA26-097A, AA25-343A, ASD/CISA logging guidance; tool metadata from SigmaHQ |
| `ews_script_or_user_path_process_to_controller_port.yml` | Sysmon 3, outbound | Script interpreter or user-writable binary connecting to 102, 502, 2222, 2404, 4840, 20000, 20256 or 44818 | ASD/CISA logging guidance; ICS-0010 |
| `ews_project_file_archived_or_copied_by_cli.yml` | Sysmon 1 / 4688 | Archiver, copy tool or curl run on .ACD, TIA .apNN/.zapNN, Control Expert .STU/.STA/.ZEF/.XEF or VisiLogic .vlp files | AA26-097A; Dragos 2026 YIR; Siemens, Schneider and Unitronics documentation |
| `ews_hmi_local_administrators_member_added.yml` | Security 4732 | Member added to BUILTIN\Administrators (S-1-5-32-544) | Microsoft 4732 guidance; ASD/CISA logging guidance |
| `ews_hmi_security_log_cleared.yml` | Security 1102 | Security audit log cleared | Microsoft 1102 guidance; ASD/CISA logging guidance |
| `ews_hmi_event_log_logon_enumeration.yml` | Sysmon 1 / 4688 | wevtutil / Get-EventLog / Get-WinEvent against Security or 4624 | ASD/CISA logging guidance (Volt Typhoon case study) |

## Deploying

- **Scope to the EWS and HMI host group.** Sigma has no notion of which
  Windows host is an engineering workstation; apply these rules only to the
  log sources of EWS, HMI, SCADA and OT jump hosts. Dragos reports OT
  incidents misclassified as IT-only because these hosts run Windows; route
  hits to whoever owns the OT response.
- **Prerequisites are off by default.** Security 4688 records no command line
  unless "Include command line in process creation events" is enabled, and
  Sysmon's network connection event (ID 3) is disabled by default. The two
  Sysmon network rules need a configuration that includes the controller and
  VNC ports. A rule that cannot see its event says nothing, which is not the
  same as passing (ICS-DS-0006).
- **Field names** follow Sysmon and the Sigma taxonomy (`Image`,
  `CommandLine`, `Initiated`, `SourceIp`, `DestinationPort`) and Microsoft's
  event XML (`LogonType`, `IpAddress`, `TargetSid`, `SubjectUserName`).
  Security 4688 uses different names (`NewProcessName`, `CommandLine`); map
  them in your pipeline.
- **"Public address"** means anything outside 127.0.0.0/8, 10.0.0.0/8,
  172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 (carrier-grade
  NAT, common behind cellular gateways), ::1, fe80::/10 and fc00::/7. Sites
  that number OT in public space must add their ranges.
- Several rules have general SigmaHQ counterparts (named in each rule's
  description). They are kept here so the OT host group gets them with an
  OT-specific level and response, not because SigmaHQ's are wrong.

## Not here, and why

- **Engineering software started by an unusual parent.** No vendor document
  read this round gives the executable names of Studio 5000 Logix Designer or
  EcoStruxure Control Expert; the only TIA Portal name found
  (`Siemens.Automation.Portal.exe`) rests on one researcher's testing and is
  rated low in ICS-0010. ICS-HUNT-0002 covers the behaviour from the network
  side until names are confirmed.
- **Project files written to removable media.** Sysmon FileCreate does not
  say whether a drive is removable; Windows removable-storage auditing was not
  read. ICS-HUNT-0008 lists it as a hunt step.
- **What the engineering software sent to the controller.** Host logs show
  that a tool ran, not what it downloaded or whether the controller accepted
  it. AA26-097A's actors used their own copies of the vendor software on
  leased infrastructure, which leaves nothing on the owner's EWS at all.
