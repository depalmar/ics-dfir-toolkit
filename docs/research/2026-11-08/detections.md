# First detections - research notes (2026-11-08)

Stream: hunts (`artifacts/hunts/ICS-HUNT-0001..0012`), detection packs
(`artifacts/packs/ICS-PACK-0001..0004`), Sigma rules for Windows EWS/HMI
hosts (`01-engineering-workstations/`, 8 files) and remote-access logs
(`03-remote-access/`, 3 files), and port/flow-level Suricata rules
(`02-ot-network/`, 4 files, sids 9000001-9000014).

Method: Firecrawl scrape (markdown, `onlyMainContent`; PDFs with the PDF
parser) and Microsoft Learn fetch; GitHub raw files fetched with curl
through the session proxy. A quote copied from a rendered page, PDF text or
raw file is `read: direct`; a quote from a search-result excerpt is
`read: summariser`. Every `accessed` date is 2026-11-08. No record in this
stream rests on a summariser read. Quotes from the CISA advisories keep the
backticks the rendered markdown puts around port numbers, as the round-1
data-source records do.

## What each detection rests on

| Detection | Primary basis | Data source |
| --- | --- | --- |
| ICS-HUNT-0001, sids 9000001-9000006, PACK-0001 `aa26097a-inbound-plc-port-session` | AA26-097A ports 44818, 2222, 102, 502 and "foreign hosting providers"; NCSC "remove inbound port exposure" | ICS-DS-0001/0002/0003/0004 |
| sids 9000007-9000009 (20000, 2404, 4840) | Parser default ports recorded in ICS-DS-0001 (Zeek DNP3, spicy-iec104, ICSNPP OPC UA); Suricata's default `DNP3_PORTS: 20000` | ICS-DS-0002 |
| ICS-HUNT-0002 | AA26-097A device control list; AA23-335A host-based allowlists; ASD/CISA "unusual communication between components" and netflow anomaly | ICS-DS-0001/0003/0006 |
| ICS-HUNT-0003, PACK-0001 controller-log detections | NCSC "verify maintenance actions are legitimate"; AA26-097A "functions ... that change an asset's operating mode or modify programs"; ASD/CISA "unauthorised updates or changes"; event names from ICS-DS-0007/0008/0013 (vendor manuals read in round 1) | ICS-DS-0007/0008/0009/0013 |
| ICS-HUNT-0004, sid 9000010, PACK-0002 network and Windows detections | AA25-343A VNC 5900/5901-5910, VPS brute force, allowlist and working hours; NCSC break-glass; ASD/CISA vendor-access anomaly | ICS-DS-0001/0004/0005/0006 |
| ICS-HUNT-0005, PACK-0002 HMI detections | AA25-343A Alarm Suppression, Change Credential, setpoint changes, "Review configurations for setpoint ranges"; Ignition table and eventtype values from ICS-DS-0010 | ICS-DS-0010/0011 |
| ICS-HUNT-0006, PACK-0001 `aa26097a-excursion-without-alarm` | AA26-097A "disabled critical shutdown and alarm logic ... without notifying operators"; ASD/CISA on historians. Comparison method is the toolkit's (medium) | ICS-DS-0010/0011 |
| ICS-HUNT-0007, 03 Dropbear rules, sid 9000011, PACK-0001 modem detections | AA26-097A Dropbear on modems, "Enable logs for connected modems"; Dropbear source strings; Dragos on VOLTZITE and Sierra Wireless gateways | ICS-DS-0012 |
| ICS-HUNT-0008, `ews_project_file_archived_or_copied_by_cli.yml`, PACK-0004 | AA26-097A project-file exfiltration and the .ACD footnote; Dragos on AZURITE and VOLTZITE; Siemens, Schneider and Unitronics extension documentation | ICS-DS-0006/0007 |
| ICS-HUNT-0009, sid 9000014 | NCSC data-flow monitoring; AA25-343A outbound monitoring; AA23-335A protocol/port mismatch | ICS-DS-0003/0004 |
| ICS-HUNT-0010, sids 9000012-9000013, PACK-0003 | AA23-335A (20256, 20257, renamed devices, no-I/O logic, not burned, splash page) | ICS-DS-0001/0004/0014 |
| ICS-HUNT-0011, 4732 / 1102 / log-enumeration rules, PACK-0004 | ASD/CISA Volt Typhoon case study and anomaly list; Microsoft 4732 and 1102 guidance; Dragos on EWS/HMI misclassification | ICS-DS-0006 |
| ICS-HUNT-0012 | AA25-343A attack-surface management and "assume ... compromised"; CISA Primary Mitigations; AA26-097A cellular modems | ICS-DS-0014 |
| `ews_hmi_rdp_logon_from_public_address.yml` | Microsoft 4624 (LogonType 10, IpAddress); AA26-097A device control list | ICS-DS-0006 |
| `hmi_inbound_vnc_from_public_address.yml` | AA25-343A; Sysmon Event ID 3 (disabled by default) | ICS-DS-0006 |
| `ews_hmi_remote_access_tool_started.yml` | AA26-097A and AA25-343A on RDP/VNC; ASD/CISA vendor-access anomaly; tool metadata from SigmaHQ rules | ICS-DS-0006 |
| `ews_script_or_user_path_process_to_controller_port.yml` | ASD/CISA "execution of scripts that are not part of regular operations" and "unusual or suspicious path"; ICS-0010 | ICS-DS-0006 |
| `jump_host_break_glass_account_logon.yml` | NCSC break-glass principle; Microsoft 4624 | ICS-DS-0005/0006 |

## Sources read directly, with the quotes records rest on

### Government (high for what the authority recommends or reports)

- **CISA AA26-097A** (April 7, 2026; updated July 22, 2026) -
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a
  - Key actions: "Query available logs for the provided indicators of
    compromise (IOCs) and check available logs for suspicious traffic on the
    ports associated with OT devices, including `44818`, `2222`, `102`, and
    `502`, especially traffic originating from foreign hosting providers."
  - Initial access (updated July 22): "Inbound malicious traffic has been
    observed targeting PLC devices on the following ports: `44818`, `2222`,
    `102`, and `502`, as well as targeting modems on port `22`." Targets:
    CompactLogix and Micro850, BMX P34/Modicon M340, S7-1200.
  - C2: "In one reported instance, the actors utilized Dropbear Secure Shell
    (SSH) software on victim modems to enable them to gain remote access
    through port `22`".
  - Exfiltration (new July 22): configuration software "on leased,
    third-party hosted infrastructure to exfiltrate device project files from
    PLC devices to threat-actor-controlled infrastructure". Footnote: "On
    Rockwell Automation devices, it is referred to as an .ACD file."
  - Impact: "modification and deletion of project file logic, to include
    Add-On Instructions (AOIs) and data manipulation on HMI and SCADA
    displays"; "the changes disabled critical shutdown and alarm logic";
    (new July 22) a malicious project that "added logic that overrode
    specific instruction sets responsible for maintaining safe operating
    parameters".
  - Mitigations used: device control list ("When possible, implement a
    device control list for workstations sending messages or connecting to
    OT components." / "Use the device control list to monitor for logon
    activity for unexpected or unusual access to devices from the
    internet."); "Monitor asset management systems for device configuration
    changes"; "Functions of industrial control systems management protocols
    that change an asset’s operating mode or modify programs."; "Enable logs
    for connected modems ..."; "Review logs and configurations on all
    connected devices, including modems, HMIs, and workstations ..."; (new
    July 22) "check the AOIs for any anomalous modifications"; "Block access
    from unauthorized or threat actor-controlled IP addresses, such as those
    associated with hosting providers."
  - IOC disclaimer: "The authoring agencies recommend organizations
    investigate or vet these IP addresses prior to taking action, such as
    blocking." The addresses themselves are ICS-IOC-0001 (another stream,
    parsed from CISA's STIX); no address is copied into any rule or hunt.
- **CISA AA25-343A** (pro-Russia hacktivists, December 2025) -
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-343a
  - "Threat actors typically search for these services on the default port
    `5900` or other nearby ports (`5901-5910`)."
  - "abuse popular internet-scraping tools, such as `Nmap` or `OPENVAS` ...
    and use brute force password spraying tools".
  - Alarm Suppression: "Threat actors use HMI interfaces to clear alarms
    caused by their activity and alarms already present on the system at the
    time of their intrusion." Change Credential: "Threat actors change the
    usernames and passwords of HMI devices in operator lockout attempts".
  - "Review configurations for setpoint ranges or tag values to stay within
    safe ranges and establish alerting for deviations."
  - "The allowlist can be refined to operator working hours ...".
  - "Regularly audit firewall rulesets and monitor outbound traffic patterns
    for anomalies ... such as beaconing or unexpected protocol usage."
  - "If organizations find exposed systems with weak or default passwords,
    they should assume threat actors compromised the system".
  - "they regularly make false or exaggerated claims".
  - Note: AA25-343A maps default credentials to T0812 (ATT&CK v18). The
    current ICS matrix page lists Default Credentials as T1694.001. No
    record in this stream uses either id.
- **CISA AA23-335A** (revised December 18, 2024) -
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a
  - Default port 20256; port moved "from `20256` to `20257`"; devices
    renamed; logic "contained no inputs or outputs"; "did not burn their
    ladder logic file to the device"; upload/download disabled; software
    version set older; splash page; "These devices either had a default
    password in place or no password".
  - Monitoring: "Use host-based allowlists ..."; "Use this to monitor for
    logon activity for unexpected or unusual access to devices from the
    internet."; "Unexpected protocols connected to ports that are mismatched
    with the protocols that would normally connect to these ports."
- **Primary Mitigations to Reduce Cyber Threats to OT** (CISA, FBI, EPA,
  DOE, May 6, 2025) -
  https://www.cisa.gov/resources-tools/resources/primary-mitigations-reduce-cyber-threats-operational-technology
  - "Critical infrastructure entities should identify their public-facing
    assets and remove unintentional exposure."
- **Secure connectivity principles for OT** (NCSC-UK with CISA, FBI, ASD's
  ACSC, Cyber Centre, BSI, NCSC-NL, NCSC-NZ), re-read directly as a PDF -
  https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-secure-connectivity-for-operational-technology.pdf
  - "All connections with the OT environment should be initiated as
    outbound connections from within the OT environment."
  - Unauthorised activity: "business processes should verify maintenance
    actions are legitimate to prevent attackers from exploiting this system
    to hide malicious activities."
  - Break-glass: "any attempt to use a break-glass account triggers the
    highest criticality alarm within your Security Operations Centre (SOC)."
  - "Continuous monitoring of data flows within and between network
    segments is crucial ...".
- **Best practices for event logging and threat detection** (ASD's ACSC
  with CISA, FBI, NSA and partners, August 2024), re-read directly as a PDF -
  https://www.cyber.gov.au/sites/default/files/2024-08/best-practices-for-event-logging-and-threat-detection.pdf
  - OT anomalies: "unexpected use of engineering and configuration tools";
    "abnormal use of vendor or third-party accesses, maintenance methods, or
    remote monitoring"; "unauthorised updates or changes to operating
    systems, software, firmware, configurations, or databases"; "unexpected
    communication between the control system and external network or unusual
    communication between components that do not usually communicate";
    "execution of scripts that are not part of regular operations".
  - General anomalies: "netflow data indicating one device talking to other
    internal devices it normally does not connect to"; "the creation of user
    accounts, or disabled accounts being re-enabled, especially accounts with
    administrative privileges"; "unexpected clearing of logs"; "downloading
    or exporting a large volume of data"; "an execution of the process from
    an unusual or suspicious path".
  - Volt Typhoon case study: "enumerate logs to search for successful logons
    using wevtutil.exe and the command Get-EventLog Security [T1654]".
  - Historians "can provide an additional source of event log data for OT
    networks."

### Vendor

- **Microsoft Learn**: 4624 (XML field names `LogonType`, `IpAddress`,
  `TargetUserName`; type 10 "A user logged on to this computer remotely using
  Terminal Services or Remote Desktop."); 4732 (fields `TargetSid`,
  `SubjectUserName`; "Examples of critical local or domain groups are
  built-in local administrators group ..."); 1102 (provider
  Microsoft-Windows-Eventlog; "Typically you should not see this event.");
  Sysmon v15.22 (Event ID 3 "is disabled by default"; Event ID 11 FileCreate
  "logged when a file is created or overwritten").
- **Microsoft Learn search excerpt** (summariser, notes only): S-1-5-32-544
  is the built-in Administrators group (Security identifiers page). Used for
  the 4732 rule's SID; SigmaHQ's rule uses the same value.
- **Siemens TIA Portal V20 help**, Working with project archives -
  https://docs.tia.siemens.cloud/r/en-us/v20/editing-projects/archiving-and-retrieving-projects/working-with-project-archives
  - "Project archives have the file extension ".zap[version number of the
    TIA Portal]"."; "Projects of the TIA Portal V20 have the extension
    ".ap20". Older projects of the TIA Portal have the extension ".ap[version
    number]"."; also ".als20" for Multiuser Engineering (not used in the
    rule). This is the first vendor source for the .apNN extension, which
    ICS-0010 had only from NVISO.
- **Schneider Electric FAQ000259996** -
  https://www.se.com/us/en/faqs/FAQ000259996/
  - "EcoStruxure Control Expert has four formats .STU, .STA, .ZEF, and
    .XEF."; .STA "is used to transfer projects to networks (local or
    Internet)."
- **Unitronics VisiLogic Knowledgebase**, Updating Project Versions -
  "This backup file does not have the .vlp (VisiLogic) file extension."
- **Dropbear source** (mkj/dropbear master, raw files under `src/`):
  `svr-authpasswd.c` - "Password auth succeeded for '%s' from %s", "Bad
  password attempt for '%s' from %s"; `svr-authpubkey.c` - "Pubkey auth
  succeeded for '%s' with %s key %s from %s", "Pubkey auth bad signature for
  '%s' with key %s from %s"; `svr-auth.c` - "Auth succeeded with blank
  password for '%s' from %s", "Login attempt for nonexistent user from %s";
  `svr-main.c` - "Child connection from %s:%s". Recorded as `kind: vendor`
  (the software's own source).
- **Suricata 7.0.3 documentation**, Thresholding Keywords -
  https://docs.suricata.io/en/suricata-7.0.3/rules/thresholding.html -
  "threshold: type <threshold|limit|both>, track
  <by_src|by_dst|by_rule|by_both>, count <N>, seconds <T>".
- **Suricata default variables**: confirmed in the installed Suricata 7.0.3
  `/etc/suricata/suricata.yaml` (HOME_NET, EXTERNAL_NET, DNP3_SERVER/CLIENT,
  MODBUS_CLIENT/SERVER, ENIP_CLIENT/SERVER all present; SSH_PORTS 22,
  DNP3_PORTS 20000, MODBUS_PORTS 502). A test rule using an undefined
  `$ICS_EWS` failed to load and `suricata -T` exited 1, so the rules use only
  the default variables and the README tells sites to set them.

### Researcher

- **Dragos 2026 Year in Review press release** (February 17, 2026) -
  https://www.dragos.com/resources/press-release/dragos-2026-year-in-review-new-ot-threats-ransomware
  - AZURITE: "targeting OT engineering workstations and exfiltrating
    operational data including network diagrams, alarm data, and process
    information".
  - VOLTZITE: "manipulating engineering workstation software to extract
    configuration files and alarm data"; "compromised Sierra Wireless Airlink
    cellular gateways ... and then pivoted to engineering workstations."
  - "persistent mischaracterization of OT incidents as “IT only” due to OT
    devices such as engineering workstations and HMIs misclassified as IT".
  - KAMACITE scanned "HMIs, variable frequency drives, metering modules, and
    cellular gateways" (context only; not used in a record).
- **SigmaHQ** (sparse clone of SigmaHQ/sigma at 53b90df, 2026-11-07, and the
  sigma-specification taxonomy appendix v2.1.0): logsource names
  (`process_creation`, `network_connection`, `service: security`,
  `product: linux` / `service: syslog`), Sysmon field names (`Initiated`,
  `SourceIp`, `DestinationPort`, `Image`, `ParentImage`, `Company`,
  `Product`), the `Provider_Name` used for 1102, and remote-access tool
  metadata (AnyDesk, ScreenConnect, UltraVNC, TeamViewer incoming session).
  Values are referenced, not rules copied; SigmaHQ rules are under the
  Detection Rule License 1.1, and the rules that supplied tool metadata are
  listed in `references`.
- **MITRE ATT&CK for ICS** techniques page (current version) - every
  T0xxx id used in this stream was checked against it.

## Tool verification

- `sigma-cli` 3.1.0 with `pysigma-backend-elasticsearch`, installed in a
  scratch virtualenv (the system pip refused to replace a Debian-packaged
  dependency). `sigma convert -t lucene --without-pipeline` succeeds for all
  11 Sigma files. `sigma check` could not run: its tag validator downloads
  MITRE D3FEND data and the proxy refused the tunnel.
- Suricata 7.0.3 installed with apt. `suricata -T -S <file> -c
  /etc/suricata/suricata.yaml` succeeds for each of the four `.rules`
  files; all 14 rules load, 0 fail, 0 inspect the application layer.
- `python artifacts/scripts/validate.py`: OK, no errors and no warnings once
  the parallel catalog stream wrote ICS-0012 (earlier runs showed it as a
  pending record).
- Quotes: 33 hunt quotes were checked mechanically, whitespace-normalised,
  against saved copies of the AA26-097A, AA25-343A, NCSC, Siemens, Schneider
  and Dropbear pages; the rest (AA23-335A, Primary Mitigations, the ASD/CISA
  PDF, Dragos, Unitronics, Microsoft) were checked by hand against the
  scraped text, because the proxy refuses direct fetches of those hosts.
- A `|re|i` regular expression converted, but Lucene's regex engine supports
  neither `(?i)` nor `\b`, so the project-file rule uses delimiter-anchored
  `contains` and `endswith` values instead.

## Rejected or deferred

- **Engineering software started by an unusual parent** (asked for in the
  brief): no vendor document read gives the Studio 5000 or Control Expert
  executable names; the TIA Portal name rests on NVISO alone (low in
  ICS-0010). Rejected rather than guessed; ICS-HUNT-0002 covers the network
  side.
- **Project files written to removable media**: Sysmon FileCreate does not
  mark removable drives and Windows removable-storage auditing was not read.
  Left as a hunt step in ICS-HUNT-0008.
- **Gateway web-UI login and configuration-change rules** (AirLink OS,
  Teltonika, Moxa, Digi): no verbatim message formats were read. ICS-HUNT-0007
  treats them as a configuration diff and log review.
- **Windows 4625 for failed break-glass attempts**: field reference not read.
- **4720 user-account creation**: Microsoft page not read; ICS-HUNT-0011
  covers group membership (4732) only.
- **Application-layer Suricata rules** (modbus, dnp3_*, enip_command,
  cip_service) and any rule on write, stop, program or mode-change function
  codes: out of scope this round and, for the keywords, disabled in
  Suricata's default configuration.
- **Unitronics protocol id (ICS-PROTO-0013, PCOM)**: AA23-335A names only the
  port, so ICS-PACK-0003 and ICS-HUNT-0010 assert no protocol, consistent
  with ICS-INC-0005.
- **Vendor blogs attributing AA26-097A to CyberAv3ngers**: not used, as in
  ICS-INC-0009.

## Gaps that limit these detections

1. AA26-097A's actors used the vendor software on their own infrastructure,
   so EWS-side rules cannot see the main campaign; the boundary, the modem,
   the controller log and the known-good logic comparison are the evidence.
2. Every Windows rule depends on settings that are off by default (command
   lines in 4688, Sysmon network events). Hosts without them are not
   evaluated.
3. The Suricata rules see ports, not content, and miss protocols moved to
   other ports; Zeek's service field (ICS-HUNT-0009) is the cross-check.
4. Dropbear strings come from current source; modem firmware may differ.
5. Only Ignition's audit and alarm tables are documented (ICS-DS-0010);
   other HMI products' detections in ICS-PACK-0002 are not evaluated until
   their formats are read.
6. "Check" detections in the packs name steps for a triage engine that is
   not built (docs/ROADMAP.md); today they are manual.

## Suggested back-links for record owners (not edited by this stream)

- ICS-INC-0009: hunts ICS-HUNT-0001, -0002, -0003, -0006, -0007, -0008;
  pack ICS-PACK-0001.
- ICS-INC-0007: ICS-HUNT-0004, -0005; ICS-PACK-0002.
- ICS-INC-0005: ICS-HUNT-0010; ICS-PACK-0003.
- ICS-INC-0010: ICS-HUNT-0003, -0007, -0012.
- ICS-TA-0019, ICS-TA-0009, ICS-TA-0010..0013, ICS-TA-0006, ICS-TA-0015:
  the packs and hunts that list them.
- ICS-DS-0006 gaps: event 1102 is now read (Microsoft) and used by
  `ews_hmi_security_log_cleared.yml`; the "not read" gap can be narrowed.
- ICS-0010: the TIA Portal .apNN and .zapNN extensions are now
  vendor-documented (Siemens TIA Portal V20 help), which can support the
  Settings.xml and PEData.plf entries' file-type claims.
- ICS-0013 / ICS-DS-0012: Dropbear log strings for the modem SSH events.
- docs/ID_REGISTRY.md: record ICS-HUNT-0001..0012 and ICS-PACK-0001..0004
  as allocated (next free ICS-HUNT-0013, ICS-PACK-0005) and sids
  9000001-9000014 as used.
