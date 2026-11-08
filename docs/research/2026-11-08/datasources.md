# Visibility data sources and protocol identity - research notes (2026-11-08)

Stream: logs and telemetry an industrial plant can collect to investigate an
incident (`artifacts/visibility/ICS-DS-0001..0014`) and identity-only protocol
records (`artifacts/protocols/ICS-PROTO-0001..0020`). Protocol records omit
`operations` by design: no function codes or command sequences that change
controller state were researched or recorded.

Method: Firecrawl scrape of primary pages (markdown, `onlyMainContent`; PDFs
with the PDF parser) and Microsoft Learn fetch; GitHub-hosted READMEs and
scripts fetched as raw files. Quotes copied from a rendered or raw page are
`read: direct`; quotes taken from a search-result snippet are
`read: summariser` and must be re-read before a record rests on them. Every
`accessed` date is 2026-11-08. GitHub-sourced quotes were re-checked
mechanically against saved copies (whitespace-normalised).

## Sources read directly

### Government guidance (high for what the authority recommends)

- **CISA AA26-097A** (Iranian-affiliated actors exploit PLCs; updated
  2026-07-22) - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a
  - "Inbound malicious traffic has been observed targeting PLC devices on the
    following ports: `44818`, `2222`, `102`, and `502`, as well as targeting
    modems on port `22`."
  - "Enable logs for connected modems and regularly review for suspicious
    activity to detect intrusions and improve incident response speed."
  - "Functions of industrial control systems management protocols that change
    an asset’s operating mode or modify programs." (under "Monitor the content
    of network traffic")
  - Actors used Studio 5000, EcoStruxure Control Expert and TIA Portal "on
    leased, third-party hosted infrastructure" - a key gap: nothing on the
    owner's EWS.
- **CISA AA25-343A** (pro-Russia hacktivists, VNC to HMIs) -
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-343a
  - "Threat actors use HMI interfaces to clear alarms caused by their activity
    and alarms already present on the system at the time of their intrusion."
  - "Restrict and monitor both inbound and outbound traffic at OT perimeter
    firewalls."
  - "Asset owners should use attack surface management services and web-based
    search platforms to scan the internet."
- **Best practices for event logging and threat detection** (ASD's ACSC with
  CISA, FBI, NSA and partners, Aug 2024) -
  https://www.cyber.gov.au/sites/default/files/2024-08/best-practices-for-event-logging-and-threat-detection.pdf
  - "Most OT devices use embedded software that is memory and/or processor
    constrained. An excessive level of logging could adversely affect the
    operation of those OT devices."
  - "Note that in cases where OT devices do not support logging, device logs
    are not available, or are available in a non-standard format, it is good
    practice to ensure network traffic and communications to and from the OT
    devices are logged."
  - "Note, it is not recommended to deploy an IPS unless it is tailored to the
    OT environment, or is outside of critical process control."
  - "Data historians ... can provide an additional source of event log data
    for OT networks."
- **Secure connectivity principles for OT** (NCSC-UK with CISA, FBI, ASD's
  ACSC, Cyber Centre, BSI, NCSC-NL, NCSC-NZ) -
  https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-secure-connectivity-for-operational-technology.pdf
  - Principle 7 "Ensure all connectivity is logged and monitored"; break-glass
    use "triggers the highest criticality alarm"; "Continuous monitoring of
    data flows within and between network segments is crucial".
- **CISA alert, Unitronics PLCs in water systems** (2023-11-28) -
  https://www.cisa.gov/news-events/alerts/2023/11/28/exploitation-unitronics-plcs-used-water-and-wastewater-systems
  - "Cyber actors are actively targeting TCP 20256 ... they leverage scripts
    specific to PCOM/TCP to query and validate the system".
- **CISA AA22-083A** (TRITON appendix; Havex) -
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-083a
  - "... collectively implement the TriStation protocol via User Datagram
    Protocol (UDP) 1502."
- **CISA Cyber Hygiene Services** - https://www.cisa.gov/cyber-hygiene-services
  - scans "internet-accessible network assets (public, static IPv4
    addresses)"; weekly reports and ad-hoc alerts.

### Open-source tooling (CISA-published and others)

- **CISA ICSNPP** overview and READMEs for modbus, s7comm, enip, dnp3,
  opcua-binary, omron-fins, hart-ip, bacnet, profinet-io-cm (BSD-3-Clause) -
  https://github.com/cisagov/ICSNPP . Log file names, default ports and
  coverage limits came from these, e.g. "There is currently no (0%) detailed
  logging for S7Comm Plus functions" and "These vendor/product specific
  functions are not included in this parser" (Modbus).
- **CISA Malcolm** supported-protocols table (Apache-2.0) -
  https://github.com/cisagov/Malcolm/blob/main/docs/protocols.md . Shows IEC 104
  via cert-lv/spicy-iec104 and PROFINET via amzn/zeek-plugin-profinet; no
  IEC 61850 MMS/GOOSE, PCOM, CODESYS, TriStation or SLMP parser listed.
- **cert-lv/spicy-iec104** scripts and zkg.meta (BSD-3-Clause): default
  2404/tcp; log paths iec104_telemetry, iec104_file, iec104_write,
  iec104_query, iec104_ctrl, iec104_param, iec104_read.
- **Zeek** base Modbus and DNP3 scripts: Modbus `ports = { 502/tcp }`, DNP3
  `ports = { 20000/tcp, 20000/udp }`; Info record fields.
- **Suricata** docs (modbus keyword, EVE JSON format) and source
  (suricata.yaml.in, dnp3/enip keyword .rst; GPL-2.0). Key finding: Modbus,
  DNP3 and ENIP parsers ship `enabled: no`.

### Vendor and standards documentation

- **Microsoft Learn**: event 4688 (command line empty by default; GPO path),
  Sysmon v15.22 (log path; Event ID 3 disabled by default), about_Logging_Windows
  (4104, PowerShellCore/Operational).
- **Rockwell 1756-PM015** (controller log: 100/500-entry circular buffer,
  entry fields, event list incl. "Log Collected Data Cleared", change
  detection) and **1756-UM900** controller-logging page (AssetCentre or
  syslog collector).
- **Siemens**: S7-1500 CPU memory function manual (retentive diagnostic
  buffer survives power failure and memory reset); application example
  68011497 (buffer contents include "Security events"; TIA path); web server
  manual page (Diagnostics > Diagnostics buffer, last 250 or all); TIA V21
  Syslog (S7-1500) introduction (FW V3.1 local cache, Syslog.Browse; recording
  "cannot be deactivated"); TIA V20 secure PG/HMI communication (TLS from V17).
- **Schneider EIO0000001999 v15** Modicon Platform Cybersecurity guide (first
  90 of 170 pages): syslog RFC 5424 over TCP; Control Expert Event Logging
  "cleared by default"; M580 and Control Expert event message tables; events
  lost on reset except M580 firmware 4.0 and later.
- **Inductive Automation Ignition 8.1**: audit profiles (default 90-day
  retention) and alarm journal (alarm data in memory by default; eventtype
  0/1/2/4/5).
- **AVEVA PI Data Archive**: audit database overview (files in PI\log; normal
  data collection not audited) and EnableAudit tuning parameter.
- **ODVA** CIP Security; **Modbus Organization** specifications page (Modbus
  Security, port 802); **DNP Users Group** SAv5 announcement; **OPC
  Foundation** OPC 10000-2 §4.8 security modes; **IEC** 61850 site page on
  IEC 62351; **BACnet International** BACnet/SC; **FieldComm Group** HART-IP
  explained (TLS/DTLS, syslog, audit logs required since HART 7.7); **CODESYS
  Security Whitepaper v10.0** (ports, user management enforced by default,
  TLS 1.2 levels).
- **Kaspersky ICS CERT** (Securelist) on UMAS: "UMAS is based on the
  Modbus/TCP protocol"; reservation "acts as authentication".
- **MITRE ATT&CK** data components list (DC ids used in records verified
  there): https://attack.mitre.org/datacomponents/

## Read only as search snippets (`read: summariser`, records flagged)

- Siemens SIOS 109955142 (legacy access-level password for HMI connections).
- Siemens S7-300 CPU 31x manual ("can save up to 500 messages").
- Sierra Wireless ALEOS 4.14 guide (Admin > Log > Configure Logging) -
  distributor-hosted copy; no official HTML found.
- AVEVA PI AuditViewer page.
- PI North America / profinet.com PROFINET Security Classes.
- Rockwell developer guide and licensing page on PCCC.
- Mitsubishi SLMP Reference Manual glossary.
- Software Toolbox and TDL pages on OPC DA / DCOM / KB5004442.
- Armis ModiPwn (UMAS); nhimg.org guide (FINS/SLMP authentication).

## Sources rejected or not used

- Press and aggregator sites (industrialcyber.co, LinkedIn posts, WaterISAC
  re-posts, industrialmonitordirect.com blogs, plc-hmi-scadas.com): leads
  only; never quoted.
- Scribd and distributor copies of the Schneider guide (rs-online,
  euautomation): the official se.com PDF was read instead.
- cyber.gov.au HTML page for the logging guidance: 404; the PDF was used.
- NCSC HTML landing page: summary only; the PDF was used.
- IANA service-name registry: blocked to direct fetch and too large to
  scrape; default ports were taken from parser defaults and vendor or
  government documents instead.
- NIST SP 800-82r3: not read this round (PDF too large for the budget); no
  claims rest on it.
- Rockwell syslog configuration steps for ControlLogix 5590, TIA Portal and
  Studio 5000 workstation-side logs, WinCC / FactoryTalk View / iFIX /
  InTouch audit trails, Moxa / Teltonika / Digi gateway logging, Shodan and
  Censys documentation, Microsoft events 1102 and service installation: not
  found or not read; records state these as gaps rather than guess.

## Monitoring gaps that matter most for OT investigations

1. **Controllers keep little and lose it fast.** Rockwell's controller log is
   100 or 500 entries and circular unless written to the card or collected;
   S7 diagnostic buffers are ring buffers; many PLCs in the registry showed
   no syslog at all in the sources read. Forward what exists before an
   incident.
2. **The richest device logs are off by default.** Suricata's ICS parsers,
   Schneider Control Expert event logging, Windows command-line auditing,
   Sysmon network events, Ignition auditing and alarm journaling all ship
   disabled.
3. **Encryption is arriving faster than parsers.** S7comm-plus under TLS (TIA
   V17+), CIP Security, OPC UA SignAndEncrypt and Modbus Security leave a
   passive sensor with metadata only; plan device-side logging (S7-1500
   syslog, M580 syslog) to replace what the wire no longer shows.
4. **Parser coverage is uneven.** ICSNPP logs S7comm-plus headers only and
   skips vendor-specific Modbus functions (UMAS); no open parser was found
   for IEC 61850 MMS/GOOSE, PCOM, CODESYS V3, TriStation or SLMP.
5. **Attackers using their own engineering software leave nothing on the
   owner's EWS** (AA26-097A). Controller-side logs, network capture at the
   boundary and comparison with offline known-good logic are the only
   evidence.
6. **Paths that bypass the broker.** Cellular modems and third-party VNC
   exposure (AA25-343A, AA26-097A) avoid boundary firewalls and remote-access
   logs; gateway logs are small and volatile.
7. **Logs show events, not intent.** No source here shows what the new logic
   does; only comparison with a trusted, offline known-good project does, and
   restoring a post-compromise backup reinstalls the attacker's logic.
