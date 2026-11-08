# ID registry

Ids are permanent. Once a file exists, its id never changes meaning. Ids below
were allocated up front so records written in parallel can reference each
other. A reference to an id listed here whose record is not written yet is a
*pending record*: the validator warns and lists it as a coverage gap. A
reference to an id that is not listed here is an error. Only list an id here
when the entity is real and sourced; never reserve one to silence the
validator. New entries take the next free number after the highest allocated
one.

| Prefix | Record | Directory |
| --- | --- | --- |
| `ICS-NNNN` | Platform (controller family, host role, gateway class) | `artifacts/catalog/` |
| `ICS-PROTO-NNNN` | Industrial protocol | `artifacts/protocols/` |
| `ICS-DS-NNNN` | Visibility data source | `artifacts/visibility/` |
| `ICS-TA-NNNN` | Threat actor (one reporter's cluster) | `artifacts/intel/actors/` |
| `ICS-MAL-NNNN` | Malware family or attack tool | `artifacts/intel/malware/` |
| `ICS-IOC-NNNN` | Indicator set from one publication | `artifacts/intel/iocs/` |
| `ICS-INC-NNNN` | Incident case study | `artifacts/intel/incidents/` |
| `ICS-HUNT-NNNN` | Hunt | `artifacts/hunts/` |
| `ICS-PACK-NNNN` | Detection pack | `artifacts/packs/` |

Files are named `<id>-<slug>.yml`, e.g. `ICS-TA-0004-xenotime.yml`.

## Platforms (`ICS-NNNN`)

| Id | Platform | Asset class |
| --- | --- | --- |
| ICS-0001 | Rockwell Automation Logix 5000 controllers (ControlLogix, CompactLogix, GuardLogix) | plc |
| ICS-0002 | Rockwell Automation MicroLogix 1100 / 1400 | plc |
| ICS-0003 | Siemens SIMATIC S7-1200 / S7-1500 | plc |
| ICS-0004 | Siemens SIMATIC S7-300 / S7-400 | plc |
| ICS-0005 | Schneider Electric Modicon (M340, M580; M221, M241, M251, M258) | plc |
| ICS-0006 | Unitronics Vision / Samba PLC+HMI | plc |
| ICS-0007 | Schneider Electric Triconex safety controllers | safety-controller |
| ICS-0008 | OMRON Sysmac NJ / NX | plc |
| ICS-0009 | CODESYS V3 runtime-based controllers (multi-vendor) | plc |
| ICS-0010 | Windows engineering workstation (TIA Portal, Studio 5000, EcoStruxure, CODESYS IDE) | engineering-workstation |
| ICS-0011 | Windows HMI / SCADA server (WinCC, FactoryTalk View, iFIX, InTouch, Ignition) | hmi-scada-server |
| ICS-0012 | OT historian (AVEVA PI and similar) | historian |
| ICS-0013 | Cellular and industrial remote-access gateways (Sierra Wireless AirLink, Moxa, Teltonika, Digi) | remote-access-gateway |
| ICS-0014 | Substation RTU and protection IED (IEC 60870-5-104, IEC 61850) | rtu |
| ICS-0015 | OPC UA servers | opc-server |

## Protocols (`ICS-PROTO-NNNN`)

| Id | Protocol | Slug |
| --- | --- | --- |
| ICS-PROTO-0001 | Modbus TCP | `modbus-tcp` |
| ICS-PROTO-0002 | S7comm (classic, S7-300/400) | `s7comm` |
| ICS-PROTO-0003 | S7comm-plus (S7-1200/1500) | `s7comm-plus` |
| ICS-PROTO-0004 | EtherNet/IP and CIP | `enip-cip` |
| ICS-PROTO-0005 | PCCC (over CIP or DF1) | `pccc` |
| ICS-PROTO-0006 | DNP3 | `dnp3` |
| ICS-PROTO-0007 | IEC 60870-5-104 | `iec-104` |
| ICS-PROTO-0008 | IEC 61850 MMS | `iec-61850-mms` |
| ICS-PROTO-0009 | IEC 61850 GOOSE | `iec-61850-goose` |
| ICS-PROTO-0010 | OPC UA | `opc-ua` |
| ICS-PROTO-0011 | OPC DA / classic (DCOM) | `opc-da` |
| ICS-PROTO-0012 | Schneider UMAS (Modbus function code 90) | `umas` |
| ICS-PROTO-0013 | Unitronics PCOM | `pcom` |
| ICS-PROTO-0014 | OMRON FINS | `fins` |
| ICS-PROTO-0015 | CODESYS V3 protocol | `codesys-v3` |
| ICS-PROTO-0016 | TriStation | `tristation` |
| ICS-PROTO-0017 | PROFINET (incl. DCP) | `profinet` |
| ICS-PROTO-0018 | BACnet/IP | `bacnet` |
| ICS-PROTO-0019 | HART-IP | `hart-ip` |
| ICS-PROTO-0020 | MELSEC SLMP / MC protocol | `slmp` |

## Threat actors (`ICS-TA-NNNN`)

One record per reporter's cluster. Overlaps are aliases with `equated: false`;
never merge clusters the reporters do not equate.

| Id | Cluster | Primary reporter |
| --- | --- | --- |
| ICS-TA-0001 | Sandworm Team / APT44 | US Government, Mandiant, ESET, CERT-UA |
| ICS-TA-0002 | ELECTRUM | Dragos |
| ICS-TA-0003 | KAMACITE | Dragos |
| ICS-TA-0004 | XENOTIME (TRITON) | Dragos |
| ICS-TA-0005 | CHERNOVITE (PIPEDREAM) | Dragos |
| ICS-TA-0006 | VOLTZITE | Dragos |
| ICS-TA-0007 | Volt Typhoon | US Government, Microsoft |
| ICS-TA-0008 | BAUXITE | Dragos |
| ICS-TA-0009 | CyberAv3ngers (IRGC-CEC affiliated) | US Government |
| ICS-TA-0010 | Cyber Army of Russia Reborn (CARR) | US Government |
| ICS-TA-0011 | Z-Pentest | US Government |
| ICS-TA-0012 | NoName057(16) | US Government, Europol |
| ICS-TA-0013 | Sector16 | US Government |
| ICS-TA-0014 | SYLVANITE | Dragos |
| ICS-TA-0015 | AZURITE | Dragos |
| ICS-TA-0016 | PYROXENE | Dragos |
| ICS-TA-0017 | Dragonfly / Energetic Bear (Havex) | Symantec, US Government |
| ICS-TA-0018 | TEMP.Veles (TRITON) | Mandiant |
| ICS-TA-0019 | Unnamed Iranian-affiliated APT actors (AA26-097A) | US Government |

ICS-TA-0004 and ICS-TA-0018 are separate because neither Dragos nor Mandiant
equates XENOTIME with TEMP.Veles. ICS-TA-0019 is separate from CyberAv3ngers
because AA26-097A attributes to "a group of Iranian-affiliated APT actors" and
cites CyberAv3ngers only as similar historical activity.

Next free: ICS-TA-0020.

## Malware (`ICS-MAL-NNNN`)

| Id | Family | Note |
| --- | --- | --- |
| ICS-MAL-0001 | Stuxnet | S7-300/400 payload |
| ICS-MAL-0002 | Havex | OPC DA scanning module |
| ICS-MAL-0003 | BlackEnergy (2/3) | HMI-targeting plugins; Ukraine 2015 |
| ICS-MAL-0004 | Industroyer / CrashOverride | IEC 101/104, 61850, OPC DA |
| ICS-MAL-0005 | TRITON / TRISIS / HatMan | Triconex |
| ICS-MAL-0006 | Industroyer2 | IEC 104 |
| ICS-MAL-0007 | INCONTROLLER / PIPEDREAM | Schneider, OMRON, OPC UA, CODESYS |
| ICS-MAL-0008 | COSMICENERGY | IEC 104 |
| ICS-MAL-0009 | FrostyGoop / BUSTLEBERM | Modbus TCP |
| ICS-MAL-0010 | Fuxnet | sensor gateways, Modbus / M-Bus |
| ICS-MAL-0011 | IOCONTROL | embedded Linux IoT/OT |
| ICS-MAL-0012 | EKANS / Snake | ICS-aware ransomware |
| ICS-MAL-0013 | DynoWiper | Poland, December 2025 |
| ICS-MAL-0014 | LazyWiper | Poland, December 2025 |
| ICS-MAL-0015 | PathWiper | Ukrainian critical infrastructure, 2025 |
| ICS-MAL-0016 | GigaWiper / BLUERABBIT | Windows destructive tool; PYROXENE link per Dragos |

BAUXITE's two June 2025 wipers and ELECTRUM's unnamed December 2025 variant
have no record: no primary source names and describes them yet.

Next free: ICS-MAL-0017.

## Incidents (`ICS-INC-NNNN`)

| Id | Incident |
| --- | --- |
| ICS-INC-0001 | Ukraine power grid, December 2015 |
| ICS-INC-0002 | Ukraine transmission substation (Industroyer), December 2016 |
| ICS-INC-0003 | TRITON at a Middle East petrochemical facility, 2017 |
| ICS-INC-0004 | Ukraine Industroyer2 attempt, April 2022 |
| ICS-INC-0005 | Unitronics PLCs at US water utilities (CyberAv3ngers), November 2023 |
| ICS-INC-0006 | Lviv district heating (FrostyGoop), January 2024 |
| ICS-INC-0007 | Pro-Russia hacktivist HMI intrusions at water utilities, 2024 |
| ICS-INC-0008 | Poland distributed-energy attack (ELECTRUM), December 2025 |
| ICS-INC-0009 | Iranian-affiliated exploitation of internet-facing PLCs (AA26-097A), 2025-2026 |
| ICS-INC-0010 | US water-sector MicroLogix 1100/1400 lockout campaign, July 2026 |
| ICS-INC-0011 | Colonial Pipeline, May 2021 (IT incident, precautionary OT shutdown) |
| ICS-INC-0012 | Florida water treatment sodium hydroxide setpoint change, February 2021 |
| ICS-INC-0013 | Internet-exposed Siemens S7 PLCs read and written with AI-generated scripts (AA26-231A), 2026 |

ICS-INC-0010 is separate from ICS-INC-0009 because CISA and the FBI neither
attribute the July 2026 campaign nor link it to AA26-097A.

Next free: ICS-INC-0014.

## Indicator sets (`ICS-IOC-NNNN`)

| Id | Set | Publisher |
| --- | --- | --- |
| ICS-IOC-0001 | AA26-097A PLC exploitation, STIX (April and July 2026) | CISA and partners |
| ICS-IOC-0002 | DynoWiper, Poland December 2025 | ESET (BSD 2-Clause) |
| ICS-IOC-0003 | Industroyer, 2016 | ESET (BSD 2-Clause) |

Next free: ICS-IOC-0004. AA23-335A indicators are not parsed (CISA calls them
outdated, and no saved copy of the file was obtained); AA25-343A publishes none.

## Visibility data sources (`ICS-DS-NNNN`)

| Id | Data source | Category |
| --- | --- | --- |
| ICS-DS-0001 | Passive ICS network capture parsed by Zeek with CISA ICSNPP parsers | network-passive |
| ICS-DS-0002 | Suricata IDS alerts on OT network capture | network-passive |
| ICS-DS-0003 | NetFlow / IPFIX at the IT/OT boundary and inside OT | network-flow |
| ICS-DS-0004 | IT/OT boundary and DMZ firewall logs | perimeter-firewall |
| ICS-DS-0005 | OT remote access logs (VPN, jump host, vendor remote-access platforms) | remote-access |
| ICS-DS-0006 | Windows Security, Sysmon and PowerShell logs on EWS / HMI hosts | host-windows |
| ICS-DS-0007 | Engineering software logs and project files (TIA Portal, Studio 5000, EcoStruxure) | application-audit |
| ICS-DS-0008 | Rockwell Logix controller log and change detection audit value | controller-onboard |
| ICS-DS-0009 | Siemens S7 diagnostic buffer | controller-onboard |
| ICS-DS-0010 | SCADA / HMI application audit trail and alarm-event journal | alarm-event |
| ICS-DS-0011 | Historian process data | historian |
| ICS-DS-0012 | Cellular and industrial remote-access gateway logs | remote-access |
| ICS-DS-0013 | Controller syslog and event logs (e.g. Modicon M580, S7-1500 syslog) | controller-onboard |
| ICS-DS-0014 | Internet exposure data for the owner's own ranges (Shodan, Censys, CISA Cyber Hygiene) | perimeter-firewall |

Next free: ICS-DS-0015.

## Hardening and response file stems

Hardening (`artifacts/hardening/<stem>.yml`): `baseline` (ALL), `rockwell-logix`
(ICS-0001), `siemens-s7` (ICS-0003), `unitronics` (ICS-0006),
`remote-access-gateways` (ICS-0013).

Response (`artifacts/response/<stem>.yml`): `baseline` (ALL).

## Rule directories (`NN-<slug>/`)

Numbered by when they were added; each needs a README.md. Files are
`[a-z0-9_]+.yml` (Sigma), `.yar` (YARA) or `.rules` (Suricata).

| Directory | Scope | Platforms |
| --- | --- | --- |
| `01-engineering-workstations/` | Sigma over Windows logs on EWS and HMI/SCADA hosts | ICS-0010, ICS-0011 |
| `02-ot-network/` | Suricata over passive OT capture, flow and port level only | ALL |
| `03-remote-access/` | Sigma over remote-access, VPN, jump-host and cellular gateway logs | ICS-0013 |
| `04-ics-malware/` | YARA for ICS malware families, vendored only after licence review | ALL |

## Hunts (`ICS-HUNT-NNNN`)

| Id | Hunt |
| --- | --- |
| ICS-HUNT-0001 | Sessions to PLC protocol ports from internet or hosting-provider addresses |
| ICS-HUNT-0002 | Hosts that start speaking an industrial protocol to a controller |
| ICS-HUNT-0003 | Controller downloads, online edits, mode changes and logins outside approved change windows |
| ICS-HUNT-0004 | Remote desktop to HMIs and use of the OT remote-access path from unexpected sources |
| ICS-HUNT-0005 | HMI alarm suppression, credential, device-name and setpoint changes during remote sessions |
| ICS-HUNT-0006 | Process excursions with no alarm, and historian or alarm gaps during remote sessions |
| ICS-HUNT-0007 | Cellular and remote-access gateways: SSH logins, administrative access and configuration changes |
| ICS-HUNT-0008 | PLC project files archived, copied or sent from engineering workstations |
| ICS-HUNT-0009 | Industrial protocols crossing the IT/OT boundary or leaving OT |
| ICS-HUNT-0010 | Unitronics PLC/HMI sessions on 20256 or 20257 from outside the site |
| ICS-HUNT-0011 | New local administrators, logon-log enumeration and log clearing on EWS and HMIs |
| ICS-HUNT-0012 | The owner's own address ranges in internet exposure data |
| ICS-HUNT-0013 | Controller, relay, RTU and HMI restarts, stops and loss of communication |
| ICS-HUNT-0014 | Breaker, valve and setpoint changes in the process record that no operator issued |
| ICS-HUNT-0015 | Safety-system trips and unplanned process shutdowns with no process cause |
| ICS-HUNT-0016 | Logins with vendor-default, built-in or unconfigured accounts on HMIs, controllers and devices |
| ICS-HUNT-0017 | Credential dumping, kernel-driver abuse, staging and remote-session reuse on hosts next to OT |
| ICS-HUNT-0018 | Stuxnet artefacts on Step 7 and WinCC hosts, in their projects and media, and in S7-300/400 blocks read from a clean host |
| ICS-HUNT-0019 | Removable drives and virtual or optical media on engineering, HMI and SCADA hosts, and what ran from them |
| ICS-HUNT-0020 | Network, OPC server, tag and value enumeration from hosts outside the OPC client baseline |
| ICS-HUNT-0021 | Exploitation of internet-facing HMI and SCADA applications - remote screen loads, SMB to the internet, installers in the HMI directory |
| ICS-HUNT-0022 | Inbound scanning of the owner's OT-facing ranges for VNC and PLC services in perimeter firewall logs |

Next free: ICS-HUNT-0023.

## Detection packs (`ICS-PACK-NNNN`)

| Id | Pack |
| --- | --- |
| ICS-PACK-0001 | AA26-097A - Iranian-affiliated exploitation of internet-facing PLCs |
| ICS-PACK-0002 | AA25-343A - pro-Russia hacktivist intrusions into HMIs over VNC |
| ICS-PACK-0003 | AA23-335A - CyberAv3ngers compromise of Unitronics Vision PLC/HMIs |
| ICS-PACK-0004 | Intrusion on engineering workstations and HMIs, and theft of PLC project files |
| ICS-PACK-0005 | Destructive attacks on engineering workstations, HMIs and substation devices |
| ICS-PACK-0006 | Controller logic, tasking and firmware compared with a known-good copy |
| ICS-PACK-0007 | Stuxnet on Step 7 and WinCC hosts, their projects and media, and S7-300/400 controllers |

Next free: ICS-PACK-0008.

## Suricata sids

`02-ot-network/` uses the local range 9000001 upward: 9000001-9000022 are
allocated. Next free: 9000023.
