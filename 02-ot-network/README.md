# 02-ot-network/ - Suricata over passive OT capture (port and flow level)

Platforms: ALL. Data sources: `ICS-DS-0002` (Suricata alerts), read
alongside `ICS-DS-0001` (Zeek/ICSNPP) for what each flagged session did.
Detection packs: `ICS-PACK-0001`, `ICS-PACK-0002`, `ICS-PACK-0003`,
`ICS-PACK-0005`. Hunts: `ICS-HUNT-0001`, `ICS-HUNT-0002`, `ICS-HUNT-0004`,
`ICS-HUNT-0007`, `ICS-HUNT-0009`, `ICS-HUNT-0010`, `ICS-HUNT-0013`,
`ICS-HUNT-0016`, `ICS-HUNT-0020`, `ICS-HUNT-0021`, `ICS-HUNT-0022`.

## Rules

| File | sids | Detects | Rests on |
|---|---|---|---|
| `ot_protocol_inbound_from_unapproved_host.rules` | 9000001-9000009 | Sessions to 44818/tcp+udp, 2222/tcp+udp, 502, 102, 20000, 2404, 4840 from outside the approved client group or HOME_NET | AA26-097A (44818, 2222, 102, 502); ICS-DS-0001 parser defaults (20000, 2404, 4840) |
| `remote_access_inbound_to_ot.rules` | 9000010-9000011 | VNC (5900-5910) and SSH into the OT range from outside | AA25-343A; AA26-097A |
| `unitronics_port_inbound.rules` | 9000012-9000013 | Sessions to 20256 from outside, and to 20257 from anywhere | AA23-335A |
| `ot_protocol_outbound_to_external.rules` | 9000014 | An OT host opening an industrial-protocol-port session to outside HOME_NET | NCSC-led connectivity principles; AA25-343A |
| `relay_and_rtu_service_sessions.rules` | 9000015-9000018 | UDP 50000 to SIPROTEC EN100 devices, and FTP (FTP_PORTS) to relays and RTUs, each from outside HOME_NET and between OT hosts | CISA ICSA-15-202-01 (CVE-2015-5374, "Monitor traffic ... on Port 50000/UDP"); CERT Polska (Relion FTP file deletion) |
| `inbound_scans_of_ot_ranges.rules` | 9000019-9000020 | One outside source sending SYNs to 5900-5910, or to 102/502/2222/44818, across HOME_NET (threshold by source) | AA25-343A (Nmap/OpenVAS search for VNC, T1595.002); AA26-097A (ports targeted on PLCs) |
| `smb_and_rpc_sessions_from_ot_hosts.rules` | 9000021-9000022 | An OT host opening SMB (139/445) to outside HOME_NET; one OT host sending SYNs to 135/tcp on many hosts (DCOM/OPC Classic enumeration pattern) | CISA ICS-ALERT-14-281-01E (remote Cimplicity screen loads); CISA ICS-ALERT-14-176-02A (Havex OPC enumeration); Microsoft (RPC endpoint mapper on 135) |

## Deploying

- **Passive only.** Run Suricata in IDS mode on a TAP or SPAN feed. Inline
  IPS on a control network is `process-risk` (ICS-DS-0002): the joint
  ASD/CISA guidance does not recommend an IPS unless it is tailored to OT or
  outside critical process control.
- **Set the variables.** Every rule uses only variables defined in Suricata's
  default `suricata.yaml` (`HOME_NET`, `EXTERNAL_NET`, `ENIP_CLIENT`,
  `ENIP_SERVER`, `MODBUS_CLIENT`, `MODBUS_SERVER`, `DNP3_CLIENT`,
  `DNP3_SERVER`, `SSH_PORTS`), so the files load unchanged in CI and on a
  stock sensor; a rule naming an undefined variable fails to load. Out of the
  box the `*_CLIENT` groups equal `HOME_NET`, so the rules fire on sessions
  from outside HOME_NET. Set `HOME_NET` to the OT ranges (including modem and
  gateway addresses) and each `*_CLIENT` to the approved engineering
  workstations, HMIs and SCADA servers - the "device control list" AA26-097A
  asks for - and they also fire on unapproved internal clients.
- **Header, flow and threshold keywords only.** No `modbus`, `dnp3_*`,
  `enip_command` or `cip_service` keyword is used: those parsers ship
  disabled. The rules therefore match on ports, not on protocol content, and
  miss a protocol moved to a non-standard port.
- **Low noise by design.** `flow:established` means the TCP handshake
  completed (the device answered), and `threshold: type limit, track by_both,
  count 1, seconds 3600` raises at most one alert per source-destination pair
  per hour. Scans of closed ports do not fire; read firewall denies for those
  (ICS-HUNT-0001). The exceptions are the scan rules (sids 9000019, 9000020,
  9000022), which match the opening SYN (`flags:S,12`) and use `threshold:
  type both, track by_src` so that one source reaching the count in the
  window raises one alert; their counts and windows are starting values to
  tune, and the 135/tcp rule fires on domain controllers, management servers
  and SCADA servers that legitimately poll many hosts until those are
  suppressed by address.
- A hit says a session reached a port. It does not say what the session did:
  pull the Zeek protocol logs for the same flow, and the controller's own log
  for the same minutes.

## Out of scope this round

- Rules on specific function codes, program-transfer or mode-change commands.
- Rules on application-layer content of any ICS protocol.
- IOC address lists from AA26-097A: indicator sets belong in
  `artifacts/intel/iocs/`, parsed from CISA's STIX file, not retyped here.
