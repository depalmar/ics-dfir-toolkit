# 02-ot-network/ - Suricata over passive OT capture (port and flow level)

Platforms: ALL. Data sources: `ICS-DS-0002` (Suricata alerts), read
alongside `ICS-DS-0001` (Zeek/ICSNPP) for what each flagged session did.
Detection packs: `ICS-PACK-0001`, `ICS-PACK-0002`, `ICS-PACK-0003`. Hunts:
`ICS-HUNT-0001`, `ICS-HUNT-0002`, `ICS-HUNT-0004`, `ICS-HUNT-0007`,
`ICS-HUNT-0009`, `ICS-HUNT-0010`.

## Rules

| File | sids | Detects | Rests on |
|---|---|---|---|
| `ot_protocol_inbound_from_unapproved_host.rules` | 9000001-9000009 | Sessions to 44818/tcp+udp, 2222/tcp+udp, 502, 102, 20000, 2404, 4840 from outside the approved client group or HOME_NET | AA26-097A (44818, 2222, 102, 502); ICS-DS-0001 parser defaults (20000, 2404, 4840) |
| `remote_access_inbound_to_ot.rules` | 9000010-9000011 | VNC (5900-5910) and SSH into the OT range from outside | AA25-343A; AA26-097A |
| `unitronics_port_inbound.rules` | 9000012-9000013 | Sessions to 20256 from outside, and to 20257 from anywhere | AA23-335A |
| `ot_protocol_outbound_to_external.rules` | 9000014 | An OT host opening an industrial-protocol-port session to outside HOME_NET | NCSC-led connectivity principles; AA25-343A |

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
  (ICS-HUNT-0001).
- A hit says a session reached a port. It does not say what the session did:
  pull the Zeek protocol logs for the same flow, and the controller's own log
  for the same minutes.

## Out of scope this round

- Rules on specific function codes, program-transfer or mode-change commands.
- Rules on application-layer content of any ICS protocol.
- IOC address lists from AA26-097A: indicator sets belong in
  `artifacts/intel/iocs/`, parsed from CISA's STIX file, not retyped here.
