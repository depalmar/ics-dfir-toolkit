# ICS DFIR Toolkit

**A sourced DFIR knowledge base for industrial control systems and operational technology.**

By [Raymond DePalma](https://www.linkedin.com/in/raymond-depalma/) · published by [DePalma Research LLC](https://www.linkedin.com/company/depalma-research)

> [!WARNING]
> **Early stage: knowledge base first, tooling later.** This release is the
> schema, the validator and the first round of research records. There is no
> collector or analyzer yet. Nothing here should be run against a live control
> system; where a record describes a collection method it states its `impact`
> on the process, and anything above `passive` needs operations' approval.

The ICS sibling of [edge-dfir-toolkit](https://github.com/depalmar/edge-dfir-toolkit)
and [ai-dfir-toolkit](https://github.com/depalmar/ai-dfir-toolkit), built with
the same discipline:

- **Every claim cites a primary source and quotes it.** Vendor documentation,
  government advisories (CISA, NSA, FBI, DOE, EPA, ASD's ACSC, NCSC-UK and
  partners), and the researchers who did the analysis. Press is a lead, never
  the basis for a rating.
- **Confidence reflects provenance.** `high` = vendor-documented or a
  government authority's own words; `medium` = multiple independent sources;
  `low` = single-source or inferred, always flagged `unverified`.
- **Gaps are stated, not filled.** A missing menu path or event id is honest; a
  guessed one fails during an incident. A malware family with no detection
  says why.
- **Safety before evidence.** Every collection method declares its impact on
  the process: `passive`, `read-only`, `online-vendor-tool` or
  `process-risk`. Active scanning of a live control network is always
  `process-risk`.
- **Attribution is reported, never computed.** One record per reporter's
  cluster. Dragos's ELECTRUM and the US Government's Sandworm are linked by
  aliases, not merged, because neither reporter equates them.

Why OT needs its own toolkit: the best evidence is usually *not* on the
controller. Many PLCs keep no audit log, diagnostic buffers are small ring
buffers, and the control logic itself is the key artifact - which makes a
trusted known-good copy a precondition for any investigation. The rest lives
on Windows engineering workstations and HMIs (which Dragos notes are routinely
misclassified as IT), on the wire, and in remote-access and historian logs.

License: Apache 2.0.

---

## Disclaimer

This is independent research by Raymond DePalma, published by DePalma Research
LLC. It is not affiliated with, endorsed by, or produced on behalf of any former
employer or any vendor whose products it covers. All content is derived from
public sources. Product names are used only to identify the platforms covered.

---

## Structure

```
ics-dfir-toolkit/
├── artifacts/
│   ├── catalog/          # ICS-NNNN   platforms: controllers, EWS/HMI hosts, gateways
│   ├── protocols/        # ICS-PROTO  operations to detect, Zeek/ICSNPP field names
│   ├── visibility/       # ICS-DS     data sources: what exists, where, how long, gaps
│   ├── intel/
│   │   ├── actors/       # ICS-TA     one reporter's cluster each
│   │   ├── malware/      # ICS-MAL    ICS malware and attack tools, published rules
│   │   ├── incidents/    # ICS-INC    case studies, chain as the sources describe it
│   │   ├── iocs/         # ICS-IOC    indicator sets parsed from publishers' files
│   │   └── exploitation.yml          # quoted exploitation dates per CVE
│   ├── hardening/        # controls with quoted sources and vendor syntax
│   ├── response/         # safety-first containment and recovery playbooks
│   ├── hunts/            # ICS-HUNT   hypotheses over data the owner already keeps
│   ├── packs/            # ICS-PACK   detections tied to evidence and rules
│   ├── watch/            # KEV ledger for ICS vendors
│   ├── schema/           # JSON Schema 2020-12, shared vocab in common.schema.json
│   └── scripts/validate.py
├── docs/
│   ├── ID_REGISTRY.md    # every allocated and reserved id
│   ├── research/         # dated research notes the records were built from
│   ├── VERIFICATION.md   # correction log
│   └── ROADMAP.md
└── CLAUDE.md             # the rules, for humans and agents alike
```

Rule directories (`NN-*`): `01-engineering-workstations/` and
`03-remote-access/` (Sigma), `02-ot-network/` (Suricata, port and flow level;
set `HOME_NET` and the client variables for your site). Every rule is linked
from the hunt or pack it expresses.

## What is in it (rounds 1-2, 2026-11-08)

| Records | Count | Highlights |
| --- | --- | --- |
| Platforms | 15 | Rockwell Logix (controller log, Change Detection AuditValue), Siemens S7-1200/1500 (diagnostics buffer survives memory reset but is not in TIA Portal backups), S7-300/400, Modicon (M580 syslog; M340 has none), Unitronics, Triconex, OMRON, CODESYS, MicroLogix (vendor password recovery erases program and IP), substation RTU/IED, OPC UA, historian, Windows EWS and HMI/SCADA hosts, cellular gateways |
| Hunts | 12 | Internet-facing PLC sessions, new engineering-protocol talkers, out-of-window downloads, HMI remote access, historian gaps during remote sessions, gateway SSH, project-file theft |
| Detection packs | 4 | AA26-097A, AA25-343A, AA23-335A, engineering-workstation intrusion; 11 Sigma rules and 14 port/flow Suricata rules in `01-`, `02-`, `03-` |
| Indicator sets | 3 | CISA AA26-097A STIX; ESET DynoWiper and Industroyer (BSD 2-Clause), parsed in code |
| Protocols | 20 | Identity records: transport, native authentication, open parsers. Operations tables come later |
| Data sources | 14 | Many of the most useful logs ship disabled (Suricata ICS parsers, Control Expert event logging, Windows 4688 command line, Ignition audit) |
| Threat actors | 19 | Dragos, US Government, Mandiant, ESET and CERT Polska clusters kept apart; Poland 2025's three-way attribution listed as reported |
| Malware | 16 | Stuxnet to the 2025 wipers (DynoWiper, LazyWiper, PathWiper, GigaWiper); every record states its detection gap |
| Incidents | 13 | Ukraine 2015 to the July 2026 US water-sector MicroLogix campaign and AA26-231A (AI-generated scripts against exposed S7 PLCs) |
| Hardening | 76 controls | Cross-platform baseline plus Rockwell, Siemens, Unitronics and remote-access gateways |
| Response | 1 | Safety-first baseline playbook with a sourced `do_not` list |

The research notes behind every record are in `docs/research/2026-11-08/`;
what is still missing is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Validate

```bash
pip install -r requirements.txt
python artifacts/scripts/validate.py
```

Maintenance, all report-only (they never edit records):

- `artifacts/scripts/mappings.py` generates [MAPPINGS.md](MAPPINGS.md) - ATT&CK
  coverage by technique: who uses it, which data sources see it, which hunts and
  packs look for it, and the **gaps** where adversary use is recorded but nothing
  detects it. CI fails if it is stale.
- `artifacts/scripts/check_quotes.py` re-fetches every quoted page and reports
  quotes that are gone; a monthly workflow opens an issue.
- `artifacts/scripts/advisory_watch.py` compares CISA's KEV catalog with the
  packs and the triage ledger, lists CVEs not yet searched for exploitation
  dates, and re-hashes indicator files; a weekly workflow opens an issue.

The validator checks every record against its schema and against every other
record: ids are unique and files are named after them, every id mentioned
anywhere has a record, `low` confidence is always `unverified`, a record whose
sources all came through a summariser is `unverified`, `high` never rests on
press alone, and every rule file is linked to the detection it expresses.

## Record types at a glance

| Record | Answers |
| --- | --- |
| Platform | What evidence exists on this controller or host, how to read it without moving the process, and what normal vs suspicious looks like |
| Protocol | Which operations change a controller (writes, downloads, stop/run, restart, firmware) and how open parsers name them |
| Data source | What an owner can have *before* an incident, what must be enabled, retention, and what it cannot see |
| Actor | Who did it, as the reporter says, with their confidence words verbatim |
| Malware | Where it runs, what it speaks, what it can do to the process, what it leaves behind, published detection content |
| Incident | What happened, in order, with the physical consequence a primary source states |
| Hardening | What to do, why, the vendor's own syntax, and what it blunts according to the source |
| Response | Safety first, then preserve, contain, rotate, eradicate, recover, verify - and what not to do |

See [docs/ROADMAP.md](docs/ROADMAP.md) for what comes next.
