# Roadmap

Ordered by value. The knowledge base comes first because every later layer
(packs, collectors, analyzer, site) reads it.

## Phase 0 - schema and first research round (this release)

- JSON schemas for every record type, shared vocabulary in
  `common.schema.json`, and `validate.py` as the gate.
- Pre-allocated ids (`docs/ID_REGISTRY.md`) for the platforms, protocols,
  data sources, actors, malware families and incidents that the 2015-2026
  public record covers.
- First-round records from Firecrawl reads of primary sources, with research
  notes in `docs/research/2026-11-08/`.

## Round 1 follow-ups (found during research, 2026-11-08)

- ~~**Pending records**~~ - all six platforms written in round 2 (ICS-0002,
  0008, 0009, 0012, 0014, 0015); the validator reports no pending records.
  Still thin: ICS-0002 (no on-controller log documented), ICS-0012 (AVEVA PI
  only), ICS-0008 (only the first 90 pages of OMRON's troubleshooting manual
  read).
- **Detections, round 2 follow-ups:** a Sigma rule for engineering software
  started by an unusual parent (needs vendor-documented process names);
  removable-media writes, gateway web logins, Windows 4625/4720 (formats not
  yet read); `check` detections in packs are manual until the triage engine
  exists; the break-glass rule ships with placeholder account names.
- ~~**New intel to record:** CISA AA26-231A~~ - recorded in round 2 as
  ICS-INC-0013 (no actor, malware or indicator named by the advisory).
- **SLMP authentication:** Mitsubishi's SLMP manual lists a "Remote Password"
  (Lock/Unlock) section that may contradict ICS-PROTO-0020's
  `authentication: none`; read it and correct the record.
- **AA23-335A indicators:** not parsed; CISA calls them outdated. Parse only
  if a saved copy of the publisher file can be obtained without retyping.
- **CISA STIX attribution objects:** AA26-097A's STIX links addresses to
  "HYDROKITTEN" and "CYBER AVENG3RS" while the advisory prose names no group
  (noted on ICS-TA-0019 and ICS-IOC-0001). Revisit if CISA's text changes.
- **Primary documents not yet read:** CERT Polska's full Poland 2025 report
  (PDF), Dragos 2026 Year in Review (PDF), Mandiant APT44 report, Dragos
  CRASHOVERRIDE and TRISIS reports, E-ISAC/SANS Ukraine 2015 report, the
  NRC-hosted TriStation 1131 manual (public; timed out), SANS Five ICS
  Critical Controls, DOE CESER guidance.
- **Behind vendor logins:** Rockwell Knowledgebase (security best practices,
  5590 syslog setup), Siemens support entries, Sierra Wireless bulletins.
  Records resting on CISA republications say so.
- **Open attribution questions:** stage labels for SYLVANITE, AZURITE and
  PYROXENE appear only in trade press; whether OpenPLC ScadaBR and Siemens
  Software Center (KEV 2025) should become watched platforms; who observed
  CVE-2018-4063 (Sierra Wireless) exploitation.
- **Protocol operations tables** (which function codes write, download, stop
  or restart) were deferred in round 1; protocol records carry identity only.

## Phase 1 - make the knowledge base trustworthy

1. **Second-read every `read: summariser` quote** against the rendered page and
   log corrections in `docs/VERIFICATION.md`. A record loses `unverified` only
   after a direct read.
2. ~~**`check_quotes.py`**~~ - done in round 3, with a monthly `quote-check`
   workflow.
3. **KEV triage.** `advisory_watch.py` and the weekly `advisory-watch` workflow
   landed in round 3. Still to do: turn the remaining `deferred` ledger entry
   (CVE-2018-4063) into a decision, and extend the watch to CISA ICS advisories
   (ICSA), not only KEV.
4. ~~**`MAPPINGS.md`**~~ - generated in round 3 with an ATT&CK gap list; the 40
   techniques recorded in use with no hunt or detection are the next detection
   backlog.
4. **Indicator sets.** Parse CISA's STIX bundles (AA26-097A, AA23-335A,
   AA25-343A) and vendor GitHub IOC files into `artifacts/intel/iocs/` in code,
   keeping each publisher's role per value.

## Phase 2 - detections

- Numbered rule directories and the first packs, from the protocol
  `operations` tables and data-source `events`:
  - Suricata over passive capture: program download / upload, CPU stop and
    mode changes, firmware update and restart function codes per protocol;
    engineering-protocol sessions from hosts that are not engineering
    workstations; OT protocols crossing the IT/OT boundary.
  - Sigma over Windows EWS/HMI logs: engineering software launched by an
    unexpected parent, project files written or copied off the host,
    remote-access tools on HMIs.
  - YARA: publishers' rules for TRITON, INCONTROLLER, COSMICENERGY,
    Industroyer2, IOCONTROL and the 2025 wipers, vendored only after licence
    review.
- Hunts (`ICS-HUNT-`): new engineering-protocol talkers, writes outside
  maintenance windows, internet-facing PLC sessions from hosting providers
  (AA26-097A), HMI logins from unexpected geographies (AA25-343A), historian
  gaps that coincide with remote sessions.
- `MAPPINGS.md` generated from the records: ATT&CK for ICS coverage per
  platform, data source and pack.

## Phase 3 - collection, safely

- Declarative collection profiles per platform, in order of volatility, with
  each step's `impact` enforced: `passive` and `read-only` steps run by
  default; `online-vendor-tool` steps print instructions for an engineer to
  perform in the vendor's own software rather than automating them;
  `process-risk` steps are never automated.
- Windows EWS/HMI triage target list (vendor software logs, project files,
  recent-project lists, remote-access tool artifacts).
- Logic comparison: ingest an exported project or upload and diff it against a
  known-good copy (`logic_compare` detections). Start with formats that export
  to text (Rockwell L5X, Siemens TIA Openness/SIMATIC AX exports, PLCopen XML).

## Phase 4 - presentation

- Static site generator (port the edge-dfir-toolkit approach: one
  self-contained page, client-side libraries, never committed).
- Audience variants for briefings: executive (consequence and investment),
  SOC (what to alert on), plant engineering (what to preserve and not touch).
