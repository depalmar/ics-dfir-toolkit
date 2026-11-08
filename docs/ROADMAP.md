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

- **Pending records** - referenced by other records but not written; the
  validator lists them as `pending record` warnings:
  - Platforms: ICS-0002 MicroLogix (no public source on its logging found),
    ICS-0008 OMRON Sysmac, ICS-0009 CODESYS runtime, ICS-0012 historian,
    ICS-0014 substation RTU/IED (referenced nine times - highest priority),
    ICS-0015 OPC UA servers.
- **New intel to record:** CISA AA26-231A (August 2026, Siemens S7-specific),
  found by the hardening pass and not yet covered by an incident or actor
  record.
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
2. **`check_quotes.py`** (port from edge-dfir-toolkit): re-fetch every quoted
   source and report quotes that are gone; a monthly workflow opens an issue.
3. **KEV triage.** Turn every `deferred` entry in `artifacts/watch/kev-watch.yml`
   into a decision with a basis, and add an `advisory_watch.py` that compares
   the KEV feed (and CISA ICS advisories) against the ledger weekly.
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
