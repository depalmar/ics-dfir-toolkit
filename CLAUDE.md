# Project context

Read this before working in this repository. It exists so a session starts
with the rules already loaded instead of rediscovering them.

## What this is

A DFIR knowledge base and (later) triage toolkit for industrial control systems
and operational technology. It is the ICS sibling of
[edge-dfir-toolkit](https://github.com/depalmar/edge-dfir-toolkit) and
[ai-dfir-toolkit](https://github.com/depalmar/ai-dfir-toolkit), and follows
their discipline: every claim cites a primary source, confidence reflects
provenance, and a gap is stated rather than filled with a guess.

Layers (built in this order):

- `artifacts/` - the knowledge base: platform catalog (`ICS-NNNN`), protocols
  (`ICS-PROTO-`), visibility data sources (`ICS-DS-`), threat actors
  (`ICS-TA-`), malware (`ICS-MAL-`), indicator sets (`ICS-IOC-`), incidents
  (`ICS-INC-`), hunts (`ICS-HUNT-`), detection packs (`ICS-PACK-`), hardening
  and response playbooks, the KEV watch, their schemas and the validator.
- Numbered `NN-*` directories - Sigma, YARA and Suricata rules, one directory
  per platform family or cross-platform domain. Glob them as `[0-9][0-9]-*`.
- `icstriage/` - the triage engine, started with its first component: offline
  logic comparison (`icstriage/logic/`, see `docs/logic-compare.md`).
  `collectors/profiles/` - not started; see `docs/ROADMAP.md`.

Reserved and allocated ids are in `docs/ID_REGISTRY.md`. Research notes that
records were built from are in `docs/research/<date>/`.

## Commands

```bash
python artifacts/scripts/validate.py              # the gate; never commit while it fails
python artifacts/scripts/mappings.py [--check]     # MAPPINGS.md is generated; CI checks it is current
python artifacts/scripts/build_site.py [--check]   # docs/site/index.html (Pages builds it; never commit it); --check writes nothing
python -m icstriage logic-diff --baseline good.L5X --current suspect.L5X [--format md|json] [--out r.md]   # offline; exit 0/10/1
python -m pytest -q tests/                         # offline tests for the scripts
python artifacts/scripts/check_quotes.py [--only f.yml] [--out r.md]   # every quote vs its live page; reports, never edits
python artifacts/scripts/advisory_watch.py [--kev f.json] [--upstream] [--draft]   # KEV vs packs and ledger; reports, never edits
python artifacts/scripts/parse_iocs.py ...         # publisher indicator files to YAML, run with python3 -I
python3.11 -m py_compile <changed .py>             # CI runs 3.11
```

Regenerate `MAPPINGS.md` whenever a record's `attack` ids, a pack or a rule
changes. Its "Gaps" section (techniques recorded in use with nothing hunting or
detecting them) is the detection backlog. The monthly `quote-check` and weekly
`advisory-watch` workflows open issues; they never commit. A source the runner
cannot fetch is reported as unfetched, never as changed.

## Rules that are not negotiable

**Safety before evidence.** In OT the process outranks the investigation.
Collection methods declare an `impact`: `passive` (copies only - TAP/SPAN,
logs already forwarded, backups), `read-only` (a vendor-documented read path
that changes no state), `online-vendor-tool` (going online with engineering
software; read-only in intent but the same session can download or force, so
operations must approve it), `process-risk` (anything that can change a
controller's mode, restart it, or load the network - active scans, debug
reads; break-glass only). Never rate a method lower than it is. Active
scanning of a live control network is `process-risk`, always.

**Not evaluated is not passed.** A detection that lacks the evidence it needs
says so. A controller whose logic was not compared with a known-good copy has
not been shown to be unmodified.

**Never call a system clean.** The lowest verdict is `NO-INDICATORS-FOUND`.
Controllers cannot be imaged the way hosts can; every report carries that gap.

**Confidence reflects provenance.** `high` = vendor-documented, a government
cyber authority's own words, or verified on a device; `medium` = multiple
independent sources; `low` = single-source or inferred and **must** carry
`unverified: true` (the validator checks every depth). A government authority's
publication (CISA, NSA, FBI, DOE, EPA, NCSC-UK, ASD's ACSC, CCCS, BSI, ANSSI,
CERT-UA and joint advisories they sign) is `high` for what that authority
recommends or reports, but documents a vendor's menu path, log format or file
location only where it prints them. Press is a lead, never the basis for
`high`. A record whose every source came through a summarising fetch is
`unverified` until someone reads the page directly.

**Omit rather than guess.** A missing artifact path, event id or menu location
is honest. A guessed one becomes somebody's failed collection during an
incident - and in OT, possibly somebody's process upset.

**Quote, do not paraphrase, the claim a record rests on.** `sources[].quote` is
verbatim from the page. `read: direct` means the quote was copied from the
rendered page; `read: summariser` means it came through a summarising fetch and
must be checked. Never "correct" a claim from memory - re-read the live primary
page (Firecrawl renders vendor knowledge bases and CISA advisories).

**Ids are permanent.** `ICS-0003` and `ICS-MAL-0005` never change meaning. New
entries take the next free id from `docs/ID_REGISTRY.md`. Files are named
`<id>-<slug>.yml`; the validator enforces it. A referenced id that is reserved
in the registry but not written yet is a pending record (a warning that doubles
as the coverage-gap list); any other unknown id fails.

**Detections are Sigma, YARA and Suricata only.** Suricata is allowed here
(unlike edge-dfir-toolkit) because passive network capture is the primary
evidence source for controllers that log nothing. No SPL, KQL, XQL, ES|QL or any
vendor dialect, in rules or hunts. Every rule file is linked from the pack,
hunt or malware record it expresses, or tagged `ics-dfir.standalone`.

**Published rules are pointed to before they are vendored.** A publisher's YARA
or Snort rule goes in `published_rules` with its licence. Vendor it only after
the licence is read, reproduce it exactly as published, and keep the licence in
the file and in NOTICE. Copyleft content (e.g. EUPL) is pointed to, not copied.

**Defensive content only.** No working exploit, no attack tool, no protocol
command sequence that would stop a controller or change a setpoint. Describing
which function code a malware family used (so a defender can detect it) is
fine; packaging it so it can be replayed is not. Do not reproduce vendor
default credentials; a government advisory's own instruction to change a named
default (CISA on Unitronics' "1111") is quoted as the authority wrote it.
Indicator values (addresses, domains, hashes) live only in `artifacts/intel/iocs/`
sets parsed from the publisher's file - never retyped into prose.

**Synthetic data only.** Fixtures and examples use documentation address
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and placeholder names.

**Do not name the maintainer's former employers anywhere in the repository.**
The publisher is DePalma Research LLC; credit it and Raymond DePalma only in
the README, NOTICE, CITATION and the generated site's footer, which reads the
credit from NOTICE and the two LinkedIn links from the README at build time
(the generator never hardcodes them). Citing a vendor's or research team's
publication as a source is not naming an employer.

## Threat intel rules

**Attribution is reported, never computed.** An actor record is one reporter's
cluster. `link_confidence` is ours and measures provenance (one reporting
party is `medium`, however authoritative); `stated_confidence` is the
attributing party's words, verbatim. Dragos's "shares technical overlaps with"
is an alias with `equated: false`, not a merge. ELECTRUM is not Sandworm;
VOLTZITE is not Volt Typhoon; BAUXITE is not CyberAv3ngers - each is its own
record, linked by aliases.

**Motivation and stage come from the reporter.** Do not upgrade "hacktivist"
to "state" or Stage 1 to Stage 2 because it seems likely.

**Attribute the action to the right actor.** Malware behaviour, exploit-script
behaviour and hands-on-keyboard behaviour are different claims; a hacktivist's
claim of impact is not a confirmed impact. Name the one the reporter names, and
say "claimed" when only the actor says it.

**Indicators are parsed, never retyped.** `artifacts/intel/iocs/` sets come
from the publisher's own file (CISA STIX/CSV, a vendor's GitHub), parsed in
code from a copy in its own directory, run with `python -I`. Keep the
publisher's role for each value; most published addresses are compromised
third parties or VPN exits. Store values refanged. VirusTotal is links only.

**A malware family with no detection states its gap.** `detections: []`
requires `gap`.

**Hunts never touch a controller.** They test data the owner already keeps:
passive ICS capture, flow, firewall, remote-access, Windows, historian, alarm
and controller audit logs. Each quotes its source.

**Response playbooks are guidance, not automation.** Order is fixed: safety
first (agree the safe state and manual fallback with operations), preserve,
contain, rotate credentials, eradicate, recover, verify. Every playbook has a
`do_not` list. Restoring a controller from a backup that was itself taken
after compromise reinstalls the attacker's logic.

**Hardening controls cite their source** and give the vendor's own syntax or
menu path, or say none is published. A CVE or campaign goes in `blunts` only
when the source ties it to the control. Note the operational impact (outage,
vendor support, safety case) where the source does.

**Exploited CVEs are triaged, not ignored.** `artifacts/watch/kev-watch.yml`
maps ICS vendors to KEV `vendorProject`/`product` regexes and keeps a dated
decision for every KEV entry on a watched platform. `deferred` means not yet
read - never use it for a decision you made.

**Exploitation dates are quoted, never inferred.** `artifacts/intel/exploitation.yml`
follows edge-dfir-toolkit's rules: primary sources only, `earliest` only as
precise as the source, and `earliest_words` must sit inside the quote.

## Logic comparison rules

`icstriage logic-diff` reads files an engineer exported; it never talks to a
controller. Element and attribute names come only from the format's public
documentation (Rockwell 1756-RM014, PLCopen TC6 XML, the Siemens TIA Portal
Openness system manual and FAQ 109480446 for SimaticML); anything undocumented or
encrypted is compared by hash and reported as such, never parsed by guess.
Input files are hostile: DOCTYPE and ENTITY declarations are refused before
parsing, and size and element counts are capped. Documentation-only changes
never change the verdict. Fixtures are synthetic; never commit a real project
file.

## Where the sharp edges are

- Most ICS evidence is not on the controller. Diagnostic buffers are small
  ring buffers, many PLCs keep no audit log at all, and the logic itself is the
  best artifact - which means a trusted known-good copy is a precondition, not
  a nice-to-have.
- Windows engineering workstations and HMIs are OT assets even though they look
  like IT. Dragos notes OT incidents get misclassified as IT-only for exactly
  this reason.
- Vendor documentation for log formats and menu paths often sits behind
  customer portals (Rockwell, Siemens SIOS, Schneider). If a page needs a login
  to verify, the record stays `unverified`.
- CVSS for ICS is frequently wrong (Dragos found a quarter of 2025 scores
  incorrect). Do not prioritise from CVSS alone.
