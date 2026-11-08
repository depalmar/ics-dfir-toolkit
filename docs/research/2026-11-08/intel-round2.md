# Intel round 2 - AA26-231A and parsed indicator sets - research notes

Date: 2026-11-08. Stream: record CISA AA26-231A and turn publishers' own indicator
files into `ICS-IOC-` records.

Records built from these notes:

- `artifacts/intel/incidents/ICS-INC-0013-siemens-s7-plc-reconnaissance-aa26-231a.yml`
- `artifacts/intel/iocs/ICS-IOC-0001-cisa-aa26-097a-plc-exploitation.yml` (21 IPv4)
- `artifacts/intel/iocs/ICS-IOC-0002-eset-dynowiper-poland-2025.yml` (7 SHA-1, 7 SHA-256, 7 MD5, 1 IPv4)
- `artifacts/intel/iocs/ICS-IOC-0003-eset-industroyer-2016.yml` (9 SHA-1, 9 SHA-256, 9 MD5, 5 IPv4)
- `artifacts/scripts/parse_iocs.py` (the parser; stdlib + PyYAML)

Pages were read with Firecrawl (`firecrawl_scrape`, markdown; PDFs with the pdf
parser). "Direct" means the quote was copied from that rendered page.

## AA26-231A

| Source | URL | Read | Notes |
| --- | --- | --- | --- |
| NSA, CISA, FBI, DOE, EPA - AA26-231A Defending Against an Active Threat to Siemens S7 Series PLCs (19 Aug 2026) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a | direct | Activity, targeted models, ATT&CK v19 and D3FEND tables, detection opportunities, hardening. No revision since release. |
| Same advisory, PDF edition | https://media.defense.gov/2026/Aug/18/2003983494/-1/-1/1/CSA_ACTIVE_THREAT_TO_SIEMENS_S7_SERIES_PLCS.PDF | direct (PDF) | Same text as the page, marked TLP:CLEAR ("Recipients may share this information without restriction."). Its D3FEND table misprints "snap7.d11". |
| Siemens ProductCERT SSB-104599 (V1.3, 21 Aug 2026) | https://cert-portal.siemens.com/productcert/html/ssb-104599.html | direct | Lists AA26-097A and AA26-231A as successive developments; does not tie their actors together. |

What it is: a threat-activity advisory, not purely a vulnerability bulletin.
Quotes the records rest on:

- "The threat actors are conducting reconnaissance and capability development
  against U.S.-based Siemens PLC installations using AI-generated exploitation
  scripts disguised as legitimate monitoring tools."
- "These tools provide read/write access to Siemens S7 Series PLC memory,
  configuration data, and ladder logic programs via the S7comm protocol."
- "The authoring agencies assess this activity pattern is likely intended as
  persistent reconnaissance in targeted sectors and facilities to develop
  capabilities and prepare to cause operational effects against critical
  infrastructure."
- Impacts are conditional only: "Unauthorized access to PLCs could result in:".

Decisions:

- **Incident: yes** (ICS-INC-0013). The activity is described, so it is more
  than a mitigation bulletin. `physical_consequence: none-reported`, because the
  advisory lists only potential impacts.
- **Actor: no.** No group, nationality, sponsor or motivation is named, and it
  does not say whether one group or several are involved. Checked
  `artifacts/intel/actors/`: no record is the same cluster. ICS-TA-0019
  (AA26-097A) is an unnamed group too, but no source equates the two, so
  nothing links them.
- **Malware: no.** The snap7-based scripts are unnamed, and snap7 is a
  legitimate library.
- **CVE / KEV: none.** The advisory says only "various critical and high
  severity known vulnerabilities".
- **Indicators: none published.**

## Indicator files parsed

Every file sits in its own directory under the session scratchpad
(`ioc-src/<name>/`) and was parsed by `parse_iocs.py` run with `python3 -I` from
the repository root. sha256 values are of the copies parsed.

cisa.gov refused connections from this session's network (proxy 403 on
CONNECT). The CISA files were therefore taken from Firecrawl's `rawHtml`. The
harness saved each result to disk, and a script wrote the `rawHtml` field
unchanged; no file was retyped. Firecrawl may re-serialise a body, so a digest
can differ from CISA's own bytes. Each copy matches the size CISA lists.

| File | URL | Bytes | sha256 |
| --- | --- | --- | --- |
| AA26-097A STIX 2.1 JSON, July 22, 2026 | https://www.cisa.gov/sites/default/files/2026-07/AA26-097A.stix_.json | 29829 (CISA: 30 KB) | 46561b15550182c692c55c48565fd6758e9664665ecc6e0f402df713eb46dd6a |
| AA26-097A STIX 1.x XML, July 22, 2026 | https://www.cisa.gov/sites/default/files/2026-07/AA26-097A.stix_.xml | 29583 (CISA: 29 KB) | 3ed5b41f1db41d77f91bb569528725089a514fd1606dd7325aed6da1704e435c |
| AA26-097A STIX 2.1 JSON, April 7, 2026 | https://www.cisa.gov/sites/default/files/2026-04/AA26-097A.stix_.json | 12154 (CISA: 12 KB) | 3f23f8c8b917abad5050c4991714434c53cf304842abdf8ffa87de5d4c2a63a8 |
| AA26-097A STIX 1.x XML, April 7, 2026 | https://www.cisa.gov/sites/default/files/2026-04/AA26-097A.stix_.xml | 36834 (CISA: 35.97 KB) | fde78a68516c1ccbef84744f9718870be6c49906dc01f15e016c5cf6512f0f55 |
| AA26-097A advisory page, rendered HTML (Tables 1-2) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a | 172763 | 0170882a826e25b7d1c61e048214e55d86b5c0452cfee9b34064db1fc365f657 |
| ESET dynowiper/README.adoc @825b826 | https://raw.githubusercontent.com/eset/malware-ioc/825b826c5cbffcc1e59c16581ffdf7d527e8b695/dynowiper/README.adoc | 1273 | 766ef2c3d41f4d2929193d6d227e399d946677450419a4746214f111bf677ccd |
| ESET dynowiper/samples.sha1 | .../825b826c5cbffcc1e59c16581ffdf7d527e8b695/dynowiper/samples.sha1 | 287 | 005064e52a8ab7703e0d034627d4805c892e5b9eba35bc2fe1b9f1714e381697 |
| ESET dynowiper/samples.sha256 | .../825b826c5cbffcc1e59c16581ffdf7d527e8b695/dynowiper/samples.sha256 | 455 | dbc94905b4a6d4082027d4fb653199140ba9bcd657cb0d79e9320b89888f9b71 |
| ESET dynowiper/samples.md5 | .../825b826c5cbffcc1e59c16581ffdf7d527e8b695/dynowiper/samples.md5 | 231 | ce091f02c35e94c092af1ca9c5b1f97b4a24f8dab3050ff34800d71a52bbcef1 |
| ESET industroyer/README.adoc | .../825b826c5cbffcc1e59c16581ffdf7d527e8b695/industroyer/README.adoc | 968 | 80ba4f866000572051366527aecd928a921bf5efd3ef2049fa2dd5db910c5069 |
| ESET industroyer/samples.sha1 | .../825b826c5cbffcc1e59c16581ffdf7d527e8b695/industroyer/samples.sha1 | 369 | 07eebe3212643bff281b59a6109f064485e8771e698bf9c5ddf47a8e90fdcbfb |
| ESET industroyer/samples.sha256 | .../825b826c5cbffcc1e59c16581ffdf7d527e8b695/industroyer/samples.sha256 | 585 | 936ba6eb1b63b5cadc495c9f73316efc336effb3249f74b9607306729cb89296 |
| ESET industroyer/samples.md5 | .../825b826c5cbffcc1e59c16581ffdf7d527e8b695/industroyer/samples.md5 | 297 | 3d325152f2a3a92aebd8838344e647831699ecf89750fa1c2d5c0be86917f13b |
| ESET LICENSE (BSD 2-Clause) | .../825b826c5cbffcc1e59c16581ffdf7d527e8b695/LICENSE | 1300 | 995182e185856186fbbe49f150409ae026aa4cda7e94f83c6ed737cbb77fa9c7 |

Checks the parser enforces:

- AA26-097A: the July JSON, July XML and the page's Tables 1-2 hold the same 21
  addresses. April JSON = April XML = 8 addresses, all in July (Table 2), so
  one record covers both bundles.
- ESET: each `samples.sha1` equals the README's SHA-1 list. `samples.sha256`
  and `samples.md5` are not mapped to README rows by ESET, so they are kept
  with role `unknown`.

Roles, in the publisher's words:

- AA26-097A gives no role per address: "The FBI observed the threat actors
  using the IP addresses listed below in the specified time frames." The
  general line "The actors used leased, third-party hosted infrastructure" is
  not tied to any address. All 21 are `unknown`.
- ESET DynoWiper (WeLiveSecurity, 30 Jan 2026, read directly):
  - DynoWiper, rsocx and Rubeus files are `actor-controlled`: the attackers
    deployed them or tried to.
  - The two ZOV wiper files are `actor-controlled`, but from ESET's Ukrainian
    comparison cases, not from Poland.
  - 31.172.71.5 is `compromised-infrastructure`: "This server is used by
    ProGame (progamevl[.]ru), a programming school for kids in Vladivostok,
    Russia, and was likely compromised."
- ESET Industroyer: the README SHA-1 values are `actor-controlled` (listed as
  Win32/Industroyer IoCs). The five C&C addresses are `unknown`, because "Most
  of the servers with these IP addresses were part of Tor network" and ESET
  does not say which.

Attribution discrepancy, recorded but not resolved:

- CISA's July STIX JSON has `indicates` relationships from all eight Table 2
  addresses to a threat-actor object "HYDROKITTEN", and from two of them
  (185.82.73.167, .168) also to "CYBER AVENG3RS".
- The report object also references threat-actor objects "BAUXITE",
  "Islamic Revolutionary Guard Corps", "APT Iran" and "Iranian-affiliated
  APT".
- None of this is in the advisory text, the April JSON or either XML file.
  The advisory names Hydro Kitten only as another name for CyberAv3ngers in its
  2023 history.
- ICS-IOC-0001 lists only ICS-TA-0019 and keeps the links in each indicator's
  context. Whether ICS-TA-0019's notes should mention them is for the
  maintainer.

## Rejected or not written

- **AA23-335A (CyberAv3ngers, Dec 2023): not written.**
  - CISA removed the indicators from the live advisory on Dec 18, 2024 ("The
    indicators provided in this advisory's initial publication have been
    removed as they are outdated"). It still links the STIX files with "These
    IOCs are from the original joint advisory published Dec. 1, 2023, and are
    not current."
  - Firecrawl returned both small files (STIX JSON 10.84 KB, XML 15.50 KB)
    inline, and they were never saved to disk. Writing them out would have
    meant retyping them.
  - The original-version PDF table
    (https://www.cisa.gov/sites/default/files/2023-12/aa23-335a-irgc-affiliated-cyber-actors-exploit-plcs-in-multiple-sectors-1.pdf)
    gives all five values (2 IPv4, MD5, SHA-1, SHA-256) Fidelity "Suspected"
    and describes each as "associated with Crucio Ransomware". That is a
    CyberAv3ngers-linked Soldiers of Solomon claim against Israeli servers, not
    the Unitronics PLC compromises.
  - Next step: fetch the STIX JSON from a host that can reach cisa.gov, then
    parse it (role `suspected`).
- **AA25-343A (pro-Russia hacktivists): no indicators published.** The page
  links only a PDF and has no indicator section.
- **ESET Industroyer2: not in eset/malware-ioc.** The repository (commit
  825b826, 2026-11-04) has `industroyer/` (2016) but no `industroyer2/`.
  `ua_wipers/` is the February 2022 HermeticWiper/IsaacWiper set and was not
  used. The 2016 Industroyer set was parsed instead (ICS-IOC-0003).
- **Wayback copies of CISA files: not used.** The session's permission
  classifier treated fetching an archive copy of a blocked host as routing
  around the block.
