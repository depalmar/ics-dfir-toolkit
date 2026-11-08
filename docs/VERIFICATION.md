# Verification log

Every correction to a sourced claim is recorded here: what the record said,
what the primary source actually says, who checked and how (direct read or
summariser), and the date. Re-read, do not remember: a correction made from
memory or from a summary is itself a claim that needs checking.

## Round 1 - 2026-11-08 (initial research)

Records were drafted from Firecrawl reads of primary pages. Quotes marked
`read: summariser` came through a search snippet or summarising fetch and must
be checked against the rendered page before the record can lose
`unverified: true`.

| Record | Field | Was | Now | Source | Read |
| --- | --- | --- | --- | --- | --- |
| ICS-0013 | artifacts[Teltonika log storage setting].sources[TRB143 Maintenance].read | summariser | direct (quote verbatim in the Logging Settings table) | https://wiki.teltonika-networks.com/view/TRB143_Maintenance | direct |
| ICS-0013 | artifacts[Teltonika log storage setting].confidence, unverified | low, unverified: true | medium, unverified removed (one vendor page, now read directly; page also confirms default RAM memory and an external syslog server field) | https://wiki.teltonika-networks.com/view/TRB143_Maintenance | direct |
| ICS-0011 | integrity_features[FactoryTalk View SE activity log].sources[FTALK-WP003].read | summariser | direct (quote verbatim in the 11.50 compliance table) | https://literature.rockwellautomation.com/idc/groups/literature/documents/wp/ftalk-wp003_-en-e.pdf | direct |
| ICS-0011 | integrity_features[FactoryTalk View SE activity log].confidence, unverified | low, unverified: true | medium, unverified removed (description checked: Diagnostics Setup local log and ODBC destinations, e-signature entries with old value, new value and approver are all in the same paper; one vendor source) | ftalk-wp003 (as above) | direct |
| ICS-0011 | artifacts[FactoryTalk View SE activity log].sources[FTALK-WP003].read | summariser | direct (quote verbatim, "Set up re-verification of operator identity" section) | ftalk-wp003 (as above) | direct |
| ICS-0011 | artifacts[FactoryTalk View SE activity log].confidence, unverified | low, unverified: true | medium, unverified removed (Message Routing figure shows the Audit category routed to Local Log and ODBC Database) | ftalk-wp003 (as above) | direct |
| ICS-0011 | notes | FactoryTalk View SE "read through a summarising fetch" | white paper re-read directly; one vendor source, so medium | ftalk-wp003 (as above) | direct |
| ICS-0010 | artifacts[PEData.plf].sources[Chan and Chow].read | summariser | direct (quote verbatim, section 3.2) | https://inria.hal.science/hal-01614856/file/434671_1_En_7_Chapter.pdf | direct |
| ICS-INC-0010 | sources[CISA Internet Exposure Reduction Guidance].read | summariser | direct (quote verbatim; page revision date 21 August 2026) | https://www.cisa.gov/resources-tools/resources/exposure-reduction | direct |
| ICS-INC-0010 | victim, notes | "read through a search summary" / "should be checked against the page" | provenance qualifier removed; notes record the direct re-read | https://www.cisa.gov/resources-tools/resources/exposure-reduction | direct |
| ICS-INC-0006 | sources[Dragos intelligence brief landing page].read | summariser | direct (quote verbatim). Record stays low and unverified: every source is Dragos relaying CSSC, which is unrelated to the read method | https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology | direct |
| ICS-INC-0006 | date_basis | "read through a search summary" | "read directly" | https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology | direct |
| ICS-INC-0011 | sources[Colonial media statement].read | summariser | direct (quote verbatim in the Monday 10 May 2021, 12:25 p.m. update) | https://www.colpipe.com/news-insights/media-resources/post/media-statement-update-colonial-pipeline-system-disruption/ | direct |
| ICS-INC-0011 | date_basis | statement "says it learned of the attack on a Friday ... No source read gives the exact day" | quotes the statement: "On May 7, the Colonial Pipeline Company learned it was the victim of a cybersecurity attack". Claim corrected: the page gives the day and does not say "Friday" | colpipe.com statement (as above), Saturday 8 May 12:30 p.m. update | direct |
| ICS-INC-0011 | consequence_detail, notes | "(search summary)"; "exact dates ... appear only in secondary sources and are not used" | "(media statement, 10 May 2021 update)"; notes say the primary statement gives 7 May and that the date field was left at month precision in this pass | colpipe.com statement (as above) | direct |
| ICS-DS-0012 | sources[ALEOS 4.14.0 guide for AirLink RV55].read | summariser | direct (quote verbatim, "Configure Logs" step 1; Figure 15-8 caption reads "ACEmanager: Admin > Log > Configure Logging") | https://www.communica.se/sierrawireless/41113782_ALEOS%204.14.0%20Software%20Configuration%20User%20Guide%20for%20AirLink%20RV55_r2.pdf | direct |
| ICS-DS-0012 | enable, gaps | ALEOS guide "seen only as a search snippet, not read directly" | "distributor-hosted copy, read directly"; gap now says only the log configuration screen was read | ALEOS guide (as above) | direct |
| ICS-DS-0009 | sources[CPU 31xC and CPU 31x Technical specifications].read | summariser | direct (quote verbatim, web server "Diagnostic buffer" page description) | https://cache.industry.siemens.com/dl/files/906/12996906/att_70325/v1/s7300_cpu_31xc_and_cpu_31x_manual_en-US_en-US.pdf | direct |
| ICS-DS-0009 | retention, gaps | "a Siemens manual (search snippet, not read directly)"; "S7-300/400 buffer size and retention were seen only in a search snippet" | names the manual's web server section and the 100-entry intervals; gap narrowed to S7-300 retention across power loss and S7-400 buffer size (not read) | S7-300 manual (as above) | direct |
| ICS-DS-0011 | sources[PI AuditViewer].read | summariser | direct (quote verbatim) | https://docs.aveva.com/bundle/pi-server-s-da-reference/page/1221516.html | direct |
| hardening/remote-access-gateways | controls[gw-https-ssh-only].sources[Teltonika Security Guidelines].read | summariser | direct (matches once the bold/italic markup around "HTTPS, SSH" is removed) | https://wiki.teltonika-networks.com/view/Security_Guidelines | direct |
| hardening/remote-access-gateways | notes | explains why the Teltonika quote was marked summariser | records the direct re-read | https://wiki.teltonika-networks.com/view/Security_Guidelines | direct |
| ICS-PROTO-0012 | sources[ModiPwn (Armis)].quote, read | "...and it adds authentication" (cut mid-sentence), summariser | full sentence "...adds authentication, binary data transfer, firmware updates, and additional features to the basic Modbus protocol.", direct | https://www.armis.com/research/modipwn/ | direct |
| ICS-PROTO-0003 | sources[SIOS 109955142].read | summariser | direct (quote verbatim; FAQ dated 9/28/2026) | https://www.industry-mobile-support.siemens-info.com/en/article/detail/109955142 | direct |
| ICS-PROTO-0003 | authentication.detail | "A Siemens support page (search snippet, not read directly)" | "A Siemens support FAQ (109955142, read directly)" | SIOS 109955142 (as above) | direct |
| ICS-PROTO-0005 | sources[developer guide].quote, read | "...PCCC encapsulated messages to access controller" (cut mid-sentence), summariser | full sentence ending "to access controller data organized in PLC-5® style.", direct | https://www.rockwellautomation.com/content/dam/rockwell-automation/sites/downloads/pdf/developerguide.pdf | direct |
| ICS-PROTO-0005 | sources[Technology Licensing Developer How-to Guides].read | summariser | direct (quote verbatim) | https://www.rockwellautomation.com/en-us/company/news/articles/technology-licensing-developer-how-to-guides.html | direct |
| ICS-PROTO-0005 | transport notes, notes | developer guide "(search snippet, not read directly)"; DF1 manual "(title only; not read)" | developer guide read; DF1 manual described on the How-to page, manual itself not read; record stays low and unverified because authentication is a placeholder | both Rockwell pages (as above) | direct |
| ICS-PROTO-0014 | sources[nhimg.org guide].read | summariser | direct (quote verbatim). Record stays low and unverified | https://nhimg.org/mitsubishi-and-omron-plc-security-guide | direct |
| ICS-PROTO-0014 | authentication.detail, notes | "third-party guide (search snippet)" | names NHI Mgmt Group; notes quote the page's own statement that it was "Researched and written by the NHI Mgmt Group editorial team using AI tools" | nhimg.org (as above) | direct |
| ICS-PROTO-0020 | sources[SLMP Reference Manual].quote, read | "MC protocol. An abbreviation ... or a programmable" (table term merged into the quote, cut mid-sentence), summariser | exact Terms-table description: "An abbreviation for the MELSEC communication protocol. This protocol is used to access ... HMI (Human Machine Interface).", direct (pages 1-30 of 242 read) | https://dl.mitsubishielectric.com/dl/fa/document/manual/plc/sh080956eng/sh080956engl.pdf | direct |
| ICS-PROTO-0020 | sources[nhimg.org guide].read | summariser | direct (quote verbatim). Record stays low and unverified | https://nhimg.org/mitsubishi-and-omron-plc-security-guide | direct |
| ICS-PROTO-0020 | transport[tcp].notes | "no source read stated the transport or a default port" | manual chapter 3 gives the communication procedure for TCP/IP and UDP/IP; no default port in the pages read. Claim corrected | SLMP manual (as above) | direct |
| ICS-PROTO-0020 | authentication.detail, notes | "SLMP Reference Manual was located but not read" | first 30 pages read, authentication content not; notes record that the table of contents lists a "Remote Password" (Lock/Unlock) section that was not read and is not reconciled with "none"; AI-assisted provenance of nhimg.org noted | SLMP manual, nhimg.org (as above) | direct |
| ICS-PROTO-0011 | sources[Software Toolbox].quote, read | "...a specific COM server is listening" (cut mid-sentence), summariser | "...is listening on.", direct | https://softwaretoolbox.com/resources/what-is-dcom | direct |
| ICS-PROTO-0011 | sources[TDL].read | summariser | direct (quote verbatim) | https://www.tdl-ia.com/insights/opc-da-dcom-errors-windows-hardening-path-to-opc-ua.html | direct |
| ICS-PROTO-0011 | transport notes, authentication.detail | "third-party explanation via search snippet"; "third-party pages (search snippets only)" | names the third-party vendor pages, read directly; Microsoft's documentation still not read, so the record stays low and unverified | both pages (as above) | direct |
| ICS-PROTO-0017 | sources[Security Classes for PROFINET (PI North America)].read | summariser | direct (quote is verbatim inside "Besides, Security Class 3 ensures ...") | https://us.profinet.com/security-classes-profinet/ | direct |
| ICS-PROTO-0017 | sources[PROFINET Security (profinet.com)].read | summariser | direct (quote verbatim) | https://www.profinet.com/profinet-explained/security | direct |
| ICS-PROTO-0017 | authentication.detail, encryption | "Not verified directly ... per search snippets of PI pages"; "(PI, via snippet)" | read directly; detail now says the PI North America page titles the classes "coming soon" and calls them proposed. Claim qualified | both PI pages (as above) | direct |

All 22 `read: summariser` quotes present at the start of this pass (17 files)
were re-read on 2026-11-08 with a Firecrawl scrape of the live page or PDF
(PDFs parsed in full except the SLMP manual, pages 1-30). Every quote was
found: 17 verbatim as recorded, 3 verbatim but cut mid-sentence and
completed from the page (ModiPwn, Rockwell developer guide, Software Toolbox),
1 matching once markup is removed (Teltonika), and 1 rewritten to the page's
exact table text (SLMP). None remains summariser-only. Three claims in record prose were
corrected (ICS-INC-0011 date basis, ICS-PROTO-0020 transport, ICS-PROTO-0017
"proposed" qualifier). Records that stay `low`/`unverified: true` do so for
reasons other than the read method: ICS-INC-0006 (single reporter),
ICS-PROTO-0005 (authentication placeholder), ICS-PROTO-0011 (no Microsoft
source), ICS-PROTO-0014 and ICS-PROTO-0020 (authentication rests on an
AI-assisted third-party guide).

Not in scope of this pass (prose mentions of search snippets with no
`sources[].quote` behind them): ICS-0005 notes on controller web pages,
`artifacts/watch/kev-watch.yml` (Field Effect post) and
`artifacts/intel/exploitation.yml` (Field Effect blog, listed as secondary).

## Round 5 - 2026-11-08 (consistency audit)

Every record under `artifacts/` (except `visibility/`, being edited in
parallel) was read against CLAUDE.md: confidence against provenance,
attribution rules, incident consequences against their quotes, cross-record
symmetry, dates and ids, hardening and response structure, prohibited content.
Quotes were not re-fetched (that is `check_quotes.py`'s job), so "Read" below
means the record and the quotes already in it were read, not the live page.
Confidence was only lowered, never raised; back-links were added only where
the forward record's own quoted source supports them.

| Record | Field | Was | Now | Source | Read |
| --- | --- | --- | --- | --- | --- |
| ICS-MAL-0006 | confidence | high | medium: both quotes come from one ESET post, a single reporting party; CERT-UA is named in `reported_by` but not quoted, so no government or vendor source carries the record | https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/ | record only |
| ICS-MAL-0012 | confidence | high | medium: Dragos is the only reporting party (two quotes, same post); a security vendor's analysis is researcher provenance, not vendor documentation of its own product | https://www.dragos.com/blog/responding-to-solarwinds-compromise-in-industrial-environments/ | record only |
| ICS-MAL-0015 | confidence | high | medium: Cisco Talos and Dragos are two independent researchers, which CLAUDE.md rates medium; no vendor or government source | https://blog.talosintelligence.com/pathwiper-targets-ukraine/ | record only |
| ICS-0008 | artifacts[Network traffic to the CPU Unit].confidence, notes | high | medium: the behavioural claims (FINS sweeps, HTTP POSTs, telnet activation) rest on Mandiant's INCONTROLLER report alone; reason added to notes | https://cloud.google.com/blog/topics/threat-intelligence/incontroller-state-sponsored-ics-tool/ | record only |
| ICS-0001 | protocols, datasources | [ICS-PROTO-0004]; no ICS-DS-0013 | + ICS-PROTO-0005 (Rockwell developer guide quoted on ICS-PROTO-0005: the Logix family supports PCCC encapsulated messages); + ICS-DS-0013 (ICS-DS-0013 already listed ICS-0001; 1756-UM900 and PN1550, quoted on ICS-0001 and hardening/rockwell-logix, document 5580/5590 syslog) | Rockwell developerguide.pdf; PN1550 | record only |
| ICS-0005 | protocols | no ICS-PROTO-0010 | + ICS-PROTO-0010 (EIO0000001999, quoted on ICS-0005, lists OPC-UA connection events in M580 syslog; ICS-PROTO-0010 already listed ICS-0005) | EIO0000001999 | record only |
| ICS-PROTO-0001 | platforms, malware | [ICS-0005]; no malware field | + ICS-0002 (1766-UM001: Modbus TCP on Channel 1, quoted in ICS-0002 notes), ICS-0006 (Unitronics SB 305 Modbus quote in hardening/unitronics), ICS-0007 (Tricon v10 guide: Modbus masters); malware [ICS-MAL-0007, ICS-MAL-0009] (Mandiant CODECALL Modbus; Dragos FrostyGoop quote) | as named | record only |
| ICS-PROTO-0002 | malware | no malware field | [ICS-MAL-0001] (Symantec dossier: s7otbxdx.dll block read/write interception, quoted on ICS-0004 and ICS-0010) | Symantec W32.Stuxnet Dossier | record only |
| ICS-PROTO-0004 | platforms | [ICS-0001] | + ICS-0002 (1766-UM001 EtherNet/IP), ICS-0005 (EIO0000001999 EtherNet/IP connection events), ICS-0008 (W503: event logs read over the built-in EtherNet/IP port) | as named | record only |
| ICS-PROTO-0005 | platforms, notes | [ICS-0001]; notes said MicroLogix had no source | + ICS-0002; notes corrected: ICS-0002's 1766-UM001 firmware history lists "ST file type for all PCCC commands" | 1766-UM001 | record only |
| ICS-PROTO-0006 | platforms | [ICS-0014] | + ICS-0002 (1766-UM001: DNP3 over IP can be enabled on Channel 1) | 1766-UM001 | record only |
| ICS-PROTO-0007 | malware | no malware field | [ICS-MAL-0004, ICS-MAL-0006, ICS-MAL-0008] (ESET 2017, ESET 2022 and Mandiant quotes on those records name IEC 60870-5-104) | as named | record only |
| ICS-PROTO-0008 | malware | no malware field | [ICS-MAL-0004] (ESET quote names IEC 61850) | ESET Industroyer | record only |
| ICS-PROTO-0010 | malware | no malware field | [ICS-MAL-0007] (CISA AA22-103A quote names OPC UA servers) | AA22-103A | record only |
| ICS-PROTO-0011 | malware | [ICS-MAL-0002] | + ICS-MAL-0004 (ESET quote names OPC DA) | ESET Industroyer | record only |
| ICS-PROTO-0014 | malware | no malware field | [ICS-MAL-0007] (Mandiant OMSHELL FINS, quoted on ICS-0008) | Mandiant INCONTROLLER | record only |
| ICS-PROTO-0015 | malware | no malware field | [ICS-MAL-0007] (AA22-103A: brute force "using CODESYS ... via UDP port 1740", quoted on ICS-0009) | AA22-103A | record only |
| ICS-TA-0002 | malware, notes | [ICS-MAL-0004] | + ICS-MAL-0015 (Dragos 2026 Year in Review, quoted on ICS-MAL-0015: "PathWiper linked to ELECTRUM appeared in the wild"); notes say why ICS-MAL-0013/0014 are not added | Dragos Year in Review | record only |
| ICS-TA-0016 | malware, notes | [] | [ICS-MAL-0016] (Dragos PYROXENE page: "destructive wiper malware (BLUERABBIT)"; Microsoft: GigaWiper is tracked as BLUERABBIT; both quoted on ICS-MAL-0016) | Dragos; Microsoft | record only |
| ICS-PACK-0004 | malware | absent | [ICS-MAL-0016] (that record's `detections` names this pack's ews-hmi-security-log-cleared; Microsoft describes command 19 clearing event logs) | Microsoft GigaWiper | record only |
| MAPPINGS.md | generated | stale after the pack change | regenerated with `mappings.py` | - | - |

Found but not changed (judgment needed; fields outside this pass's remit or
the forward record's sources do not settle it): ICS-INC-0001 lists ICS-TA-0002
and says Dragos attributes 2015 to ELECTRUM, but no quoted Dragos text says so
and ICS-TA-0002 does not list it; ICS-MAL-0014 lists ICS-TA-0001 although ESET
attributed only DynoWiper, and its CERT Polska quote ("identical to that
employed in the attack on the combined heat and power plant") reads as
describing DynoWiper; ICS-PACK-0005 claims ICS-MAL-0004 and ICS-MAL-0014 while
those records say "No pack yet" (`detections: []`); ICS-MAL-0010 reproduces a
vendor default credential pair in `artifacts`; ICS-MAL-0012's two reference
URLs point to a SolarWinds post, not an EKANS post; `kev-watch.yml` still
carries the comment "No indicator sets exist yet"; ICS-INC-0011 `date` could
be narrowed to 2021-05-07 from the quoted statement.

## Round 5 - 2026-11-08 (quote check run 2 re-reads)

`check_quotes.py` run 2 (issue #7) reported 37 quotes as no longer on their
page; eight (justice.gov, cert.gov.ua) were bot-wall shells handled earlier.
The remaining 29 were re-read against the rendered page. Firecrawl answered
"insufficient credits" for every call in this pass, so the pages were fetched
with curl through a session environment that allows the source hosts, PDFs
were read with pdftotext, and JavaScript pages were rendered with Playwright.
The CODESYS whitepaper host refused every connection, so its three table rows
were checked against the Firecrawl-rendered copy of the same PDF fetched at
01:21 UTC today. Where the finding was about the checker, not the record, the
checker was changed (last rows). "Read" is how the live page was read today.

| Record | Field | Was | Now | Source | Read |
| --- | --- | --- | --- | --- | --- |
| ICS-MAL-0013 | references[CERT Polska].quote | `'Static Tundra' (Cisco), 'Berserk Bear' ...` (single quotes) | the page's `“Static Tundra” (Cisco), “Berserk Bear” (CrowdStrike), “Ghost Blizzard” (Microsoft), and “Dragonfly” (Symantec).` | https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/ | direct |
| ICS-MAL-0014 | references[CERT Polska].quote | two fragments spliced in the wrong order (`The wiper malware used ... the objective was opportunistic ...`) | the two sentences are adjacent on the page and are now quoted contiguously, in the page's order: `These actions were coordinated with the attacks on the energy-sector entities, but the objective was opportunistic and unrelated to the other targets. The wiper malware used was identical to that employed in the attack on the combined heat and power plant.` | cert.pl post (as above) | direct |
| ICS-MAL-0015 | references[Cisco Talos].quote | `we are calling 'PathWiper' ...` | `we are calling “PathWiper”. ...` (the page's double quotes and full stop); second fragment verbatim | https://blog.talosintelligence.com/pathwiper-targets-ukraine/ | direct |
| ICS-MAL-0015 | references[Dragos Year in Review].quote; `unverified`; summary | "PathWiper linked to ELECTRUM appeared in the wild.", record not unverified | quote kept; `unverified: true` at record level (the malware schema has no per-reference `unverified` or `notes`) and the summary says why: the landing page rendered in a browser carries no PathWiper or ELECTRUM text, only a download form for the gated report. Confidence was already medium. ICS-TA-0002's malware link to ICS-MAL-0015 rests on this quote | https://www.dragos.com/ot-cybersecurity-year-in-review | direct (Playwright render) |
| ICS-MAL-0011 | references[Claroty Team82].quote, second fragment | `... IOCONTROL leverages the MQTT protocol.` | `... IOCONTROL leverages the MQTT protocol as a dedicated IoT communication channel.` (the sentence did not end where the record cut it) | https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol | direct |
| ICS-MAL-0010 | references[Fuxnet NAND/UBI destruction and M-Bus flooding].quote, second fragment | `... with presumably random data.` | `... with presumably random data, effectively overloading the serial bus and the sensors.` | https://claroty.com/team82/research/unpacking-the-blackjack-groups-fuxnet-malware | direct |
| ICS-MAL-0012 | references[Dragos EKANS].quote | `('kills')` | `(“kills”)` as printed; second fragment and the Iran-links quote verbatim | https://www.dragos.com/blog/responding-to-solarwinds-compromise-in-industrial-environments/ | direct |
| ICS-MAL-0012 | published_rules[Dragos].notes | - | explains the URL: the slug reads "responding-to-solarwinds-compromise" but it is the canonical address Dragos serves its February 2020 post "EKANS Ransomware and ICS Operations" from (page `<title>` and canonical link; `sitemap-202002.xml` lists it; the December 2020 SolarWinds post lives at `/blog/industry-news-responding-to-solarwinds-compromise-in-industrial-environments`). No other EKANS URL exists on dragos.com (2020-2021 sitemaps searched; the only other hit is the later "misconceptions" post), so the URL is kept | Dragos post and sitemaps | direct |
| ICS-MAL-0008 | references[Mandiant].quote, second fragment | `... hosted by Rostelecom-Solar.` | `... hosted by Rostelecom-Solar, a Russian cyber security company.` | https://cloud.google.com/blog/topics/threat-intelligence/cosmicenergy-ot-malware-russian-response/ | direct |
| ICS-MAL-0007 | references[Mandiant].quote | `INCONTROLLER is comprised of three main components: TAGRUN ... CODECALL ... OMSHELL ...` (the tool names are cells of Table 1, not the rest of the sentence) | `INCONTROLLER is comprised of three main components: ... TAGRUN ... A tool that scans for OPC servers, ... ... CODECALL ... A framework that communicates using Modbus ... ... OMSHELL ... A framework with capabilities to interact with and scan some types of Omron PLCs via HTTP, Telnet, and Omron FINS protocol.` - each fragment a cell of Table 1, in order | https://cloud.google.com/blog/topics/threat-intelligence/incontroller-state-sponsored-ics-tool/ | direct |
| ICS-MAL-0016 | references[Dragos PYROXENE].quote | two fragments spliced in the wrong order (`Builds custom RAT ... During periods ...`) | page order: `During periods of heightened geopolitical tension ... against its victims. ... Builds custom RAT malware (MINIBIKE) and destructive wiper malware (BLUERABBIT).` | https://www.dragos.com/threat/pyroxene | direct |
| ICS-MAL-0016 | references[Microsoft GigaWiper].quote | flagged (closest 0.64) | unchanged: both fragments verbatim; only the " ... " splice defeated the checker | https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/ | direct |
| ICS-MAL-0013 | references[ESET].quote | flagged (0.68) | unchanged: both fragments verbatim | https://www.welivesecurity.com/en/eset-research/dynowiper-update-technical-analysis-attribution/ | direct |
| ICS-TA-0012 | references[Europol].quote | flagged (0.12) | unchanged: verbatim on the rendered page; a plain fetch gets "Loading application. Please wait.", so the host is now in `RENDERED_HOSTS` | https://www.europol.europa.eu/media-press/newsroom/news/global-operation-targets-noname05716-pro-russian-cybercrime-network | direct (Playwright render) |
| ICS-0014 | integrity_features[Relion 670 security events].confidence, unverified; artifacts[Relion 670 security events on the IED], artifacts[Fault / disturbance records]; notes | high; four 1MRK511399-UEN quotes `read: direct` | medium + `unverified: true` on the three items the four quotes support; quotes kept as read on 2026-11-08; notes explain that the publisher link (DocumentRevisionId=Y) now renders "We are sorry, but the linked document cannot open as it does not exist anymore" (the document was replaced, archived or withdrawn), so the quotes cannot be checked until the current revision is located. A plain fetch gets the JavaScript app shell, so the host is in `RENDERED_HOSTS` | https://publisher.hitachienergy.com/download?DocumentID=1MRK511399-UEN... | direct (Playwright render of the error page) |
| ICS-0010 | artifacts[PEData.plf].sources[Chan and Chow].quote | flagged (0.1) | unchanged, unfetchable: inria.hal.science answers a plain fetch with an Anubis proof-of-work challenge page and a headless browser with "Access Denied"; not circumvented. The quote was read directly earlier today (Round 1). Host added to `RENDERED_HOSTS` so the runner reports it as needing a rendered check, not as changed | https://inria.hal.science/hal-01614856/file/434671_1_En_7_Chapter.pdf | unfetched (bot wall) |
| ICS-0005 | artifacts[M580 OPERATING_MODE_CHANGE].sources quote | `Program Operating Mode change (Run, Stop, Init, halt) Mode Maintenance / SafeRun / Stop SAFE Task` | `Program Operating Mode change (Run, Stop, Init, halt) ... Mode Maintenance / SafeRun / Stop SAFE Task` - the table cell's two lines, which pdftotext joins as `halt)Mode`, quoted as fragments; both verbatim | https://docs.rs-online.com/7a9a/A700000012779990.pdf (EIO0000001999.12, November 2024, 170 pages) | direct (PDF, pdftotext) |
| ICS-0005 | sources quotes `\| BMX P34 2020 \| 2.60 \| X \| X \| - \| - \| X \| X \| - \|` and `Login problem (Unity Application password through Modbus-Umas)` | flagged (0.27, 0.9) | unchanged: the table row is verbatim (pdftotext prints the cells space-separated); "Modbus-Umas" is hyphenated at a line end and pdftotext joins it as "ModbusUmas". `norm()` now drops cell borders and intra-word hyphens | rs-online PDF (as above) | direct |
| ICS-PROTO-0012 | sources[EIO0000001999].quote `Login problem (Control Expert application password through Modbus-Umas)` | flagged (0.92) | unchanged: same line-end hyphenation | https://download.se.com/files?p_Doc_Ref=EIO0000001999&p_enDocType=User+guide (EIO0000001999.15, July 2026, 170 pages) | direct (PDF, pdftotext) |
| ICS-DS-0007 | sources quote `\| Transfer project to PAC \| 10 \| 6 \| Download the application to the controller. \|` | flagged (0.55) | unchanged: row verbatim; cell borders now normalised | se.com PDF (as above) | direct |
| ICS-DS-0013 | sources[M580 event log message descriptions].quote | `Operating mode change \| Program operating mode change (Run, Stop, Init, Halt) Mode maintenance / SafeRun / Stop SAFE task` | `Program operating mode change (Run, Stop, Init, Halt) ... Mode maintenance / SafeRun / Stop SAFE task` - row label dropped and the cell's two lines quoted as fragments, because pdftotext emits this cell in two separate runs; the whole row is verbatim in the rendered table | se.com PDF (as above) | direct |
| ICS-HUNT-0013 | sources[CERT Polska PDF].quote `Device Restart/Shutdown \| T0816 \| Shutdown of compromised industrial automation devices` | flagged (0.62) | unchanged: row verbatim; cell borders now normalised | https://cert.pl/uploads/docs/CERT_Polska_Energy_Sector_Incident_Report_2025.pdf | direct (PDF, pdftotext) |
| ICS-PROTO-0010 | sources[CODESYS Security Whitepaper].quote (port 4840 row) | flagged (0.4) | unchanged: row verbatim in the rendered copy; cell borders now normalised | https://customers.codesys.com/fileadmin/data/customers/security/CODESYS-Security-Whitepaper.pdf | direct (Firecrawl-rendered copy, 2026-11-08 01:21 UTC; live PDF refused by the proxy) |
| ICS-PROTO-0015 | sources[CODESYS Security Whitepaper].quote (1740-1743 and 1217 rows) | flagged (0.63, 0.8) | unchanged: rows verbatim in the rendered copy | CODESYS whitepaper (as above) | as above |
| ICS-DS-0002 | sources[suricata.yaml.in] x2 .url | `https://github.com/OISF/suricata/blob/main/suricata.yaml.in` (GitHub builds the file view in the browser; the runner saw closest 0.23 and 0.5) | `https://raw.githubusercontent.com/OISF/suricata/main/suricata.yaml.in`; both quotes verbatim in the raw file | raw file | direct |
| check_quotes.py | `RENDERED_HOSTS` | - | + www.europol.europa.eu, publisher.hitachienergy.com, inria.hal.science (reasons above, in the source comment) | - | - |
| check_quotes.py | `norm()` | - | `\|` becomes a space (table cell borders of a row copied from a rendered PDF or HTML table); a hyphen between two word characters is dropped (pdftotext joins a word hyphenated at a line end). "read only" still differs from "read-only" | - | - |
| check_quotes.py | `check()` / `missing_fragment()` | a quote containing " ... " could never match | the quote is split on " ... " (or "…") and every fragment must be on the page in the page's order; `closest` is computed for the first fragment that is not. Unit tests added for both changes | - | - |

Counts for the 29: 13 verbatim on the rendered page with no record change
(checker-only), 11 quotes corrected to the page's exact text or order
(ICS-MAL-0007, -0008, -0010, -0011, -0012, -0013, -0014, -0015 Talos,
-0016 PYROXENE, ICS-0005 and ICS-DS-0013 operating-mode cells), 5 claims now
`unverified` (ICS-MAL-0015 Dragos Year in Review; ICS-0014 x4 Hitachi
Energy guideline, link withdrawn), 1 unfetchable (ICS-0010, Anubis bot wall;
read directly in Round 1), 2 URLs changed (ICS-DS-0002). Re-running the
checker on every touched record with the widened network matched 45 quotes
and reported only the two Dragos/cert.pl order fixes above (then fixed) and
the Year in Review quote (now `unverified`); the rest of that run's misses
were hosts the sandbox cannot reach. Not re-checked: ICS-MAL-0002's spliced
CISA quote (cisa.gov unreachable here; not flagged in run 2).
