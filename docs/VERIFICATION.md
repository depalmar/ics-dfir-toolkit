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
