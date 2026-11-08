# Hardening controls and OT response playbook - research notes

Date: 2026-11-08. Stream: hardening/remediation controls and the OT incident
response baseline.

Records built from these notes:

- `artifacts/hardening/baseline.yml` (ALL, 35 controls)
- `artifacts/hardening/rockwell-logix.yml` (ICS-0001, 9 controls)
- `artifacts/hardening/siemens-s7.yml` (ICS-0003, 11 controls)
- `artifacts/hardening/unitronics.yml` (ICS-0006, 11 controls)
- `artifacts/hardening/remote-access-gateways.yml` (ICS-0013, 10 controls)
- `artifacts/response/baseline.yml` (ALL)

All pages were fetched with Firecrawl (`firecrawl_scrape`, markdown, PDFs with
the pdf parser). "Direct" means the quote was copied from that rendered page.
72 of the quotes were re-checked by script against the saved scrape output
(whitespace and markdown emphasis normalised); the rest were copied from the
scrape output in the session and checked by eye.

## Sources read

### Government

| Source | URL | Read | Notes |
| --- | --- | --- | --- |
| CISA, FBI, EPA, DOE - Primary Mitigations to Reduce Cyber Threats to OT (6 May 2025) | https://www.cisa.gov/sites/default/files/2025-05/fact-sheet-primary-mitigations-to-reduce-cyber-threats-to-operational-technology-508c.pdf | direct (PDF) | Five mitigations; maps to original CPG ids (2.X, 2.A-C, 2.H, 2.F). |
| CISA AA26-097A - Iranian-Affiliated Cyber Actors Exploit PLCs (7 Apr 2026, updated 22 Jul 2026) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a | direct | Mitigations, modem guidance, Dropbear on modems, AOI review, backup verification, IP vetting disclaimer. Uses CPG 2.0 ids (3.S, 3.F). |
| NSA, CISA, FBI, DOE, EPA AA26-231A - Defending Against an Active Threat to Siemens S7 Series PLCs (19 Aug 2026) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a | direct | Found via Siemens SSB-104599; S7-specific hardening and detection, D3FEND mapping. |
| CISA AA25-343A - Pro-Russia Hacktivists Conduct Opportunistic Attacks (9 Dec 2025) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-343a | direct | Has an explicit "Incident Response" section (six steps) plus mitigations mapped to CPG 2.0. |
| CISA AA23-335A - IRGC-Affiliated Cyber Actors Exploit PLCs (1 Dec 2023, updated 18 Dec 2024) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a | direct | Unitronics TTPs (lock-out, version rollback, port change) and mitigations. |
| CISA alert - Exploitation of Unitronics PLCs used in Water and Wastewater Systems (28 Nov 2023, updated 19 Dec 2023) | https://www.cisa.gov/news-events/alerts/2023/11/28/exploitation-unitronics-plcs-used-water-and-wastewater-systems | direct | Default password "1111", TCP 20256, factory reset familiarity. |
| ASD's ACSC et al. - Principles of operational technology cyber security (Oct 2024) | https://www.cyber.gov.au/publication/principles-of-operational-technology-cyber-security | direct | Six principles; strong incident-response material (safe state, backup trust, ransom, volatile memory). |
| CISA et al. - Foundations for OT Cybersecurity: Asset Inventory Guidance (13 Aug 2025) | https://www.cisa.gov/resources-tools/resources/foundations-ot-cybersecurity-asset-inventory-guidance-owners-and-operators | direct | Steps and the 14 high-priority attributes. Does not discuss active vs passive discovery. |
| CISA - Key Secure by Demand Elements for OT (fact sheet) | https://www.cisa.gov/sites/default/files/2025-04/Priority-Considerations-for-OT-508c.pdf | direct (PDF) | Summary of the January 2025 joint guide; the full 1.4 MB guide was not read. |
| NSA, CISA - Control System Defense: Know the Opponent (AA22-265A, Sep 2022) | https://media.defense.gov/2022/Sep/22/2003083007/-1/-1/0/CSA_ICS_Know_the_Opponent_.PDF | direct (PDF) | Connectivity inventory, remote access, tools and scripts, audits. |
| NIST SP 800-82r3 (Sep 2023) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf | direct (PDF, 316 pp) | Used: 6.4-6.5 Respond/Recover, 6.2.4.3 backups, 6.2.12 time sync, E.2.3 active scanning, C.3.4 scanning incidents, key switch, SIS independence. Recorded as `kind: government`. |
| CISA - Recommended Practice: Developing an ICS Cybersecurity Incident Response Capability (2009) | https://www.cisa.gov/sites/default/files/2023-01/final-RP_ics_cybersecurity_incident_response_100609.pdf | direct (PDF) | Containment by disconnecting the communication point; RTOS kernel lost on power-off; acceptance tests. |
| CISA, FBI, EPA - Incident Response Guide: Water and Wastewater Sector (publication January 2024) | https://www.cisa.gov/sites/default/files/2024-10/WWS-Sector_Incident-Response-Guide.pdf | direct (PDF) | Mostly federal roles; used for vendor PSIRT reporting and evidence retention. |
| CISA ICSA-23-026-04 - Sierra Wireless AirLink Router with ALEOS | https://www.cisa.gov/news-events/ics-advisories/icsa-23-026-04 | direct | Republishes Sierra's mitigations (WAN ACEManager off, Trusted IP, unique random credentials). |
| CISA ICSA-19-122-03 - Sierra Wireless AirLink ALEOS (Update B) | https://www.cisa.gov/news-events/ics-advisories/icsa-19-122-03 | direct | Sierra's console/AAF password and HTTPS-only advice. |

### Vendor

| Source | URL | Read | Notes |
| --- | --- | --- | --- |
| Rockwell SD1771 (20 Mar 2026) | https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1771.html | direct | Disconnect, mode switch RUN, offline project uploads, CIP Security, FactoryTalk Security binding. |
| Rockwell SD1672 (21 May 2024, rev 1.1 Aug 2025) | https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1672.html | direct | The 2024 disconnect notice; lists related CVEs. |
| Rockwell PN1550 - CVE-2021-22681 (rev 1.6, 10 Mar 2026; KEV: yes) | https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.PN1550.html | direct | Per-family mitigation table, detection strategies (Controller Log, Change Detection, syslog), TCP 44818. |
| Rockwell 1756-PM016T Logix 5000 Controllers Security (Sep 2025) | https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm016_-en-p.pdf | direct (PDF) | FactoryTalk Security overview only. |
| Siemens ProductCERT SSB-104599 (V1.3, 21 Aug 2026) | https://cert-portal.siemens.com/productcert/html/ssb-104599.html | direct | Points to AA26-097A and AA26-231A. |
| Siemens Cybersecurity for Industry Operational Guidelines v2.2.1 | https://cert-portal.siemens.com/operational-guidelines-industrial-security.pdf | direct (PDF) | Services, default passwords, secure PG/HMI (TLS, V17), project-file protection, antivirus must not quarantine/block/shut down. |
| Siemens TIA Portal V20 information system - Configuring access levels (S7-1500) | https://docs.tia.siemens.cloud/r/en-us/v20/functional-description-of-s7-1500-cpus-s7-1500/setting-the-operating-behavior-s7-1500/protection-security-s7-1500/settings-for-access-levels-s7-1500/configuring-access-levels-s7-1500 | direct | The URL rendered neighbouring topics too (Connection mechanisms, protection settings table); quotes from them are attributed to this URL. |
| Siemens SIOS FAQ 109925755 - PUT/GET on S7-1500 FW V3.1 / S7-1200 FW V4.7 | https://support.industry.siemens.com/cs/document/109925755/how-do-you-activate-put-get-access-on-an-s7-1500-cpu-from-fw-v3-1-or-s7-1200-cpu-from-fw-v4-7-?dti=0&lc=en-WW | direct | Menu path and warning; public, no login needed. |
| Unitronics Cybersecurity Advisory 2023-001 (CVE-2023-6448, 19 Dec 2023) | https://downloads.unitronicsplc.com/Sites/plc/Technical_Library/Unitronics-Cybersecurity-Advisory-2023-001-CVE-2023-6448.pdf | direct (PDF) | VisiLogic 9.9.00 / OS 12.38 force password changes. |
| Unitronics - Cyber Protection: Vision and Samba Series | https://www.unitronicsplc.com/cyber_security_vision-samba/ | direct | PCOM levels, SB 314/SDW 10 MFA, SB 305 / SI 165-168 Modbus limit, no port forwarding. |
| Moxa - Security Hardening Guide for the OnCell Series v1.0 (29 Aug 2025) | https://www.moxa.com/getmedia/293109b1-6b71-4734-899d-a6c6fbee1e6b/moxa-the-security-hardening-guide-for-oncell-series-tech-note-v1.0.pdf | direct (PDF) | Default service table; OnCell 3120-LTE-1 has no stateful firewall. |
| Teltonika Networks Wiki - Security Guidelines | https://wiki.teltonika-networks.com/view/Security_Guidelines | direct | One quote kept as summariser (markup inside parentheses). |
| Sierra Wireless SWI-PSA-2023-006 landing page | https://source.sierrawireless.com/resources/security-bulletins/sierra-wireless-technical-bulletin---swi-psa-2023-006 | direct | Landing page only; the PDF needs sign-in. |

## Key verbatim quotes

- Primary Mitigations: "OT devices are easy targets when connected to the internet."
- Primary Mitigations: "The capability for organizations to revert to manual controls to quickly restore operations is vital in the immediate aftermath of an incident."
- AA26-097A: "Specifically, “remove inbound port exposure,” so the OT system is never directly exposed to the internet or external networks, and to ensure all access is mediated, monitored, and controlled."
- AA26-097A: "Prior to switching the device to run mode, review and validate project files, as changing modes will lock in the current project file downloaded to the device."
- AA26-097A: "If restoring from backups, verify the backup does not contain malicious logic before deployment."
- AA26-097A: "Additionally, the changes disabled critical shutdown and alarm logic, allowing systems to enter unsafe conditions without notifying operators of the anomalies."
- AA26-097A: "the actors utilized Dropbear Secure Shell (SSH) software on victim modems to enable them to gain remote access through port 22"
- AA26-097A: "The authoring agencies recommend organizations investigate or vet these IP addresses prior to taking action, such as blocking."
- AA25-343A: "If organizations find exposed systems with weak or default passwords, they should assume threat actors compromised the system and begin the following incident response protocols:"
- AA25-343A: "While threat actors claim to turn off HMIs, it is possible that operators (not the threat actors) turn the devices off during incident response."
- CISA ICS IR RP: "It may be possible to take a snapshot of the kernel on the isolated component for later analysis under two conditions: the offending component is isolated by disconnecting it from the network, and leaving it in a powered state."
- CISA ICS IR RP: "In most incident instances, the system administrator or process engineer’s priority is to resume normal operations as soon as possible, often by rebooting the affected device. When this process is executed in this manner, evidence may be destroyed."
- ASD: "Most, if not all, of the traditional remediation steps listed will reset communication links and wipe volatile memory, which may have helped a cyber security investigation."
- ASD: "paying a ransom cannot be an option, as there is no timely large-scale method to verify that the system has been returned to a safe state."
- NIST SP 800-82r3: "OT network owners should exercise extreme caution when permitting active scanning on an operational network due to device sensitivity on the target network."
- Rockwell PN1550: "Rockwell Automation has determined that this vulnerability cannot be mitigated with a patch."
- Siemens TIA V20: "By default, the \"Permit access with PUT/GET communication from remote partners (...)\" option is disabled."
- Unitronics alert (CISA): "Ensure the Unitronics PLC default password “1111” is not in use."
- Sierra (via CISA ICSA-23-026-04): "Disable access to ACEManager on the wide area network (WAN) and use the Sierra Wireless Airlink Management System (ALMS) or an alternative device management platform for remote management of ALEOS devices."

## Pages that needed a login (not read; nothing rests on them)

- Rockwell Knowledgebase 494865 (advisory on web search tools that identify ICS devices) - SD1672/SD1771 mark it "[login required]".
- Rockwell Knowledgebase 1085012 "Security Best Practices" - "[login required]".
- Rockwell BF7490 "TCP/UDP Ports Used by Rockwell Automation Products" - Knowledgebase (custhelp) link; not attempted.
- Sierra Wireless SWI-PSA-2023-006 PDF and ALEOS release notes on source.sierrawireless.com - sign-in page returned. Sierra wording taken from CISA republication instead.
- Siemens restricted SIOS documents (PCS 7 / PCS neo security concepts) - not attempted.

## Controls considered and rejected (or left out)

- **"Implement a dynamic network environment"** (AA22-265A: change IP pools, add firewalls from different vendors). Not adopted: operationally disruptive, not repeated in the 2023-2026 advisories, and it works against the stable baselines detection depends on.
- **Watchdog timers** (AA23-335A). Left out: availability monitoring rather than hardening; candidate for a visibility record.
- **Canary tokens on OT data** (ASD, "potentially"). Left out: ASD presents it as an idea, not a recommendation.
- **CPU-side IP allowlist menu path for S7-1200/1500.** AA26-231A recommends MAC/IP allowlisting "on PLCs"; no Siemens page read gives the TIA path, so s7-restrict-engineering-access says so and cites SCALANCE port security instead.
- **CVE-2023-3595 (Rockwell communication modules) as its own control.** Rockwell lists it in SD1672; ICSA-23-193-01 was not read this pass, so it only appears in rok-apply-listed-cve-mitigations.
- **Rockwell Micro800 guidance** (SD1771). Out of scope for ICS-0001; no platform id exists for Micro800.
- **Teltonika "By default, all the traffic from WAN network to the router is rejected"** (Firewall traffic rules wiki) and **RUT241 "Enable remote HTTP access ... default: off"**. Search snippets only; not scraped, not used.
- **Forescout Sierra:21 mitigation list.** Researcher restatement of vendor/CISA advice already sourced directly.
- **Gateway physical security** (Moxa: locked cabinet, secured cables). No matching schema category; omitted rather than mis-filed.
- **ISA/IEC 62443 SR mappings.** Paywalled; not cited. The asset-inventory guidance mentions zones and conduits from 62443, which is reflected in base-asset-inventory's how.
- **SANS Five ICS Cybersecurity Critical Controls.** Page found (https://www.sans.org/white-papers/five-ics-cybersecurity-critical-controls) but the PDF was not fetched; its five controls overlap controls already sourced to government guidance, so nothing rests on it.
- **DOE CESER / E-ISAC response guidance, SANS ICS IR.** Not read in this pass; the response playbook rests on CISA, NIST, ASD and the joint advisories.
- **Response do_not "don't disconnect safety systems".** No source says it verbatim. Kept with `basis: toolkit`, reasoned from NIST (SIS independence) and AA26-097A (disabling shutdown logic was the harm).

## Points for other streams

- AA26-231A (S7) is new since the registry was drafted; it may deserve an incident or campaign record and a KEV-watch check of the S7 CVEs it alludes to (it names no CVE).
- AA26-097A's July 2026 update adds Schneider and Siemens targeting and AOI modification; the ICS-INC-0009 record should reflect the update date.
- Search results showed a NIST SP 800-82r4 initial public draft exists (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r4.ipd.pdf); not read. Records cite r3, the final version.
- CPG numbering differs between sources: the May 2025 fact sheet and AA23-335A use the original CPG ids, AA25-343A/AA26-097A use CPG 2.0. Hardening records give each id as its source prints it.
