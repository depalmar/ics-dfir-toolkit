# Incidents, exploited ICS CVEs (KEV) and exploitation dates - research notes, 2026-11-08

Stream: incident case studies (`artifacts/intel/incidents/`), the KEV watch ledger
(`artifacts/watch/kev-watch.yml`) and exploitation dates (`artifacts/intel/exploitation.yml`).
All pages were fetched with Firecrawl on 2026-11-08. "Direct" means the quote was copied from the
rendered page; "summariser" means it came from a search-result excerpt and still needs a direct read.

## Records written

| Id | Incident | Consequence (enum) | Confidence |
| --- | --- | --- | --- |
| ICS-INC-0001 | Ukraine distribution outages, 2015-12-23 | service-outage | high |
| ICS-INC-0002 | Kyiv transmission substation (Industroyer), 2016-12-17 | service-outage | high |
| ICS-INC-0003 | TRITON at a refinery, 2017 | safety-system-trip | high |
| ICS-INC-0004 | Industroyer2 attempt, 2022-04-08 | attempted-no-effect | high |
| ICS-INC-0005 | CyberAv3ngers / Unitronics, from 2023-11-22 | loss-of-control | high |
| ICS-INC-0006 | Lviv heating (FrostyGoop), 2024-01 | service-outage | low, unverified |
| ICS-INC-0007 | Pro-Russia hacktivist HMI manipulation at US water utilities, 2024 | process-manipulation | high |
| ICS-INC-0008 | Poland distributed energy / CHP, 2025-12-29 | loss-of-control | high |
| ICS-INC-0009 | Iranian-affiliated PLC exploitation (AA26-097A), 2026-03 | process-manipulation | high |
| ICS-INC-0010 (new) | US water MicroLogix lockout campaign, 2026-07-27 | loss-of-control | high |
| ICS-INC-0011 (new) | Colonial Pipeline precautionary OT shutdown, 2021-05 | service-outage | high |
| ICS-INC-0012 (new) | Reported NaOH setpoint change at a US water plant (press: Oldsmar), 2021-02-05 | attempted-no-effect | low, unverified |

## KEV summary

Catalog version 2026.11.06 (1,769 entries), via the Firecrawl `cisa-gov` `vulnerabilities/kev_search`
provider (one query per vendor, `added_from: 2023-01-01`) and cross-checked by scanning a copy of
`cisagov/kev-data` JSON for every watched vendor and ICS keyword. Only three KEV entries added since
2023-01-01 fall on registry platforms:

| CVE | KEV vendor | KEV product | Date added | Ransomware | Platform | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2023-6448 | Unitronics | Vision PLC and HMI | 2023-12-11 | Unknown | ICS-0006 | no-indicators (ref ICS-INC-0005) |
| CVE-2018-4063 | Sierra Wireless | AirLink ALEOS | 2025-12-12 | Unknown | ICS-0013 | deferred |
| CVE-2021-22681 | Rockwell | Multiple Products | 2026-03-05 | Unknown | ICS-0001 | no-indicators |

None of the three is BOD 26-04 `forensic_triage: Yes`. Zero KEV entries since 2023 for Siemens SIMATIC/S7,
Schneider Modicon/Triconex, OMRON, CODESYS, Moxa, Teltonika, Digi International, AVEVA/OSIsoft or Inductive
Automation.

Near misses checked and deliberately not mapped:

- CVE-2026-110936, Siemens "Software Center" (DLL search path, added 2026-10-20): not a registry platform;
  SSA-580366 not read. Revisit if the platform owners decide it lives on engineering workstations (ICS-0010).
- CVE-2021-26828 / CVE-2021-26829, OpenPLC "ScadaBR" (added 2025-12-03 / 2025-11-28): an open-source web
  SCADA/HMI. Not mapped because ICS-0011 is scoped to Windows HMI/SCADA products (WinCC, FactoryTalk View,
  iFIX, InTouch, Ignition). Open question for the platform stream.
- CVE-2021-3129, Laravel "Ignition" (ransomware Known): a PHP debug page, not Inductive Automation Ignition;
  the ICS-0011 vendor regex is anchored to exclude it.
- CVE-2023-52163, Digiever DS-2105 Pro: an NVR; "Digi" substring only. ICS-0013 vendor regex is anchored.
- CVE-2026-12569, PTC Windchill and FlexPLM: PLM, not Kepware; ICS-0015 matches on product only.
- Pre-2023 (not triaged, before `since`): CVE-2016-8562 Siemens SIMATIC CP (2022-03-03), CVE-2018-7841
  Schneider U.motion Builder (2022-04-15), CVE-2021-38406 Delta DOPSoft 2 (2022-08-25), Cisco IOS industrial
  Ethernet PROFINET/CIP DoS CVE-2017-12233/12234/12235 (2022-03-03).

## Exploitation dates

| CVE | Earliest | Words | Source | Read |
| --- | --- | --- | --- | --- |
| CVE-2023-6448 | 2023-11-22 | "Since at least November 22, 2023" | CISA AA23-335A, December 14, 2023 PDF | direct |
| CVE-2021-22681 | - (reports empty) | - | PN1550 shows only the KEV flag; AA26-097A names no CVE | direct |
| CVE-2018-4063 | - (reports empty) | - | no primary report found | - |
| CVE-2015-5374 | - (reports empty) | - | Industroyer carried a module; no statement it was run | direct |

The CVE-2023-6448 sentence names "default credentials"; the CVE tie is the same PDF's "On December 11,
2023, CVE-2023-6448 was assigned to address the default passwords". The current (December 2024) web
revision of AA23-335A no longer names the CVE.

## Per incident

### ICS-INC-0001 Ukraine, 23 December 2015

Chain as CISA tells it (interviews only, no technical evidence reviewed): spear phishing with BlackEnergy
(role unknown) -> credentials obtained beforehand -> remote access via OS-level remote admin tools or ICS
client software over VPN -> breakers opened at three Oblenergos within 30 minutes -> KillDisk, HMIs in RTUs
overwritten, serial-to-Ethernet firmware corrupted, UPS disconnects scheduled.

- CISA IR-ALERT-H-16-056-01, https://www.cisa.gov/news-events/ics-alerts/ir-alert-h-16-056-01 (direct):
  "power outages were caused by remote cyber intrusions at three regional electric power distribution
  companies (Oblenergos) impacting approximately 225,000 customers."
- Same page: "we do not know whether the malware played a role in the cyber-attacks."
- DOJ, GRU Unit 74455 indictment (direct): "December 2015 through December 2016 destructive malware attacks
  against Ukraine’s electric power grid ... using malware known as BlackEnergy, Industroyer, and KillDisk".
- Conflict: CISA 225,000 customers vs ESET "around 250,000 households".
- Attribution: DOJ (Sandworm Team labels) -> ICS-TA-0001; Dragos (ELECTRUM, "distribution control
  centers in Ukraine in 2015") -> ICS-TA-0002. KAMACITE (ICS-TA-0003) lists this incident but no KAMACITE
  source was read here, so it is not listed back (validator warning only).

### ICS-INC-0002 Kyiv, 17 December 2016

ESET: Industroyer backdoor (Tor C&C, Notepad-masquerading backup backdoor) -> custom port scanner and OPC
mapping -> IEC 101/104/61850/OPC DA payloads operate switches and breakers -> wiper, serial COM DoS,
SIPROTEC DoS (CVE-2015-5374). Activation timestamp 17 December 2016.

- ESET, https://www.welivesecurity.com/2017/06/12/industroyer-biggest-threat-industrial-control-systems-since-stuxnet/
  (direct): "it’s highly probable that Industroyer was used in the December 2016 attack".
- CISA TA17-163A (direct, July 2021 update): "Russian nation-state cyber actors deployed CrashOverRide
  malware to conduct a cyberattack against Ukrainian critical infrastructure."
- Gap: no source read describes initial access. ESET's one-hour Kyiv outage cites Reuters.

### ICS-INC-0003 TRITON, 2017

Mandiant: DCS foothold -> SIS engineering workstation -> trilog.exe (masquerades as Triconex Trilog) reads
controller state over TriStation -> appends inject.bin / imain.bin to program memory -> validation failure
between redundant processors -> safe shutdown. DOJ: "between May and September 2017", "two automatic
emergency shutdowns".

- Mandiant, https://cloud.google.com/blog/topics/threat-intelligence/attackers-deploy-new-ics-attack-framework-triton (direct).
- DOJ, https://www.justice.gov/archives/opa/pr/four-russian-government-employees-charged-two-historical-hacking-campaigns-targeting-critical (direct): TsNIIKhM employee.
- Actors left empty: no source read uses XENOTIME or TEMP.Veles; country not named (DOJ "foreign
  refinery"). Registry label "Middle East petrochemical" is from reporting not read.

### ICS-INC-0004 Industroyer2, 8 April 2022

ESET timeline (UTC): 14:58 CaddyWiper and Linux/Solaris wipers; 15:02:22 scheduled task for Industroyer2;
16:10 Industroyer2; 16:20 CaddyWiper on the same host. CERT-UA: two waves, initial compromise no later than
February 2022, SSH tunnels and IMPACKET, POWERGAP GPO deployment.

- CERT-UA#4435, https://cert.gov.ua/article/39518 (direct, Ukrainian): "Разом з тим, реалізації
  зловмисного задуму на поточний момент вдалося запобігти." (toolkit translation: implementation of the
  plan has so far been prevented).
- ESET, https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/ (direct): "an attempt
  to deploy the Industroyer2 malware against high-voltage electrical substations".

### ICS-INC-0005 CyberAv3ngers / Unitronics, November 2023 - January 2024

AA23-335A (December 2024 revision): default TCP 20256 with default or no password -> ladder logic replaced
with a no-I/O file -> devices renamed, software version set older, upload/download disabled, upload
password set, port moved to 20257, logic not burned -> HMI defacement. At least 75 devices, 34 in WWS.

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a (direct).
- December 2023 PDF (direct): CVE-2023-6448 assigned 2023-12-11 for the default passwords; KEV same day.
- Aliquippa: named only in a press headline in CISA's reference list; not read. Manual operation at
  Aliquippa is press-only.

### ICS-INC-0006 Lviv, January 2024

Dragos: router (undetermined vulnerability) -> unsegmented network -> Modbus commands to ENCO controllers ->
inaccurate measurements, two-day heating loss. Low/unverified: Dragos relaying CSSC is the only source; the
January date is from a search excerpt of the Dragos brief page. Tension inside Dragos's post: access via an
external router vs FrostyGoop targeting controllers "through Modbus TCP port 502 open to the internet".

### ICS-INC-0007 Pro-Russia hacktivists, 2024

Fact sheet (May 2024): VNC on 5900, default/weak passwords -> set points maxed, settings altered, alarms off,
admin passwords changed -> pumps/blowers beyond parameters, minor tank overflows, manual control.

- https://www.cisa.gov/sites/default/files/2024-05/defending-ot-operations-against-ongoing-pro-russia-hacktivist-activity-508c.pdf (direct).
- NJCCIC, https://www.cyber.nj.gov/Home/Components/News/News/1292/214 (direct): Muleshoe, Texas tank
  overflow in January; CARR claimed responsibility.
- AA25-343A, https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-343a (direct): CARR,
  Z-Pentest, NoName057(16), Sector16; "regularly make false or exaggerated claims".
- The fact sheet names no group; the CARR link is NJCCIC + CARR's own claims.

### ICS-INC-0008 Poland, 29 December 2025

CERT Polska: edge devices -> default credentials to HMIs/RTUs -> reconnaissance -> partially automated
destruction (controller firmware, file deletion, wipers) at 30+ wind/PV grid connection points -> loss of
DSO communication/control, generation unaffected; CHP wiper blocked by EDR; manufacturer hit the same day.

- https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/ (direct).
- CISA, https://www.cisa.gov/news-events/alerts/2026/02/10/poland-energy-sector-cyber-incident-highlights-ot-and-ics-security-gaps (direct).
- Attribution conflict: CERT Polska -> Static Tundra / Berserk Bear / Ghost Blizzard / Dragonfly
  (ICS-TA-0017); Dragos -> ELECTRUM, moderate (ICS-TA-0002). Sandworm (ICS-TA-0001) lists this incident;
  no source read here attributes it to Sandworm, so it is not listed back.

### ICS-INC-0009 AA26-097A, 2025-2026

AA26-097A (April 7, 2026; updated July 22, 2026): leased hosting + vendor programming software -> internet
PLCs (CompactLogix, Micro850, Modicon M340, S7-1200) on 44818/2222/102/502; Dropbear SSH on modems ->
project file exfiltration -> logic and AOI modification/deletion, safety-parameter override at one victim,
shutdown and alarm logic disabled, HMI/SCADA data manipulated -> disruption and financial loss.

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a (direct). Names no CVE and no group.

### ICS-INC-0010 (new) US water MicroLogix campaign, July 2026

FBI/EPA PSA I-073026-PSA, https://www.ic3.gov/PSA/2026/PSA260730.pdf (direct): since 27 July 2026, WWS
utilities in at least seven states; MicroLogix 1100/1400; IP addresses and passwords changed; loss of view
and some function; loss of pressure and flooding; modified project files at one utility. CISA alert,
https://www.cisa.gov/news-events/alerts/2026/07/30/cisa-urges-water-and-wastewater-systems-sector-protect-ot-against-activity-targeting-plcs
(direct): boil water notices and sustained manual operations. Separate from AA26-097A because neither
agency links them. IOActive (not primary) says it began 26 July.

### ICS-INC-0011 (new) Colonial Pipeline, May 2021

AA21-131A (direct): DarkSide on IT; company "proactively disconnected certain OT systems"; no lateral
movement to OT. Colonial's statement (summariser): "temporarily halted all pipeline operations".

### ICS-INC-0012 (new) US water treatment plant, 5 February 2021

AA21-042A (direct): NaOH dose raised via SCADA software, caught by staff; but "the FBI was not able to
confirm that this incident was initiated by a targeted cyber intrusion". Kept low/unverified.

## Rejected or lead-only sources

- SecurityWeek on CVE-2021-22681 (press): says PN1550 mentions in-the-wild exploitation; rendered PN1550
  rev 1.6 shows only "Known Exploited Vulnerability (KEV): Yes".
- The Hacker News on CVE-2018-4063 (press): body did not render.
- SafeBreach, Picus, IOActive blogs on AA26-097A (vendor commentary): attribute to CyberAv3ngers; not adopted.
- Industrial Cyber, Trout Software, dtsec-labs on FrostyGoop: secondary.
- CyberScoop, Wired, Texan News on Muleshoe: press; not quoted.

## Open questions

1. CVE-2018-4063: who observed exploitation, and when? Read ICSA-19-122-03, the Sierra Wireless bulletin
   and any CISA alert for the 2025-12-12 KEV addition; until then the ledger entry stays `deferred`.
2. CVE-2021-22681: Rockwell's KEV flag gives no exploitation context. Does any Rockwell or CISA statement tie
   it to the AA26-097A Logix activity? AA26-097A itself does not.
3. Are the July 2026 water MicroLogix campaign and AA26-097A related? No source links them.
4. Lviv/FrostyGoop needs a second, independent source (SBU/CSSC statement) to rise above low.
5. Oldsmar: read the later public statements questioning whether it was an intrusion before raising
   confidence or naming the utility.
6. Read the CERT Polska PDF (timeline, device vendors, IOCs), the Dragos CRASHOVERRIDE and TRISIS reports,
   the E-ISAC/SANS Ukraine 2015 report and the CISA 28 November 2023 Unitronics alert.
7. Platform stream: decide whether OpenPLC ScadaBR belongs under ICS-0011 and Siemens Software Center under
   ICS-0010; both are KEV-listed since 2025.
8. Cross-links for the orchestrator: ICS-TA-0019 (AA26-097A unnamed group) -> ICS-INC-0009 actors;
   ICS-MAL-0013 DynoWiper and ICS-MAL-0014 LazyWiper -> ICS-INC-0008 malware. These ids were created by
   other streams outside the range this stream may cite, so they are not in the records yet.
