# Threat actors and attribution: research notes (2026-11-08)

Stream: threat actors (`artifacts/intel/actors/`). Every page below was read
with Firecrawl (`firecrawl_scrape`, markdown, main content). Quotes were
copied from the rendered page (`read: direct`) unless marked otherwise.
Search excerpts were used only to find pages, except where flagged
**[summariser]**.

## Method and rules applied

- One record per reporter's cluster. "Overlaps with" means an alias with
  `equated: false`. `equated: true` only where the reporter itself says the names
  are the same group.
- When a government advisory lists a Dragos name as another name for its cluster
  (AA24-038A "Voltzite", AA26-097A "Bauxite"), Dragos, the naming party, states
  only overlap. Per CLAUDE.md the toolkit keeps separate records with
  `equated: false`, and records the conflict.
- Appendix-only names in AA25-343A carry the advisory's own caveat ("this may
  not be a 1:1 correlation"), so they are `equated: false`.
- `link_confidence`: medium for a single reporting party or publication, even a
  multi-agency advisory. High only where independent publishers (government plus
  vendor, or two separate government actions) report the same cluster.
- No record is rated `low`. **Schema gap:** `actor.schema.json` has
  `additionalProperties: false` and no `unverified` property. A `low` actor
  record could not carry `unverified: true` without failing the schema. The
  validator's low-confidence check looks for the key `confidence`, not
  `link_confidence`.
- Protocol ids (`ICS-PROTO-`) are left out of actor records because they were not
  in this stream's permitted cross-reference list. Protocols are named in
  text.

## New ids added by this stream

| Id | Cluster | Why |
| --- | --- | --- |
| ICS-TA-0018 | TEMP.Veles (FireEye/Mandiant) | The registry paired it with XENOTIME under ICS-TA-0004, but neither Dragos nor Mandiant equates the two. ICS-TA-0004 is now XENOTIME alone, matching the registry's example filename `ICS-TA-0004-xenotime.yml`. |
| ICS-TA-0019 | Iranian-affiliated APT actors exploiting internet-facing PLCs (AA26-097A, unnamed) | AA26-097A attributes the 2026 activity to "a group of Iranian-affiliated APT actors" and cites CyberAv3ngers only as "similar activity". Filing it under CyberAv3ngers would compute attribution. |

Next free after this stream: ICS-TA-0020.

## Per actor

### ICS-TA-0001 Sandworm Team / APT44

- DOJ 2020 (https://www.justice.gov/archives/opa/pr/six-russian-gru-officers-charged-connection-worldwide-deployment-destructive-malware-and):
  "officers in Unit 74455 of the Russian Main Intelligence Directorate (GRU)";
  "December 2015 through December 2016 destructive malware attacks against
  Ukraine’s electric power grid, Ministry of Finance, and State Treasury Service,
  using malware known as BlackEnergy, Industroyer, and KillDisk";
  "Cybersecurity researchers have tracked the Conspirators and their malicious
  activity using the labels “Sandworm Team,” “Telebots,” “Voodoo Bear,” and “Iron
  Viking.”" (The old `/opa/pr/` URL redirects to `/archives/opa/pr/`.)
- Mandiant APT44 (https://cloud.google.com/blog/topics/threat-intelligence/apt44-unearthing-sandworm):
  "Sponsored by Russian military intelligence, APT44 is a dynamic and
  operationally mature threat actor that is actively engaged in the full spectrum
  of espionage, attack, and influence operations."; "Sandworm (aka
  FROZENBARENTS)".
- Mandiant 2023 OT (https://cloud.google.com/blog/topics/threat-intelligence/sandworm-disrupts-power-ukraine-operational-technology/):
  "We initially tracked this activity as UNC3810 before merging the cluster with
  Sandworm."; "Government indictments have linked the group to the Main Center
  for Special Technologies (also known as GTsST and Military Unit 74455)."; scilc.exe
  / SCIL; "we believe they were probably commands to open circuit breakers".
- ESET Industroyer2 (https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/):
  "We assess with high confidence that the APT group Sandworm is responsible for
  this new attack"; "Industroyer2 only implements the IEC-104 (aka IEC
  60870-5-104) protocol to communicate with industrial equipment."
- ESET DynoWiper (https://www.welivesecurity.com/en/eset-research/dynowiper-update-technical-analysis-attribution/):
  "We attribute DynoWiper to Sandworm with medium confidence"; "we only attribute
  the data-wiping component of this activity to Sandworm with medium confidence";
  "the preparatory stages leading up to the destructive activity may have been
  conducted by another threat actor group collaborating with Sandworm";
  "Microsoft ... Seashell Blizzard (aka Sandworm)".
- AA25-343A Appendix B lists GRU military unit 74455 as Sandworm Team, Voodoo
  Bear, Seashell Blizzard and APT44, with the 1:1 caveat.
- Rejected: Mandiant's APT44 PDF (not read). ICS kill-chain stage (no reporter
  stages Sandworm).

### ICS-TA-0002 ELECTRUM (Dragos)

- https://www.dragos.com/threat/electrum: "ELECTRUM is the activity group
  responsible for the 2016 power outage event caused by the ICS malware
  CRASHOVERRIDE."; "Dragos associates ELECTRUM with the SANDWORM Advanced
  Persistent Threat (APT)"; "Assessed links with SANDWORM APT, now appears
  independent"; MS SQL servers as the IT/OT gateway.
- 2026 YIR press release (https://www.dragos.com/resources/press-release/dragos-2026-year-in-review-new-ot-threats-ransomware):
  "In December 2025, ELECTRUM targeted combined heat and power (CHP) facilities
  and renewable energy management systems in Poland with deliberate attempts to
  impact operational assets"; "ELECTRUM shares technical overlaps with Sandworm."
- Dragos CHERNOVITE page: "CRASHOVERRIDE and the associated Activity Group,
  ELECTRUM, exploited the OPC-DA protocol to manipulate breakers and switch gear."
- Conflict: Dragos's two pages differ in emphasis ("now appears independent" vs
  "shares technical overlaps"). The Poland incident has three attributions (see
  ICS-TA-0017).

### ICS-TA-0003 KAMACITE (Dragos)

- https://www.dragos.com/threat/kamacite: "KAMACITE facilitated ICS-specific
  operations including the BLACKENERGY2 campaign and the 2015 and 2016 Ukraine
  power events."; "has not directly caused an ICS disruptive event according to
  Dragos analysis"; "Overlap with SANDWORM activity".
- YIR press release: reconnaissance "from March through July 2025, systematically
  scanning entire control loops including HMIs, variable frequency drives,
  metering modules, and cellular gateways".
- Rejected: listing BlackEnergy (ICS-MAL-0003) as KAMACITE malware. "Facilitated
  the campaign" does not say KAMACITE deployed the malware. Motivation: unknown,
  because Dragos gives a role, not a motivation.

### ICS-TA-0004 XENOTIME (Dragos)

- https://www.dragos.com/threat/xenotime: "XENOTIME configured TRISIS based on
  the specifics and functions of the Triconex system"; "Dragos assesses with
  moderate confidence that XENOTIME intends to establish required access and
  capability to cause a potential, future disruptive—or event." (sic); "This group
  has no known associations to other activity groups."
- Treasury 2020 (https://home.treasury.gov/news/press-releases/sm1162) quotes
  private industry: "the most dangerous threat activity publicly known". That
  matches Dragos's wording but names no cluster.
- Rejected: merging with TEMP.Veles (see ICS-TA-0018).

### ICS-TA-0005 CHERNOVITE (Dragos)

- https://www.dragos.com/threat/chernovite: "The Dragos team assesses with high
  confidence this capability was developed by a state actor with the intention to
  leverage it in future operations."; "Dragos assesses that PIPEDREAM has not yet
  been deployed in the wild."; "ICS Kill Chain Stage 2 - Install/Modify; Execute
  ICS Attack".

### ICS-TA-0006 VOLTZITE (Dragos)

- https://www.dragos.com/threat/voltzite: "has operational overlaps with Volt
  Typhoon (Microsoft)"; "Overlap with Volt Typhoon and BRONZE SILHOUETT" (sic);
  "VOLTZITE’s 2023 behavior suggested operational objectives of espionage and
  information gathering."
- YIR press release: "VOLTZITE was elevated to Stage 2 of the ICS Cyber Kill
  Chain"; "compromised Sierra Wireless Airlink cellular gateways to access U.S.
  midstream pipeline operations and then pivoted to engineering workstations".
- Conflict: AA24-038A lists "Voltzite" as another name for Volt Typhoon; Dragos
  states overlap only.

### ICS-TA-0007 Volt Typhoon

- AA24-038A (https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a):
  "the U.S. authoring agencies assess with high confidence that Volt Typhoon
  actors are pre-positioning themselves on IT networks to enable lateral movement
  to OT assets to disrupt functions."; "(also known as Vanguard Panda, BRONZE
  SILHOUETTE, Dev-0391, UNC3236, Voltzite, and Insidious Taurus)"; "for at least
  five years"; "positioned to move to a second control system"; the PuTTY profiles.
- Microsoft 2023 (https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/):
  "Microsoft assesses with moderate confidence that this Volt Typhoon campaign is
  pursuing development of capabilities that could disrupt critical communications
  infrastructure"; "active since mid-2021".
- Conflicts: motivation differs (Microsoft says espionage, AA24-038A says
  pre-positioning). UNC3236 appears as a Volt Typhoon name in AA24-038A and as a
  SYLVANITE overlap in Dragos.

### ICS-TA-0008 BAUXITE (Dragos)

- https://www.dragos.com/threat/bauxite: "shares substantial technical overlaps
  with the pro-Iranian hacktivist persona CyberAv3ngers"; "BAUXITE is capable of
  Stage 2 ICS Cyber Kill Chain"; "Linux Backdoor with C2 over MQTT".
- YIR press release: "deployed two custom wiper malware variants against Israeli
  targets during the Iran-Israel conflict in June 2025"; "BAUXITE exhibits
  technical overlap with activity the U.S. Government assesses is aligned with
  CyberAv3ngers and IRGC-CEC."
- Rejected: linking the MQTT backdoor to IOCONTROL. No reporter read makes that
  link.

### ICS-TA-0009 CyberAv3ngers

- AA23-335A (https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a):
  "In November 2023, IRGC-affiliated cyber actors using the persona
  “CyberAv3ngers” began actively targeting and compromising Israeli-made
  Unitronics Vision Series programmable logic controllers (PLCs) and human machine
  interfaces (HMIs)."; "compromised at least 75 devices, including at least 34 in
  the WWS Sector"; "several of these claimed compromises ... are false";
  "reportedly has connections to another IRGC-linked group known as Soldiers of
  Solomon".
- AA26-097A: "Private industry and open sources also refer to this group as Hydro
  Kitten, Storm-0784, APT Iran, Bauxite, Mr. Soul, Soldiers of Solomon, UNC5691, and
  the Shahid Kaveh Group."
- Treasury jy2072 (https://home.treasury.gov/news/press-releases/jy2072): six
  IRGC-CEC officials sanctioned over the Unitronics operations.
- Microsoft (https://www.microsoft.com/en-us/security/blog/2024/05/30/exposed-and-vulnerable-recent-attacks-highlight-critical-need-to-protect-internet-exposed-ot-devices/):
  "Microsoft tracks both “CyberAv3ngers” and its associated group “Soldiers of
  Solomon” as Storm-0784."
- Claroty (https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol):
  hedged, "allegedly compromised by a threat actor group linked to Iran known as
  the CyberAv3ngers".
- Conflict: US sources differ on Soldiers of Solomon (AA23-335A says a connected
  group; AA26-097A says another name), so it is `equated: false`.

### ICS-TA-0010 CARR; ICS-TA-0011 Z-Pentest; ICS-TA-0012 NoName057(16); ICS-TA-0013 Sector16

- AA25-343A (https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-343a):
  GRU unit 74455 "is likely responsible for supporting the creation of CARR";
  Z-Pentest "separate from GRU involvement"; CISM "created NoName057(16) as a
  covert project"; Sector16 "may have received indirect support from the Russian
  government"; "they regularly make false or exaggerated claims".
- Treasury jy2473 (https://home.treasury.gov/news/press-releases/jy2473): "CARR
  has been responsible for manipulating industrial control system equipment at
  water supply, hydroelectric, wastewater, and energy facilities in the U.S. and
  Europe"; Abernathy and Muleshoe overflow "claimed" by CARR, with Treasury
  stating the loss of "tens of thousands of gallons of water".
- Europol (https://www.europol.europa.eu/media-press/newsroom/news/global-operation-targets-noname05716-pro-russian-cybercrime-network):
  Operation Eastwood "Between 14 and 17 July". The scraped body does not print
  the year.
- Rejected: Mandiant APT44 report's CARR discussion (PDF not read). Any impact
  stated only by the actors is recorded as claimed.

### ICS-TA-0014 SYLVANITE; ICS-TA-0015 AZURITE; ICS-TA-0016 PYROXENE (Dragos, new in 2026 YIR)

- SYLVANITE (https://www.dragos.com/threat/sylvanite/): "Dragos has directly
  observed SYLVANITE transferring access to VOLTZITE"; overlaps "UNC5221, UNC5174,
  UNC5291, UNC3236, HOUKEN, Red Dev 61, CL-STA-0048, UTA0178".
- AZURITE (https://www.dragos.com/threat/azurite): "Defenders should treat any
  AZURITE presence in an OT environment as active prepositioning for future
  destructive operations"; overlaps "Flax Typhoon, Ethereal Panda, UNC5923, Raptor
  Train, Red Dev 54"; "Assessed to share tasking and targeting objectives with
  VOLTZITE".
- PYROXENE (https://www.dragos.com/threat/pyroxene): "Shares technical overlaps
  with APT35, UNC1549, Tortoiseshell adversary clusters."; "Collaborates with
  PARISITE for initial access."; MINIBIKE and BLUERABBIT. The press release adds
  "substantial technical overlap with activity the U.S. Government assesses is
  aligned with the Islamic Revolutionary Guard Corps Cyber Electronic Command
  (IRGC-CEC)".
- Rejected:
  - Stage labels seen only in trade press (Industrial Cyber, Cyber Magazine):
    SYLVANITE "Stage 1", AZURITE "Stage 2", and PYROXENE "low confidence ...
    Stage 2".
  - "Imperial Kitten" for PYROXENE. **[summariser]** It appeared only in a search
    excerpt of `hub.dragos.com/hubfs/2026_YIR_ExecutiveBriefing O_G.pdf`.
  - PYROXENE page subtitle, which duplicates AZURITE's.
- The brief's description of PYROXENE as overlapping "IRGC-CEC-aligned
  activity" is confirmed by the press release. The threat page itself names
  APT35, UNC1549 and Tortoiseshell instead.

### ICS-TA-0017 Dragonfly / Energetic Bear

- DOJ 2022 (https://www.justice.gov/archives/opa/pr/four-russian-government-employees-charged-two-historical-hacking-campaigns-targeting-critical):
  "members of a Center 16 operational unit known among cybersecurity researchers
  as “Dragonfly,” “Berzerk Bear,” “Energetic Bear,” and “Crouching Yeti.”"; Havex
  "inside legitimate software updates"; "more than 17,000 unique devices". The
  `/opa/pr/...-schemes-...` URL returns 404; the live slug is `...-campaigns-...`
  under `/archives/`.
- TA18-074A (https://www.cisa.gov/news-events/alerts/2018/03/15/russian-government-cyber-activity-targeting-energy-and-other-critical-infrastructure-sectors):
  "copying Virtual Network Connection (VNC) profiles that contained configuration
  information on accessing ICS systems"; HMI screenshot fragments.
- Symantec (https://www.security.com/threat-intelligence/dragonfly-energy-sector-cyber-attacks):
  "While Symantec cannot definitively determine Dragonfly’s origins"; Russian and
  French code strings, a possible false flag.
- CERT Polska (https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/):
  infrastructure "shows a high degree of overlap with the infrastructure used by
  the activity cluster publicly known as “Static Tundra” (Cisco), “Berserk Bear”
  (CrowdStrike), “Ghost Blizzard” (Microsoft), and “Dragonfly” (Symantec)";
  "the first publicly described destructive activity attributed to this activity
  cluster". CERT Polska's full PDF was not read.

### ICS-TA-0018 TEMP.Veles (new)

- Mandiant 2018 (https://cloud.google.com/blog/topics/threat-intelligence/triton-attribution-russian-government-owned-lab-most-likely-built-tools/):
  "FireEye Intelligence assesses with high confidence that intrusion activity that
  led to deployment of TRITON was supported by the Central Scientific Research
  Institute of Chemistry and Mechanics (CNIIHM; a.k.a. ЦНИИХМ)"; "we do not have
  specific evidence to prove that CNIIHM did (or did not) develop the tool."
- Treasury 2020 and DOJ 2022 tie the TRITON attack to TsNIIKhM and a TsNIIKhM ADC
  employee. Neither names TEMP.Veles or XENOTIME.

### ICS-TA-0019 AA26-097A unnamed Iranian-affiliated group (new)

- AA26-097A (https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a,
  7 April 2026, updated 22 July 2026): "The authoring agencies assess a group of
  Iranian-affiliated APT actors is conducting this activity to cause disruptive
  effects within the United States."; "previously reported on similar activity
  targeting PLCs by CyberAv3ngers"; targets CompactLogix, Micro850, BMX P34/Modicon
  M340, S7-1200; ports 44818, 2222, 102, 502 and modem port 22; Dropbear SSH;
  changes "disabled critical shutdown and alarm logic".
- The brief described this as affecting "Rockwell/Schneider/Siemens PLCs". That
  is confirmed, with Schneider and Siemens added in the 22 July update.

## Notable conflicts between reporters

1. Poland, 29 December 2025: three attributions. Dragos says ELECTRUM; ESET
   says Sandworm (medium, wiper only); CERT Polska says the Static Tundra /
   Berserk Bear / Ghost Blizzard / Dragonfly cluster, by infrastructure overlap.
2. Voltzite: CISA's AA24-038A lists it as another name for Volt Typhoon; Dragos
   says overlap.
3. Bauxite: CISA's AA26-097A lists it as another name for CyberAv3ngers; Dragos
   says overlap.
4. UNC3236: AA24-038A says Volt Typhoon; Dragos says SYLVANITE overlap.
5. Soldiers of Solomon: AA23-335A says a connected group; AA26-097A says another
   name.
6. Volt Typhoon motivation: Microsoft says espionage; US agencies say
   pre-positioning.
7. ELECTRUM and Sandworm: the Dragos threat page says "now appears independent";
   the Dragos 2026 press release says "shares technical overlaps".

## Open questions

- Read the full Dragos 2026 Year in Review report (PDF). It would confirm the
  stage labels for SYLVANITE, AZURITE and PYROXENE, PYROXENE's overlap list
  (Imperial Kitten), and whether Dragos names the BAUXITE and ELECTRUM 2025 wipers.
- Read CERT Polska's full report PDF for its attribution wording and confidence.
- Read Mandiant's APT44 report PDF for its CARR / hacktivist-persona assessments.
- Confirm the year of Europol's Operation Eastwood from the page header.
- Read vendor primaries for the names the US agencies list (CrowdStrike Hydro
  Kitten, Mandiant UNC5691, Cisco Static Tundra, Microsoft Ghost Blizzard and
  Seashell Blizzard).
- The asymmetry warnings need back-links from other streams: ICS-MAL-0004 to
  ICS-TA-0002; ICS-MAL-0005 to ICS-TA-0018; ICS-INC-0001 and 0002 to
  ICS-TA-0003; ICS-INC-0003 to ICS-TA-0004 and 0018; ICS-INC-0009 to
  ICS-TA-0019; ICS-INC-0008 to ICS-TA-0017.
- The incident record ICS-INC-0008 currently fails to parse (YAML error at line
  50), so its actor links could not be checked.
