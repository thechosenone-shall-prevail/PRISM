"""
PRISM Demo Scenarios
Pre-built realistic attack scenarios for demonstration purposes.
"""

DEMO_SCENARIOS = {
    "lazarus_crypto": {
        "name": "Cryptocurrency Exchange Heist",
        "description": "Multi-stage attack on a Southeast Asian crypto exchange. Analyst observations from incident response.",
        "threat_context": "Financial sector targeting, cryptocurrency focus",
        "timeline": "3 weeks",
        "input_text": """
Incident Response Observations - Case #IR-2024-0847

Initial vector: Spearphishing email with malicious attachment sent to finance team.
Macro-enabled Excel document dropped a loader upon opening.

Week 1:
- Encoded PowerShell payload executed via scheduled task
- Process injection observed into legitimate Windows process (svchost)
- VM detection and sandbox evasion routines identified in loader
- LSASS memory access detected (credential dumping)
- Obfuscated binary with packed sections identified

Week 2:
- Lateral movement via RDP using stolen credentials
- Pass the hash observed for admin share access
- Screen capture module deployed
- Data staging in temp directory with zip compression
- Cryptocurrency wallet files specifically targeted

Week 3:
- DNS tunneling for C2 beacon (randomized 2-4 hour intervals)
- HTTPS exfiltration to actor-controlled domain
- Multi-hop proxy chain through compromised hosts
- Evidence of time-based delays in execution (sandbox evasion)
- Inhibit system recovery - shadow copy deletion observed

Target: cryptocurrency exchange
Industry: Financial, Cryptocurrency
Region: Southeast Asia
Suspected motivation: Financial theft
        """,
    },

    "sandworm_ics": {
        "name": "Energy Grid Attack",
        "description": "Attack against European energy infrastructure. Combines espionage phase with destructive payload.",
        "threat_context": "Critical infrastructure, energy sector, destructive intent",
        "timeline": "6 weeks",
        "input_text": """
CERT Advisory - Critical Infrastructure Incident

Observed attack chain targeting European energy grid operator:

Phase 1 - Initial Compromise:
- Spearphishing with exploit targeting public-facing application
- Valid accounts used after initial compromise
- Windows service created for persistence

Phase 2 - Reconnaissance:
- Network share enumeration across OT/IT boundary
- SCADA system discovery
- ICS protocol analysis traffic observed
- Power grid topology mapping

Phase 3 - Lateral Movement:
- SMB lateral movement using admin shares
- Credential dumping via LSASS
- Lateral tool transfer to ICS environment

Phase 4 - Destructive Payload:
- Wiper malware deployed to engineering workstations
- Inhibit system recovery - all backups targeted
- Data destruction across industrial control systems
- Power grid disruption capability activated
- Defacement of monitoring dashboards

C2: Custom protocol, Tor-based fallback
Target: Energy infrastructure, Ukraine region
Motivation: Destruction, disruption
Infrastructure: Critical infrastructure, ICS/SCADA
        """,
    },

    "apt29_supply_chain": {
        "name": "Software Supply Chain Infiltration",
        "description": "Long-dwell supply chain compromise discovered after 8 months. Mimics SUNBURST-style operation.",
        "threat_context": "Supply chain, government, extreme stealth, long dwell time",
        "timeline": "8 months",
        "input_text": """
Supply Chain Security Investigation

Discovery of compromise in enterprise software update mechanism:

Compromise vector:
- Software supply chain attack via compromised build system
- Backdoor injected into legitimate software update (T1195.002)
- Signed with legitimate certificate - trusted by all endpoints
- Deployed to 15,000+ endpoints via standard update channel

Behavioral observations:
- Dwell time: approximately 8 months before discovery
- Beacon interval: 12-72 hours (highly irregular, long delays)
- C2 via legitimate cloud services (OneDrive, SharePoint)
- OAuth token theft and abuse for persistence
- Living off the land - no custom malware post-initial access
- Exfiltration only via legitimate cloud storage platforms
- Staged collection: only valuable targets received second stage
- Account manipulation for persistent access
- Minimal footprint - file deletion after execution

Targeting:
- Government agencies (multiple)
- Defense contractors
- Think tanks and research institutions
- Technology companies
- NGOs

No destructive payload. Pure intelligence collection operation.
Extreme operational security. Minimal language artifacts.
Evidence of long-term pre-positioning and patience.
Target: Government, Think Tanks
Motivation: Intelligence collection, espionage
        """,
    },

    "apt35_middle_east": {
        "name": "Iranian Targeting of Israeli Research",
        "description": "Spearphishing campaign against Israeli nuclear and defense researchers during Middle East conflict.",
        "threat_context": "Middle East conflict, Israel targeting, nuclear research, dissidents",
        "timeline": "2 months",
        "input_text": """
Threat Intelligence Report - Middle East APT Activity

Campaign targeting Israeli academic and defense institutions:

Initial access:
- Spearphishing via email with links to fake conference registration sites
- Spearphishing via service (LinkedIn, WhatsApp messages)
- Browser extension installed for credential harvesting
- MFA bypass via web portal capture

Social engineering:
- Highly personalized emails referencing real conferences
- Spoofed university and academic institution domains
- Targeting of nuclear research faculty
- Surveillance of Iranian dissidents abroad

Execution and persistence:
- VBScript and PowerShell payloads
- Registry Run Keys for persistence
- Scheduled tasks

Collection:
- Email collection from Outlook (local and remote)
- Browser cookie theft - session token abuse
- Keylogging module deployed
- Telegram bot used for exfiltration

C2:
- HTTPS beacon (30 min - 4 hour intervals)
- Telegram API abuse for command delivery
- Cloud storage (Google Drive) for data exfiltration

Language artifacts: Farsi strings identified in loader
Timezone analysis: Tehran working hours (UTC+3:30)
Target sectors: Nuclear research, academic, defense, journalism
Regions: Israel, Europe (diaspora)
Motivation: Espionage, counter-dissidence, nuclear intelligence
        """,
    },

    "volt_typhoon_lotl": {
        "name": "Critical Infrastructure Pre-Positioning",
        "description": "Detection of pre-positioned threat in US communications infrastructure using only built-in tools.",
        "threat_context": "Living off the land, critical infrastructure, no custom malware, pre-positioning",
        "timeline": "18 months (estimated)",
        "input_text": """
CISA/FBI Joint Investigation - Critical Infrastructure Pre-positioning

Long-term access discovered in US communications provider:

Detection method: Anomaly in legitimate admin tool usage patterns

Key observations:
- Zero custom malware identified - exclusively living off the land
- All activity used built-in Windows tools: PowerShell, cmd, wmic, netsh
- LOLBin usage for all discovery and lateral movement
- SOHO router network used as proxy infrastructure
- Traffic routed through compromised small office routers globally
- Non-standard port usage to blend with legitimate traffic

Techniques observed:
- Exploit public-facing application for initial foothold
- Valid accounts used extensively (no malware needed)
- Living off the land throughout entire campaign
- Scheduled task for persistence using only built-in tools
- Rundll32 and certutil for tool execution
- Network discovery using built-in tools (netstat, ipconfig, nltest)
- RDP and SSH for lateral movement with stolen credentials
- Data collected and staged - no exfiltration yet observed
- Long dwell time estimated 18 months

Infrastructure:
- C2 through compromised SOHO routers
- Protocol tunneling through legitimate services
- External proxy chains

Assessment: Pre-positioning for potential future activation
No destructive activity yet observed
Target: Communications infrastructure, energy, transportation
Motivation: Pre-positioning, strategic access
Nation-state context: Pacific geopolitical tensions
        """,
    },

    "apt28_nato": {
        "name": "NATO Government Espionage Campaign",
        "description": "Multi-vector campaign against NATO member defense ministries. Combines credential harvesting with custom implants.",
        "timeline": "4 months",
        "input_text": """
Intelligence Advisory - NATO Member Targeting

Active campaign against European defense ministries and political organizations:

Initial access:
- Spearphishing emails impersonating NATO communications
- Exploit public-facing Outlook Web Access servers
- Valid accounts obtained through credential phishing portals
- Password spray attacks against government mail systems

Execution:
- PowerShell execution via scheduled tasks
- WMI for remote code execution
- Macro-enabled documents with staged delivery

Persistence:
- Registry Run Keys for persistence
- UEFI bootkit implant on high-value targets (system firmware)
- Windows services for long-term access
- Scheduled tasks with encoded PowerShell

Credential access:
- LSASS credential dumping
- Kerberoasting against Active Directory
- Cookie theft from browser sessions
- Pass the hash for lateral movement

Lateral movement:
- Remote Desktop Protocol with stolen credentials
- Windows Remote Management (WinRM)
- Pass the ticket attacks

Collection and exfiltration:
- Email collection from Outlook local mailboxes
- Email collection from remote Exchange servers
- Data archived and compressed before exfil
- Exfiltration via compromised email accounts

C2:
- HTTPS beacon (irregular 15 min - 4 hour intervals)
- OneDrive and Dropbox used as dead drops
- Anti-debug and encrypted strings in implant

Language markers: Russian debug strings in older samples
Target: NATO government, defense, political organizations, election infrastructure
Region: Europe, United States, Ukraine
Motivation: Espionage, political intelligence, election interference
        """,
    },

    "apt41_supply_chain": {
        "name": "Dual-Purpose Supply Chain Attack",
        "description": "APT41's signature dual-hat operation: state espionage combined with financially motivated compromise.",
        "timeline": "5 months",
        "input_text": """
Incident Investigation - Software Vendor Compromise

Discovery of compromise in enterprise software vendor:

Phase 1 - Supply Chain Compromise:
- Exploit public-facing application on build server
- Valid accounts used to access source code repository
- Backdoor injected into legitimate software update (supply chain)
- Code signing certificate stolen and abused
- Software deployment tools used for distribution

Phase 2 - Espionage Collection:
- Targeted government and defense contractor clients
- Process injection for stealth
- Rootkit-level capabilities to hide presence
- Data from local system collected systematically
- Network shared drive enumeration and collection

Phase 3 - Financial Operations:
- Simultaneously targeted gaming company clients
- Ransomware deployed against non-strategic targets
- Cryptocurrency mining on compromised infrastructure

Persistence:
- Hijack execution flow via DLL side-loading
- Windows services for persistent access
- Web shells deployed on public-facing servers
- Scheduled tasks with encoded commands

C2:
- Custom TCP protocol with encrypted channel
- DNS C2 as fallback
- Multiple proxy layers

Language artifacts: Chinese language artifacts, Simplified Chinese
Target: Technology, healthcare, telecommunications, gaming, defense
Region: United States, Europe, Southeast Asia, Taiwan
Motivation: Espionage and financial dual-purpose
        """,
    },

    "kimsuky_think_tank": {
        "name": "Intelligence Collection Against Policy Researchers",
        "description": "Highly targeted spearphishing campaign against North Korea policy experts and nuclear researchers.",
        "timeline": "6 months",
        "input_text": """
Threat Intelligence Report - Academic and Policy Sector Targeting

Long-running campaign against North Korea policy researchers:

Initial access:
- Spearphishing emails impersonating fellow researchers and journalists
- Malicious links to fake academic portals
- Credential harvesting via spoofed Google/Naver login pages
- Browser extension installed to capture credentials

Social engineering:
- Highly personalized emails mentioning real conferences and papers
- Impersonation of known academics in the field
- Multi-week rapport building before payload delivery

Execution:
- VBScript downloaders in document attachments
- PowerShell second-stage payload
- User execution of malicious files disguised as research papers

Persistence:
- Registry Run Keys for startup
- Scheduled tasks set to weekly cadence
- Browser extension for persistent credential access

Collection:
- Local email collection from Outlook and Thunderbird
- Screen capture at regular intervals
- Keylogging module active on target systems
- Specific targeting of documents related to North Korea policy

Exfiltration:
- Email forwarding rules created for persistent collection
- Cloud service exfiltration (Google Drive)
- Low-volume exfil to avoid detection

C2:
- HTTPS to actor-controlled domains (12-48 hour beacon)
- Email-based C2 through compromised Google accounts
- Telegram-based command delivery

Language: Korean language artifacts in decoy documents
Target: Think tanks, nuclear research, policy research, academic
Region: South Korea, United States, Japan
Motivation: Intelligence collection on foreign policy positions
        """,
    },

    "muddywater_telecom": {
        "name": "Middle East Telecom and Government Intrusion",
        "description": "Campaign using legitimate RMM tools against Middle Eastern telecoms and government entities.",
        "timeline": "3 months",
        "input_text": """
CERT Incident Report - Government and Telecom Targeting

Active intrusion into Middle Eastern telecommunications provider and government ministry:

Initial access:
- Spearphishing with macro-enabled documents
- Malicious link campaigns targeting government employees
- Valid accounts obtained through credential harvesting

Execution and persistence:
- PowerShell execution with heavy obfuscation
- VBScript droppers delivering second-stage payload
- Registry Run Keys for persistence
- Scheduled tasks for execution
- Windows service installation

Unique tradecraft:
- Extensive abuse of legitimate RMM tools for C2:
  - SimpleHelp deployed as primary remote access
  - Atera installed on secondary targets
  - ScreenConnect used for interactive sessions
- PowerShell scripts with multi-layer encoding
- Rundll32 used for proxy execution

Credential access:
- LSASS memory dumping on domain controllers
- Cookie and session token theft from browsers

Lateral movement:
- RDP with stolen credentials
- SMB/admin share access
- Software deployment tools for spreading

Collection:
- Local file collection focused on sensitive documents
- Email collection from Exchange servers
- Data staged in archive files

C2:
- SimpleHelp RMM tool (legitimate software, no signatures)
- HTTPS fallback to custom infrastructure
- High infrastructure reuse with recycled phishing templates

Language: Farsi artifacts in PowerShell scripts
Target: Government, telecommunications, oil and gas
Region: Middle East, Turkey, Pakistan
Motivation: Espionage, surveillance
        """,
    },

    "transparent_tribe_india": {
        "name": "Indian Defense Forces Targeting",
        "description": "Persistent espionage campaign against Indian military and government with CrimsonRAT and mobile malware.",
        "timeline": "Ongoing (years)",
        "input_text": """
Military Intelligence Advisory - Defense Sector Targeting

Persistent campaign targeting Indian armed forces personnel:

Initial access:
- Spearphishing with defense-themed documents
- Malicious links in WhatsApp and email
- Watering hole attacks on defense-related websites
- India-Pakistan conflict-themed lures

Execution:
- VBScript and PowerShell droppers
- Macro-enabled documents delivering CrimsonRAT
- User execution of files disguised as defense circulars

Persistence:
- Registry Run Keys
- Scheduled tasks

Mobile targeting:
- CapraRAT Android malware distributed via fake messaging apps
- Trojanized versions of legitimate apps targeting military personnel
- Audio capture and video capture capabilities on mobile
- GPS tracking of military targets

Desktop capabilities:
- Screen capture at regular intervals
- Keylogging for credential and intelligence capture
- File enumeration and theft of defense documents
- Process listing for environment awareness

C2:
- HTTP/HTTPS C2 (active 30min-2 hour intervals)
- Custom TCP protocol for data transfer
- High infrastructure reuse - same C2 servers active for months

Language: Urdu language artifacts in malware strings
Target: Defense, military, government, education
Region: India (exclusively), Afghanistan
Motivation: Military intelligence, espionage
        """,
    },

    "salt_typhoon_telecom": {
        "name": "US Telecom Wiretap System Breach",
        "description": "Deep infiltration of major US telecommunications providers. Compromise of lawful intercept systems.",
        "timeline": "12+ months",
        "input_text": """
National Security Advisory - Telecommunications Infrastructure Breach

Deep compromise of US telecommunications infrastructure:

Discovery:
- Anomalous kernel-level activity on telecom core routers
- Unauthorized access to lawful intercept (wiretap) systems
- Network sniffing infrastructure deployed at carrier level

Initial access:
- Exploit public-facing application on network equipment
- Valid accounts with elevated ISP credentials
- External remote services targeted

Techniques:
- Rootkit deployment on network infrastructure
- Kernel driver installation for persistent access
- Network sniffing at carrier backbone level
- Automated collection of communications metadata
- Protocol tunneling through legitimate telecom traffic
- Non-standard port usage

Scope:
- AT&T, Verizon, T-Mobile confirmed compromised
- Lawful interception systems accessed
- Call metadata for government officials collected
- Text messages and call records of political figures intercepted

Persistence:
- Windows service creation on management servers
- Valid account abuse across multiple carriers
- Scheduled tasks for maintenance access

C2:
- Custom TCP through telecom backbone
- Encrypted channel via standard protocols
- Protocol tunneling through carrier traffic

Target: Telecommunications, ISP, government communications
Region: United States
Motivation: Signals intelligence, communications intelligence
Assessment: Most significant telecom breach in US history
        """,
    },

    "turla_diplomatic": {
        "name": "Diplomatic Network Infiltration",
        "description": "Long-running espionage operation against European diplomatic missions using satellite C2.",
        "timeline": "24+ months",
        "input_text": """
Counter-Intelligence Investigation - Diplomatic Espionage

Discovery of long-running espionage operation targeting European diplomatic networks:

Initial access:
- Spearphishing emails with diplomatic-themed content
- Watering hole attacks on diplomatic news portals
- Exploit public-facing application on embassy VPN
- Valid accounts obtained through prior credential operations

Advanced tradecraft:
- Kernel rootkit (Snake/Uroburos) deployed on high-value targets
- Encrypted virtual filesystem for payload and log storage
- Named pipe communication between implant components
- Reflective code loading to avoid disk artifacts

Persistence:
- Windows service with rootkit concealment
- Hijack execution flow via DLL side-loading
- Web shells on public-facing diplomatic portals
- Valid account abuse

Credential access:
- OS credential dumping across domain controllers
- Kerberos ticket theft
- Unsecured credentials harvested from configuration files

Discovery and collection:
- Systematic account enumeration
- Permission group discovery
- Domain trust analysis
- Email collection from diplomatic mail servers
- Data staged and archived with encryption

C2:
- Multi-hop proxy through compromised diplomatic networks
- Custom protocol with encrypted channel
- Satellite internet channel as covert backup
- Extremely long beacon interval: 24-96 hours

Language: Russian language artifacts in early tooling generations
Target: Government, diplomatic, defense, research
Region: Europe, Middle East, NATO members
Motivation: Strategic intelligence, diplomatic espionage
        """,
    },
}


def get_demo_names():
    return {k: v["name"] for k, v in DEMO_SCENARIOS.items()}


def get_demo_scenario(key: str) -> dict:
    return DEMO_SCENARIOS.get(key, {})