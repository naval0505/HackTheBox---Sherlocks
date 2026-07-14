# Sandworm - Hack The Box Sherlock Writeup

## Basic Information

| Category | Details |
|----------|----------|
| Platform | Hack The Box Sherlock |
| Challenge | Sandworm |
| Category | Threat Intelligence |
| Difficulty | Easy |
| Framework | MITRE ATT&CK |

---

# Introduction

Today we are solving another **Hack The Box Sherlock** challenge focused on **Threat Intelligence (CTI)** rather than traditional Digital Forensics or Penetration Testing.

Unlike most Sherlocks where we investigate forensic artifacts, this challenge requires researching one of the most destructive Advanced Persistent Threat (APT) groups ever observed: **Sandworm Team**, also known as **BlackEnergy Group** and **APT44**.

The objective is to utilize the **MITRE ATT&CK Framework** to understand the adversary's behavior, map techniques used across multiple campaigns, and learn how threat intelligence can be translated into actionable defensive knowledge.

Throughout this assessment we will investigate Sandworm's historic attacks against Ukrainian critical infrastructure, identify malware families used throughout multiple campaigns, and understand how MITRE ATT&CK can be leveraged for threat hunting and defensive planning.

---

# Scenario

The provided scenario states:

> Being in the ICS Industry, your security team always needs to be up to date and should be aware of the threats targeting organizations in your industry. You just started as a Threat Intelligence intern, with a bit of SOC experience. Your manager has given you a task to test your skills in research and how well can you utilize MITRE ATT&CK to your advantage.

Our objective is to research the Sandworm Team and answer questions related to their campaigns, malware, techniques, and ATT&CK mappings.

---

# Objectives

During this assessment we aim to:

- Research Sandworm Team.
- Understand MITRE ATT&CK.
- Analyze historical campaigns.
- Identify malware families.
- Map adversary techniques.
- Understand ICS attacks.
- Learn defensive applications of ATT&CK.

---

# Investigation Methodology

The research follows the methodology below.

```
Threat Actor Research
         │
         ▼
MITRE ATT&CK
         │
         ▼
Campaign Analysis
         │
         ▼
Technique Mapping
         │
         ▼
Malware Research
         │
         ▼
ICS Attack Analysis
         │
         ▼
Threat Intelligence Summary
```

---

# About Sandworm Team

Sandworm Team is one of the most sophisticated and destructive nation-state threat groups currently tracked by the cybersecurity community.

The group is widely attributed to:

```
GRU

Unit 74455

Russian Federation
```

Sandworm is also known by several alternative names.

- Sandworm
- BlackEnergy Group
- APT44

Unlike financially motivated ransomware groups, Sandworm primarily targets:

- Governments
- Energy providers
- Critical infrastructure
- Telecommunications
- Military organizations
- Industrial Control Systems (ICS)

Many of the largest cyberattacks against Ukraine have been attributed to this threat actor.

---

# Understanding MITRE ATT&CK

MITRE ATT&CK is a publicly available knowledge base that documents adversary behavior observed during real-world cyberattacks.

Instead of focusing on malware alone, ATT&CK organizes attacker activity into:

- Tactics
- Techniques
- Procedures (TTPs)

Example:

```
Credential Access

↓

OS Credential Dumping

↓

LSASS Memory
```

Every technique receives a unique identifier.

Example:

```
T1003.001
```

This allows defenders to map attacker behavior consistently across different organizations.

---

# Question 1

## When Did Sandworm Begin Operations?

The official MITRE ATT&CK page for Sandworm states that the group has been active:

```
Since at least 2009
```

### Answer

```
2009
```

---

# Why This Matters

Threat actor longevity often indicates:

- Operational maturity
- Extensive infrastructure
- Advanced tooling
- Nation-state resources
- Long-term objectives

Sandworm has remained active for more than a decade and has continuously evolved its capabilities.

---

# Question 2

## Additional Credential Access Technique

During the **2016 Ukraine Electric Power Grid** attack, MITRE documents two primary Credential Access techniques.

The first is:

```
T1003.001

LSASS Memory
```

The second documented technique is:

```
T1110

Brute Force
```

### Answer

```
T1110
```

---

# Analysis

Following initial access, Sandworm performed credential theft using multiple methods.

The attackers:

- Dumped LSASS memory.
- Performed brute-force authentication.
- Expanded access throughout the environment.

Credential Access allowed the attackers to later compromise additional systems across the electrical network.

---

# Understanding the 2016 Ukraine Attack

The 2016 attack remains one of the most important incidents in Industrial Control System (ICS) history.

Objectives included:

- Disrupt electrical power.
- Compromise operator workstations.
- Manipulate SCADA systems.
- Delay recovery efforts.

Unlike ordinary malware campaigns, the attackers directly interacted with industrial control environments.

---

# Question 3

## Identify the VBS Script

MITRE documents that the attackers executed a Visual Basic Script during operations.

The filename recorded is:

```
ufn.vbs
```

### Answer

```
ufn.vbs
```

---

# Why VBScript?

VBScript remains attractive for attackers because:

- Native Windows support.
- Minimal dependencies.
- Easy automation.
- Simple execution.
- Often trusted by administrators.

Scripts are commonly used for:

- Payload delivery.
- Lateral movement.
- Administrative automation.
- Persistence.

---

# Question 4

## Persistence Technique During 2022 Campaign

During the **2022 Ukraine Electric Power Attack**, Sandworm deployed a malicious web shell onto an internet-facing server.

MITRE maps this behavior to:

```
T1505.003

Server Software Component

Web Shell
```

### Answer

```
T1505.003
```

---

# Understanding Web Shells

A web shell provides attackers with remote command execution through an existing web application.

Typical workflow:

```
Internet

↓

Web Server

↓

Web Shell

↓

Remote Commands
```

Advantages include:

- Persistent remote access.
- Blending into normal web traffic.
- Simple command execution.
- Easy file transfers.

---

# Question 5

## Malware Used for Persistence

MITRE identifies the deployed web shell as:

```
Neo-REGEORG
```

### Answer

```
Neo-REGEORG
```

---

# About Neo-REGEORG

Neo-REGEORG is an advanced web shell designed primarily for covert network tunneling.

Capabilities include:

- HTTP tunneling.
- SOCKS proxy creation.
- Internal network access.
- Command execution.

Rather than acting solely as a web shell, it also functions as an effective pivoting tool.

---

# Question 6

## SCADA Binary Used During 2022 Attack

One of the most significant discoveries documented by MITRE is Sandworm's abuse of legitimate SCADA software.

The attackers leveraged:

```
scilc.exe
```

which belongs to the **MicroSCADA** platform.

### Answer

```
scilc.exe
```

---

# Why This Is Significant

Rather than deploying custom malware directly against substations, Sandworm abused legitimate industrial software already trusted within the environment.

This technique significantly reduces detection because:

- Legitimate binaries execute.
- Normal software behavior is abused.
- Security tools often trust signed applications.

This approach is commonly referred to as **Living off the Land**.

---

# Question 7

## Command Used Against Substations

MITRE documents the exact command executed by the attackers.

```
C:\sc\prog\exec\scilc.exe -do pack\scil\s1.txt
```

### Answer

```cmd
C:\sc\prog\exec\scilc.exe -do pack\scil\s1.txt
```

---

# Understanding the Command

Rather than manually issuing commands to substations, Sandworm supplied a predefined instruction file.

```
s1.txt
```

contained SCADA commands that were processed by:

```
scilc.exe
```

This allowed the attackers to issue unauthorized operational commands across multiple substations automatically.

---

# Current Research Findings

At this stage we have successfully identified:

- Sandworm has operated since **2009**.
- The group used **Brute Force (T1110)** alongside **LSASS Memory (T1003.001)** during the 2016 campaign.
- The attackers executed **ufn.vbs** during operations.
- Persistence during the 2022 campaign was achieved using **T1505.003 (Web Shell)**.
- The deployed web shell was **Neo-REGEORG**.
- The attackers abused the trusted **scilc.exe** binary within the MicroSCADA platform.
- The exact command executed against substations was:

```cmd
C:\sc\prog\exec\scilc.exe -do pack\scil\s1.txt
```

The next phase of the research focuses on **CaddyWiper**, **NotPetya**, **AcidRain**, operational security practices, collaboration with **APT28**, MITRE ATT&CK mappings, defensive recommendations, and a complete threat intelligence assessment.


# Question 8

## Malware Used for Data Destruction

Following successful access to the compromised environment during the **2022 Ukraine Electric Power Attack**, Sandworm deployed destructive malware to erase data from infected systems.

Rather than simply disrupting operations, the attackers attempted to permanently destroy systems to delay recovery efforts.

According to MITRE ATT&CK, the malware used for this stage of the attack was:

```
CaddyWiper
```

The malware was distributed through a **Group Policy Object (GPO)**, allowing it to be copied from a staging server onto multiple systems before execution.

The executable observed during deployment was:

```
msserver.exe
```

### Answer

```
CaddyWiper
```

---

# Understanding CaddyWiper

Unlike ransomware that encrypts data for financial gain, **CaddyWiper** is classified as a **wiper malware**.

Its primary objective is:

- Destroy data.
- Render systems unusable.
- Disrupt business operations.
- Prevent rapid recovery.

Once executed, the malware overwrites user data and damages the operating system, making recovery extremely difficult without backups.

---

# Question 9

## Execution Technique Used by CaddyWiper

Beyond deleting files, CaddyWiper also demonstrates advanced execution capabilities.

MITRE ATT&CK documents that the malware dynamically resolves Windows APIs during execution.

This behavior maps to:

```
T1106

Native API
```

### Answer

```
T1106
```

---

# Why Native API Matters

Instead of relying solely on standard Windows libraries, malware often interacts directly with low-level Windows APIs.

Advantages include:

- Improved stealth.
- Lower detection rates.
- Greater control over system resources.
- Easier privilege manipulation.

MITRE specifically notes CaddyWiper's ability to leverage privileges such as:

```
SeTakeOwnershipPrivilege
```

which can facilitate destructive actions against protected files.

---

# Question 10

## Worm-Like Ransomware Used by Sandworm

One of Sandworm's most infamous malware families appeared during the worldwide attacks beginning on:

```
27 June 2017
```

Although initially presented as ransomware, researchers later concluded that the malware's true purpose was irreversible destruction.

The malware is:

```
NotPetya
```

### Answer

```
NotPetya
```

---

# Understanding NotPetya

NotPetya combined characteristics of both:

- Wiper malware.
- Self-propagating worm.

Unlike traditional ransomware:

```
Victim

↓

Pays Ransom

↓

Receives Decryption
```

NotPetya intentionally destroyed encryption keys, making recovery impossible.

The ransom demand merely disguised the malware's destructive intent.

---

# Why NotPetya Was So Dangerous

NotPetya introduced several capabilities rarely combined in previous malware.

These included:

- Worm-like propagation.
- Credential theft.
- Lateral movement.
- SMB exploitation.
- Data destruction.

The attack rapidly spread across:

- Ukraine
- Europe
- United States
- Asia

Ultimately causing billions of dollars in damages worldwide.

---

# Question 11

## Vulnerability Used by NotPetya

MITRE documents that NotPetya spread by exploiting Microsoft's SMBv1 vulnerability.

The associated Microsoft Security Bulletin is:

```
MS17-010
```

### Answer

```
MS17-010
```

---

# Understanding MS17-010

MS17-010 patched multiple SMB vulnerabilities including:

- EternalBlue
- EternalRomance

Once inside a network, NotPetya leveraged these vulnerabilities to automatically spread between vulnerable Windows systems without user interaction.

This capability transformed the malware into one of the fastest-spreading destructive campaigns ever observed.

---

# Question 12

## Malware Used Against Modems

During Russia's full-scale invasion of Ukraine, Sandworm deployed malware targeting communication infrastructure.

MITRE identifies this malware as:

```
AcidRain
```

### Answer

```
AcidRain
```

---

# About AcidRain

Unlike traditional Windows malware, AcidRain specifically targets:

- Routers.
- Satellite modems.
- Embedded Linux devices.

The malware is an ELF executable designed primarily for:

```
MIPS Architecture
```

AcidRain gained international attention after disrupting **Viasat KA-SAT** satellite communications during the opening stages of the invasion.

---

# Question 13

## SSH Listening Port

Threat actors frequently avoid default ports to reduce detection.

MITRE documents that Sandworm configured an SSH service listening on:

```
6789
```

### Answer

```
6789
```

---

# Why Non-Standard Ports?

Moving services away from default ports provides attackers with several advantages.

These include:

- Avoiding simple detection rules.
- Blending with uncommon traffic.
- Reducing automated scanning alerts.
- Supporting operational security (OPSEC).

Although this technique provides only limited protection, it remains common among advanced threat groups.

---

# Question 14

## Collaborating Threat Group

Public reporting indicates that several Sandworm operations involved assistance from another GRU-associated threat actor.

MITRE identifies this collaborating group as:

```
APT28
```

also known as:

```
GRU Unit 26165
```

### Answer

```
APT28
```

---

# Relationship Between Sandworm and APT28

Although tracked as separate threat groups, both organizations have been linked to the Russian General Staff Main Intelligence Directorate (GRU).

Public reporting indicates collaboration during several operations including:

- Ukraine campaigns.
- Political targeting.
- Olympic Destroyer.
- Government espionage.

The relationship demonstrates how nation-state operators often coordinate capabilities across multiple specialized teams.

---

# Sandworm Campaign Timeline

```
2009
│
├── Initial Activity Observed
│
2015
├── Ukraine Power Grid Attack
│
2016
├── Ukraine Electric Power Attack
│
├── BlackEnergy
├── ufn.vbs
├── Credential Dumping
│
2017
├── NotPetya
├── MS17-010
├── Worldwide Destructive Campaign
│
2018
├── Olympic Destroyer
│
2022
├── Ukraine Power Grid Attack
├── Neo-REGEORG
├── scilc.exe
├── CaddyWiper
├── AcidRain
│
Present
└── Continued Operations
```

---

# Malware & Tool Summary

| Malware / Tool | Purpose |
|----------------|---------|
| BlackEnergy | Initial access and ICS operations |
| ufn.vbs | VBScript automation |
| Neo-REGEORG | Web shell and HTTP tunnel |
| scilc.exe | Legitimate SCADA binary abused for command execution |
| CaddyWiper | Data destruction |
| NotPetya | Worm-like destructive malware |
| AcidRain | Router and modem wiper |

---

# MITRE ATT&CK Summary

| Technique | ATT&CK ID |
|------------|-----------|
| LSASS Memory | T1003.001 |
| Brute Force | T1110 |
| Web Shell | T1505.003 |
| Command-Line Interface | T0807 |
| System Binary Proxy Execution | T0894 |
| Native API | T1106 |
| Lateral Tool Transfer | T1570 |

---

# Threat Hunting Opportunities

Security teams protecting Industrial Control Systems should actively monitor for:

- Unusual authentication attempts.
- LSASS memory access.
- Web shell creation.
- Unexpected SCADA command execution.
- Unauthorized use of trusted ICS binaries.
- Group Policy modifications.
- SMB exploitation attempts.
- Non-standard SSH services.
- Large-scale destructive file activity.

Mapping detections to the MITRE ATT&CK framework enables defenders to identify adversary behavior rather than relying solely on malware signatures.

---

# Defensive Recommendations

To defend against Sandworm-style attacks, organizations should:

- Patch publicly exposed systems promptly.
- Disable SMBv1 and apply Microsoft security updates.
- Implement multi-factor authentication for privileged accounts.
- Monitor LSASS access and credential dumping attempts.
- Restrict execution of administrative scripts and web shells.
- Segment Industrial Control Systems from enterprise networks.
- Monitor execution of trusted SCADA binaries for unusual behavior.
- Maintain offline backups to recover from destructive malware.
- Use threat intelligence feeds to track emerging Sandworm infrastructure and TTPs.

---

# Lessons Learned

This Sherlock highlights the value of Cyber Threat Intelligence in understanding sophisticated adversaries before they target an organization. By studying Sandworm's historical campaigns through the MITRE ATT&CK framework, defenders gain insight into the techniques, malware, and operational patterns used across multiple years of activity.

The challenge also demonstrates that modern threat intelligence extends far beyond malware names. Understanding tactics such as credential dumping, web shell deployment, abuse of legitimate SCADA binaries, and destructive wiper malware enables security teams to develop stronger detections and proactive hunting strategies.

Perhaps the most important takeaway is that mapping adversary behavior to MITRE ATT&CK creates a common language between analysts, incident responders, and threat hunters, allowing organizations to improve detection coverage against nation-state threats.

---

# Conclusion

**Sandworm** is an excellent introductory Threat Intelligence Sherlock that demonstrates how publicly available intelligence and the **MITRE ATT&CK** framework can be used to analyze one of the world's most capable nation-state adversaries. Through systematic research, we explored Sandworm's evolution from its early operations in **2009** through major campaigns targeting Ukraine's critical infrastructure, the **NotPetya** global outbreak, and the destructive attacks carried out during the **2022 Ukraine Electric Power Attack**.

The investigation highlighted a wide range of techniques including credential dumping, brute-force authentication, web shell deployment, abuse of trusted SCADA software, destructive wiper malware, and operational security practices. We also examined several malware families associated with the group, including **BlackEnergy**, **Neo-REGEORG**, **CaddyWiper**, **NotPetya**, and **AcidRain**, illustrating how Sandworm combines offensive cyber operations with strategic objectives against industrial and critical infrastructure.

Overall, this Sherlock provides an excellent foundation for learning Cyber Threat Intelligence, demonstrating how defenders can transform threat reports into actionable detection strategies by leveraging the MITRE ATT&CK framework to understand adversary tactics, techniques, and procedures.
