# HTB Sherlock - Noxious Writeup

## Basic Information

| Category | Details |
|----------|----------|
| Platform | Hack The Box Sherlock |
| Challenge | Noxious |
| Category | SOC / Network Forensics |
| Difficulty | Easy |
| Artifact | PCAP |
| Tool Used | Wireshark |

---

# Introduction

Today we are back with another **Hack The Box Sherlock** challenge. Unlike traditional penetration testing machines, Sherlock challenges simulate real-world Security Operations Center (SOC) investigations where analysts are provided with forensic artifacts instead of a live target.

In this challenge, we investigate a suspected **LLMNR Poisoning attack** inside an Active Directory environment. Our objective is to analyze the provided packet capture, determine whether a rogue system performed name resolution poisoning, identify the compromised credentials, and evaluate whether those credentials could have been cracked by the attacker.

This challenge closely resembles incidents frequently observed during internal penetration tests and real-world enterprise breaches where attackers leverage misconfigured name resolution protocols to steal NTLM credentials.

---

# Scenario

The provided scenario states:

> The IDS device alerted us to a possible rogue device in the internal Active Directory network. The Intrusion Detection System also indicated signs of LLMNR traffic, which is unusual. It is suspected that an LLMNR poisoning attack occurred. The LLMNR traffic was directed towards Forela-WKstn002, which has the IP address 172.17.79.136. A limited packet capture from the surrounding time is provided to you, our Network Forensics expert. Since this occurred in the Active Directory VLAN, it is suggested that we perform network threat hunting with the Active Directory attack vector in mind, specifically focusing on LLMNR poisoning.

Our task is to answer several investigative questions by examining the supplied network traffic. :contentReference[oaicite:0]{index=0}

---

# Objectives

Throughout this investigation we aim to:

- Identify the rogue machine
- Determine the attacker's hostname
- Identify the victim account
- Reconstruct the NTLM authentication
- Recover the victim password
- Understand how credentials were leaked
- Determine the intended SMB share
- Explain the attack methodology

---

# Investigation Methodology

The investigation followed the workflow below.

```
Packet Capture
      │
      ▼
Traffic Identification
      │
      ▼
Protocol Analysis
      │
      ▼
LLMNR Investigation
      │
      ▼
DHCP Analysis
      │
      ▼
SMB Authentication
      │
      ▼
NTLM Negotiation
      │
      ▼
Hash Reconstruction
      │
      ▼
Password Recovery
      │
      ▼
Attack Timeline
      │
      ▼
Incident Conclusion
```

---

# Preparing the Investigation

The Sherlock challenge provides a password-protected ZIP archive.

After downloading the challenge, the archive is moved into the working directory.

```bash
mv ~/Downloads/noxious.zip .
```

The archive is extracted using the supplied password.

```
hacktheblue
```

Extraction produces a packet capture file.

```
capture.pcap
```

The investigation is performed primarily inside **Wireshark**, allowing protocol filtering, packet inspection, and credential reconstruction.

---

# Understanding LLMNR

Before beginning packet analysis, it is important to understand the protocol involved.

## What is LLMNR?

**Link-Local Multicast Name Resolution (LLMNR)** is Microsoft's fallback name resolution protocol.

Normally, Windows resolves hostnames using DNS.

If DNS fails to resolve a hostname, Windows attempts to locate the system using LLMNR by broadcasting a multicast request across the local network.

Example:

```
Who has DC01?
```

Every host on the subnet receives this request.

If an attacker is listening with tools such as **Responder**, they can immediately reply:

```
I am DC01.
```

The victim then attempts to authenticate to the attacker's system using NTLM authentication.

The attacker captures the challenge-response exchange without ever knowing the password.

This technique is known as **LLMNR Poisoning**.

---

# Question 1

## Identify the Rogue Device

The first objective is determining which machine responded to the victim's LLMNR requests.

Applying the following display filter:

```
llmnr
```

reveals several multicast name resolution requests and responses.

Among the packets, one system consistently responds to requests that it should not legitimately answer.

The malicious IP address is identified as:

```
172.17.79.135
```

### Answer

```
172.17.79.135
```

---

# Why This Host Is Malicious

During normal operation:

```
Victim
   │
DNS Query
   │
DNS Failure
   │
LLMNR Broadcast
```

Only the legitimate owner of the hostname should respond.

Instead, another workstation immediately answers every failed lookup.

This behavior strongly indicates the presence of a tool such as **Responder**, which automatically poisons LLMNR requests.

---

# Question 2

## Determine the Hostname

Knowing only the IP address is not enough.

The next objective is identifying the hostname associated with the rogue machine.

Filtering traffic using:

```
ip.addr == 172.17.79.135 && dhcp
```

reveals DHCP request packets originating from the suspected attacker.

Inside the DHCP options, Wireshark displays:

```
Option (12)

Host Name
```

The value shown is:

```
kali
```

This immediately identifies the attack platform.

### Answer

```
kali
```

---

# Why DHCP Is Useful

Many analysts immediately jump to SMB traffic.

However, DHCP packets often contain valuable information including:

- Hostname
- Requested options
- Client identifier
- MAC address
- Operating system clues

These packets can quickly identify previously unknown systems without requiring additional investigation.

---

# Question 3

## Determine Which User Was Targeted

Now that the rogue device has been identified, attention shifts toward determining whether any credentials were captured.

Since NTLM authentication occurs over SMB, filtering SMB traffic is the logical next step.

Display filter:

```
smb2
```

Reviewing the authentication packets reveals:

```
NTLMSSP_AUTH
```

Expanding the NTLM authentication details shows:

```
User

john.deacon
```

This confirms that the attacker successfully received NTLM authentication from the victim workstation.

### Answer

```
john.deacon
```

---

# Understanding NTLM Authentication

Windows does not transmit passwords directly.

Instead, authentication follows a challenge-response process.

```
Client
     │
Negotiate
     │
     ▼
Server
     │
Challenge
     │
     ▼
Client
     │
NTLM Response
```

The attacker captures:

- Username
- Domain
- Challenge
- NTProofStr
- NTLM Response

If the password is weak, the response can later be cracked offline.

---

# Question 4

## Determine When Credentials Were Captured

To establish an accurate incident timeline, the timestamp of the first successful authentication must be identified.

Applying the filter:

```
ntlmssp
```

shows every NTLM negotiation exchanged during the attack.

Changing the Wireshark time display to:

```
UTC Date and Time
```

allows direct reading of the timestamp.

The first captured authentication occurs at:

```
2024-06-24 11:18:30 UTC
```

### Answer

```
2024-06-24 11:18:30 UTC
```

---

# Why the Timestamp Matters

Incident responders use timestamps to:

- Correlate IDS alerts
- Match Windows Event Logs
- Build attack timelines
- Identify patient zero
- Determine lateral movement

Even a single packet timestamp can significantly improve an investigation by showing exactly when credential theft occurred.

---

# Question 5

## Determine the Typographical Error

One of the most interesting parts of this challenge is identifying **why** the victim's credentials were leaked.

Examining the LLMNR packets reveals repeated queries for:

```
DCC01
```

Instead of the expected hostname:

```
DC01
```

Because **DCC01** does not exist, DNS fails to resolve the hostname.

Windows therefore falls back to LLMNR, broadcasting the request across the local network.

The attacker's rogue Responder system immediately claims ownership of the non-existent hostname and tricks the victim into authenticating.

This simple typographical mistake ultimately resulted in credential disclosure.

### Answer

```
DCC01
```

---

# Attack Chain So Far

The investigation has reconstructed the following sequence of events:

```
Victim attempts SMB access
          │
          ▼
Mistypes hostname
          │
          ▼
DNS fails
          │
          ▼
LLMNR Broadcast
          │
          ▼
Responder replies
          │
          ▼
Victim trusts attacker
          │
          ▼
NTLM Authentication
          │
          ▼
Credential Capture
```

At this stage we have successfully:

- Identified the rogue workstation
- Determined its hostname
- Confirmed an LLMNR poisoning attack
- Identified the compromised user
- Established the attack timeline
- Determined the user typo that triggered the compromise

The next phase of the investigation focuses on reconstructing the NTLM authentication, extracting the Server Challenge and NTProofStr values, rebuilding the captured hash, recovering the user's password with Hashcat, identifying the intended SMB share, and concluding the forensic investigation.

# Question 6

## Extracting the NTLM Server Challenge

The next objective is to reconstruct the NTLM authentication so that the captured credentials can be cracked offline.

Windows NTLM authentication follows a challenge-response mechanism.

The authentication process consists of three messages:

```
NTLM NEGOTIATE
        │
        ▼
NTLM CHALLENGE
        │
        ▼
NTLM AUTHENTICATE
```

The **Server Challenge** is generated by the server (or in this case, the rogue Responder machine) and is one of the mandatory values required for rebuilding the NetNTLMv2 hash.

Applying the following display filter narrows the traffic to SMB authentication packets.

```
ntlmssp
```

Opening the **NTLMSSP_CHALLENGE** packet reveals:

```
NTLM Secure Service Provider

NTLM Message Type:
NTLMSSP_CHALLENGE
```

Inside the authentication details Wireshark displays:

```
NTLM Server Challenge:
601019d191f054f1
```

This value is generated by the rogue server and sent to the victim before authentication.

### Answer

```
601019d191f054f1
```

---

# Why the Server Challenge Matters

Unlike NTLMv1, NTLMv2 authentication is based on multiple values.

Among them:

- Username
- Domain
- Server Challenge
- Client Challenge
- NTProofStr
- NTLM Response

Without the Server Challenge it is impossible to reconstruct the captured authentication correctly.

---

# Question 7

## Extracting the NTProofStr

The next packet in the authentication exchange contains the **NTLMSSP_AUTH** message.

Expanding:

```
NTLM Secure Service Provider
```

reveals:

```
NTLM Response
```

Inside this section Wireshark conveniently separates the response into its individual components.

The field labelled:

```
NTProofStr
```

contains:

```
c0cc803a6d9fb5a9082253a04dbd4cd4
```

### Answer

```
c0cc803a6d9fb5a9082253a04dbd4cd4
```

---

# Understanding NTProofStr

The NTProofStr is one of the most important parts of a NetNTLMv2 authentication.

It is generated using:

- User password hash
- Server Challenge
- Client Challenge
- Authentication metadata

Hashcat later attempts millions (or billions) of candidate passwords until the generated NTProofStr matches the captured one.

If a match is found, the user's password has been recovered.

---

# Reconstructing the NetNTLMv2 Hash

Before Hashcat can begin cracking, all authentication values must be stitched together into the correct format.

The reconstructed hash becomes:

```
john.deacon::FORELA:601019d191f054f1:c0cc803a6d9fb5a9082253a04dbd4cd4:010100000000000080e4d59406c6da01cc3dcfc0de9b5f2600000000020008004e0042004600590001001e00570049004e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360036004100530035004c00310047005200570054002e004e004200460059002e004c004f00430041004c00030014004e004200460059002e004c004f00430041004c00050014004e004200460059002e004c004f00430041004c000700080080e4d59406c6da0106000400020000000800300030000000000000000000000000200000eb2ecbc5200a40b89ad5831abf821f4f20a2c7f352283a35600377e1f294f1c90a001000000000000000000000000000000000000900140063006900660073002f00440043004300300031000000000000000000
```

This format is directly compatible with Hashcat.

---

# Question 8

## Recovering the Victim Password

With the NetNTLMv2 hash reconstructed, offline password cracking becomes possible.

Hashcat supports NetNTLMv2 using mode:

```
5600
```

Example command:

```bash
hashcat -m 5600 hash.txt rockyou.txt
```

After processing the hash, Hashcat successfully recovers the password.

```
Notmypasswordok?
```

### Answer

```
Notmypasswordok?
```

---

# Why Offline Cracking Is Dangerous

One of the biggest misconceptions regarding NTLM authentication is that attackers immediately obtain passwords.

This is not true.

Instead they capture a challenge-response exchange.

If the password is:

- Weak
- Predictable
- Dictionary based
- Reused

then offline cracking becomes practical.

Because the attack occurs offline:

- No account lockout
- No failed login attempts
- No alerts from Active Directory
- Unlimited cracking attempts

This makes captured NetNTLM hashes extremely valuable.

---

# Question 9

## Determining the Intended SMB Share

The final objective is identifying what the victim originally attempted to access.

Returning to the SMB2 packets shows the requested network resource.

Within the authentication metadata Wireshark displays:

```
Target Name

cifs/DCC01
```

Following the SMB conversation eventually reveals the intended share.

```
\\DC01\DC_Confidential
```

Unfortunately the hostname typo prevented the connection from reaching the legitimate Domain Controller.

Instead the authentication was redirected to the rogue machine.

### Answer

```
DC_Confidential
```

---

# Complete Attack Timeline

The investigation successfully reconstructs the attack from beginning to end.

```
Victim
    │
    ▼
Attempts SMB Share
    │
    ▼
Mistypes Hostname (DCC01)
    │
    ▼
DNS Resolution Fails
    │
    ▼
Windows Falls Back to LLMNR
    │
    ▼
Responder Listens
    │
    ▼
Responder Claims Hostname
    │
    ▼
Victim Connects
    │
    ▼
NTLM Challenge
    │
    ▼
Victim Sends NTLM Authentication
    │
    ▼
Responder Captures Hash
    │
    ▼
Offline Password Cracking
    │
    ▼
Credential Compromise
```

---

# Indicators of Compromise (IOCs)

| IOC | Value |
|------|-------|
| Rogue IP | 172.17.79.135 |
| Rogue Hostname | kali |
| Victim Host | FORELA-WKSTN002 |
| Victim User | john.deacon |
| Protocol | LLMNR |
| Authentication | NTLMv2 |
| Target Share | `\\DC01\DC_Confidential` |
| Server Challenge | 601019d191f054f1 |
| NTProofStr | c0cc803a6d9fb5a9082253a04dbd4cd4 |

---

# MITRE ATT&CK Mapping

| Technique | ID |
|------------|----|
| LLMNR/NBT-NS Poisoning | T1557.001 |
| Adversary-in-the-Middle | T1557 |
| OS Credential Dumping / Credential Access | T1003 (Credential Theft Context) |
| Password Cracking | T1110.002 |
| Valid Accounts | T1078 |

---

# Detection Opportunities

Security teams can detect attacks like this by monitoring:

- Unexpected LLMNR traffic
- Multiple LLMNR responses from a single workstation
- Responder signatures
- Excessive NTLM authentication
- SMB authentication to non-server devices
- Unauthorized DHCP clients
- Network devices answering hostname requests they do not own

Network monitoring solutions such as Microsoft Defender for Identity, Zeek, Suricata, or commercial NDR platforms can identify these behaviors.

---

# Security Recommendations

## Disable LLMNR

The most effective mitigation is disabling LLMNR through Group Policy.

```
Computer Configuration

↓

Administrative Templates

↓

Network

↓

DNS Client

↓

Turn Off Multicast Name Resolution
```

---

## Disable NetBIOS Name Resolution

If legacy systems do not require it, NetBIOS should also be disabled to prevent fallback name resolution attacks.

---

## Enforce Strong Password Policies

Even if hashes are captured, strong passwords significantly increase the time required for offline cracking.

Recommended controls include:

- Minimum 14–16 characters
- Passphrases instead of dictionary words
- Password manager usage
- Regular password rotation where appropriate

---

## SMB Signing

Enable SMB Signing wherever possible to reduce the effectiveness of relay-based attacks.

---

## Network Segmentation

Restrict workstation-to-workstation communication.

Only legitimate servers should be reachable for SMB authentication.

---

## User Awareness

This investigation highlights how a single typographical mistake resulted in credential theft.

Users should:

- Verify server names before connecting.
- Report repeated authentication prompts.
- Avoid manually typing UNC paths whenever possible.

---

# Lessons Learned

This Sherlock demonstrates how seemingly harmless protocols can become major security risks inside Active Directory environments.

Several important lessons emerge from the investigation:

- LLMNR should never remain enabled unless absolutely necessary.
- Rogue responders can silently capture NTLM authentication.
- Offline password cracking remains a serious threat when weak passwords are used.
- Packet captures contain enough information to completely reconstruct an authentication exchange.
- Careful protocol analysis allows investigators to identify both the attacker and the victim without requiring endpoint access.

Perhaps the most valuable takeaway is that no exploit was required. The attacker simply abused default Windows behavior and waited for a user to make a minor typing mistake.

---

# Conclusion

The **Noxious** Sherlock provides an excellent introduction to Windows network forensics and Active Directory attack analysis. Through careful examination of a packet capture, we successfully identified a rogue Responder system performing an LLMNR poisoning attack, traced the malicious host, reconstructed the NTLM authentication process, recovered the captured credentials, and determined the exact network resource the victim intended to access.

The challenge demonstrates how attackers can leverage legacy name resolution protocols to steal credentials without exploiting software vulnerabilities. A simple hostname typo caused Windows to fall back to LLMNR, allowing a rogue device to impersonate the requested host and capture the victim's NetNTLMv2 authentication. Once obtained, the captured hash was reconstructed and cracked offline, proving that weak passwords remain a significant security risk even when passwords are never transmitted directly across the network.

From a defensive perspective, disabling LLMNR and NetBIOS, enforcing strong password policies, enabling SMB signing, and monitoring for abnormal multicast name resolution traffic are highly effective measures for mitigating this class of attack. Overall, Noxious serves as an excellent exercise for SOC analysts and incident responders, reinforcing the importance of protocol analysis, attack timeline reconstruction, and understanding Windows authentication mechanisms during network forensic investigations.
