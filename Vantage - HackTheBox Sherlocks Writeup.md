# Hack The Box Sherlock - Vantage Writeup

## Overview

Today we are going to investigate another **Hack The Box Sherlock challenge**, this time an **easy cloud and network-forensics case** named **Vantage**.

The scenario provided for the challenge is:

> A small company moved some of its resources to a private cloud installation. The developers left the redirect to the dashboard on their web server. The security team received an email from the alleged attacker stating that user data had been leaked. It is up to us to investigate what happened.

The challenge provides two packet captures:

* `web-server.2025-07-01.pcap`
* `controller.2025-07-01.pcap`

The goal of the investigation is to reconstruct the attacker’s activity from both captures, determine how the attacker accessed the environment, what cloud resources were touched, what data was stolen, and whether persistence was established.

This challenge is a good example of a **cloud-focused intrusion investigation** where the attacker first abuses a web-facing application, gains access to a private cloud dashboard, downloads OpenStack API access configuration, and then uses the **OpenStack API directly** to enumerate resources, access object storage, steal data, and create a new privileged user for persistence.

---

# Table of Contents

* [Scenario Summary](#scenario-summary)
* [Evidence Provided](#evidence-provided)
* [Investigation Goals](#investigation-goals)
* [High-Level Attack Flow](#high-level-attack-flow)
* [Analysis Methodology](#analysis-methodology)
* [Phase 1 - Web Server Traffic Analysis](#phase-1---web-server-traffic-analysis)

  * [Q1 - Fuzzing Tool Used by the Attacker](#q1---fuzzing-tool-used-by-the-attacker)
  * [Q2 - Subdomain Discovered by the Attacker](#q2---subdomain-discovered-by-the-attacker)
  * [Q3 - Number of Login Attempts Before Success](#q3---number-of-login-attempts-before-success)
  * [Q4 - Download of the OpenStack OpenRC Config File](#q4---download-of-the-openstack-openrc-config-file)
* [Phase 2 - Controller Traffic Analysis](#phase-2---controller-traffic-analysis)

  * [Q5 - First API Interaction on the Controller Node](#q5---first-api-interaction-on-the-controller-node)
  * [Q6 - Default Project ID Accessed by the Attacker](#q6---default-project-id-accessed-by-the-attacker)
  * [Q7 - OpenStack Service Responsible for Authentication and Authorization](#q7---openstack-service-responsible-for-authentication-and-authorization)
  * [Q8 - Endpoint URL of the Swift Service](#q8---endpoint-url-of-the-swift-service)
  * [Q9 - Number of Containers Discovered by the Attacker](#q9---number-of-containers-discovered-by-the-attacker)
  * [Q10 - Time Sensitive User Data Was Downloaded](#q10---time-sensitive-user-data-was-downloaded)
  * [Q11 - Number of User Records in the Sensitive Data File](#q11---number-of-user-records-in-the-sensitive-data-file)
  * [Q12 - Username of the New Admin User Created for Persistence](#q12---username-of-the-new-admin-user-created-for-persistence)
  * [Q13 - Password of the New User](#q13---password-of-the-new-user)
  * [Q14 - MITRE ATT&CK Technique for the Persistence Action](#q14---mitre-attck-technique-for-the-persistence-action)
* [Detailed Timeline of the Intrusion](#detailed-timeline-of-the-intrusion)
* [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
* [MITRE ATT&CK Mapping](#mitre-attck-mapping)
* [Key Findings](#key-findings)
* [Conclusion](#conclusion)

---

# Scenario Summary

The challenge centers around a private cloud deployment that was exposed through a web-facing system. The developers appear to have left a redirect or reference to the internal cloud dashboard on the public-facing web server. The attacker used that exposure to locate the dashboard, authenticate successfully, and download an **OpenStack API remote access configuration file**.

After obtaining the API access configuration, the attacker moved away from the web interface and began interacting directly with the **OpenStack API** on the controller node. Through that API access, the attacker:

* authenticated to the cloud services,
* enumerated projects and service endpoints,
* discovered the Swift object storage endpoint,
* enumerated storage containers,
* downloaded a sensitive user data file,
* and finally created a new administrative cloud user for persistence.

So this case is not just about a web login compromise. It is about **pivoting from a web dashboard into direct cloud API abuse**.

---

# Evidence Provided

The challenge provides two packet captures:

## 1. `web-server.2025-07-01.pcap`

This capture contains the attacker’s interaction with the public-facing web application and the cloud dashboard.

## 2. `controller.2025-07-01.pcap`

This capture contains the attacker’s activity against the **OpenStack controller node**, including direct API requests after the OpenRC file was downloaded.

---

# Investigation Goals

The investigation focuses on answering the following questions:

1. What fuzzing tool was used?
2. Which subdomain was discovered?
3. How many login attempts were made before successful access to the dashboard?
4. When was the OpenStack API remote access config file downloaded?
5. When did the attacker first interact with the controller API?
6. What project ID was used?
7. Which OpenStack service handled authentication and authorization?
8. What was the Swift endpoint?
9. How many containers were discovered?
10. When was the sensitive data file downloaded?
11. How many user records were in that file?
12. What user was created for persistence?
13. What password was assigned to that user?
14. What MITRE ATT&CK technique maps to the persistence action?

---

# High-Level Attack Flow

Before diving into each packet capture, it is useful to summarize the attack chain at a high level:

1. The attacker probes the public web server and fuzzes it for hidden resources.
2. A cloud-related subdomain is discovered: `cloud.vantage.tech`.
3. The attacker attempts to log into the cloud dashboard and eventually succeeds using valid credentials.
4. From the dashboard, the attacker downloads the **OpenRC** file, which provides API access configuration for OpenStack.
5. Using the OpenRC data and valid credentials, the attacker begins talking directly to the **controller node API**.
6. The attacker authenticates through **Keystone**, enumerates service endpoints, and identifies the **Swift object storage** endpoint.
7. The attacker lists storage containers and accesses a sensitive user data file.
8. Finally, the attacker creates a new user with admin privileges to maintain persistent access.

This sequence shows a complete transition from **web discovery → dashboard compromise → cloud API abuse → data theft → persistence**.

---

# Analysis Methodology

The investigation was carried out using **Wireshark** and focused primarily on **HTTP traffic** in both packet captures.

The methodology was:

1. Open the web-server PCAP and identify the attacker’s recon and dashboard activity.
2. Filter for suspicious HTTP requests, especially login attempts and API access pages.
3. Identify the OpenRC download event and note the timestamp in UTC.
4. Open the controller PCAP and pivot to the attacker’s API traffic.
5. Follow authentication requests, endpoint enumeration, and object storage access.
6. Reconstruct the timeline from first API interaction to data theft and persistence.

The investigation is split into **two major phases**:

* **Phase 1** → Web server and dashboard activity
* **Phase 2** → Controller node / OpenStack API activity

---

# Phase 1 - Web Server Traffic Analysis

The first capture to analyze is:

```text id="l1p8ku"
web-server.2025-07-01.pcap
```

This file contains the attacker’s interaction with the company’s web server and the exposed cloud dashboard.

---

# Q1 - Fuzzing Tool Used by the Attacker

## Question

**What tool did the attacker use to fuzz the web server?**
Format expected: include version, e.g. `nmap@7.80`

## Answer

```text id="o6a4lu"
ffuf@2.1.0
```

## Analysis

The investigation started with the **web-server** capture because the scenario indicates that the attacker first interacted with the public web application before pivoting to the cloud dashboard.

Filtering around the early HTTP requests revealed signs of **directory and resource fuzzing**, and the requests contained identifiers consistent with **ffuf**. The user-agent and request pattern were enough to identify the tool and its version.

### Why this matters

This tells us that the attacker did not immediately know the target paths. Instead, they performed **content discovery / fuzzing** against the web server to locate hidden pages, subdomains, or routes that could lead to internal functionality.

So the attack began with **reconnaissance and discovery**, not direct exploitation.

---

# Q2 - Subdomain Discovered by the Attacker

## Question

**Which subdomain did the attacker discover?**

## Answer

```text id="j3gq5d"
cloud.vantage.tech
```

## Analysis

Still within the `web-server` PCAP, the next task was to determine which hidden resource or subdomain the attacker ultimately found during enumeration.

A key packet later in the capture shows the attacker requesting the cloud dashboard API access page:

```http id="d1t2vu"
GET /dashboard/project/api_access/ HTTP/1.1
Host: cloud.vantage.tech
...
[Full request URI: http://cloud.vantage.tech/dashboard/project/api_access/]
```

This request makes the discovered subdomain clear:

```text id="xov99f"
cloud.vantage.tech
```

## Why this matters

This is the pivot point in the intrusion. The attacker moved from the public-facing web server to the **cloud dashboard subdomain**, which exposed internal cloud management functionality.

In other words, the fuzzing activity was successful because it led to the cloud portal that would later be abused.

---

# Q3 - Number of Login Attempts Before Success

## Question

**How many login attempts did the attacker make before successfully logging in to the dashboard?**

## Answer

```text id="fq2w7k"
4 login attempts
```

## Analysis

To answer this, the traffic was filtered for requests to the dashboard login endpoint:

```text id="n33k8n"
http.request.full_uri == "http://cloud.vantage.tech/dashboard/auth/login/"
```

Reviewing the matching requests in the web-server PCAP showed a sequence of repeated login attempts. By tracing the requests and their responses, it became clear that the attacker did not succeed on the first try. Instead, the login endpoint was hit multiple times before a valid session was established.

The notes indicate that the attacker eventually logged in using:

```text id="usl58w"
admin : StrongAdminSecret
```

and that the total number of attempts observed before success was:

```text id="t4lf3r"
4
```

## Why this matters

This confirms that the attacker either:

* was guessing or testing multiple credential combinations,
* or already had partial credential knowledge and was trying variants until one worked.

The important takeaway is that the dashboard was not accessed anonymously. The attacker authenticated successfully, which allowed them to reach the **API access area** and obtain the OpenRC file.

---

# Q4 - Download of the OpenStack OpenRC Config File

## Question

**When did the attacker download the OpenStack API remote access config file? (UTC)**

## Answer

```text id="v9ylg0"
2025-07-01 09:40:29 UTC
```

## Analysis

The packet of interest in the web-server capture is a request for the OpenStack API access config file:

```http id="nksjpb"
GET /dashboard/project/api_access/openrc/ HTTP/1.1
Host: cloud.vantage.tech
...
[Full request URI: http://cloud.vantage.tech/dashboard/project/api_access/openrc/]
```

This request is critical because it shows the attacker explicitly downloading the **OpenRC file** from the dashboard.

## Why the OpenRC file matters

In OpenStack environments, an OpenRC file is not just a harmless config file. It is effectively a **cloud API access bootstrap file**. It typically contains environment variables and endpoint references needed to authenticate to the OpenStack services from the command line or via SDKs.

Once an attacker has:

* valid dashboard credentials
* and the OpenRC file

they can stop using the browser and instead interact directly with the cloud API.

After changing Wireshark’s time display to UTC, the timestamp for this request was identified as:

```text id="jlwmft"
2025-07-01 09:40:29
```

This marks the transition from **dashboard access** to **cloud API operations**.

---

# Phase 2 - Controller Traffic Analysis

After the OpenRC file was downloaded, the next phase of the intrusion moved to the controller node. That activity is captured in:

```text id="cc0v3u"
controller.2025-07-01.pcap
```

This PCAP shows the attacker interacting directly with the OpenStack API rather than the web dashboard.

---

# Q5 - First API Interaction on the Controller Node

## Question

**When did the attacker first interact with the API on the controller node? (UTC)**

## Answer

```text id="n7j7oc"
2025-07-01 09:41:44 UTC
```

## Analysis

To determine the first controller-side interaction, the traffic in `controller.2025-07-01.pcap` was inspected for the earliest API requests coming from the attacker IP.

The first relevant interaction identified was a request involving:

```text id="yknx8f"
http://134.209.71.220:2379/v3/lease/keepalive
```

After reviewing the packet timestamps in UTC, the earliest controller API interaction was determined to be:

```text id="szz0dz"
2025-07-01 09:41:44
```

## Why this matters

This timestamp is only about a minute after the OpenRC file download at `09:40:29`, which strongly supports the attack sequence:

1. attacker logs into dashboard
2. downloads OpenRC config
3. immediately begins using API tooling against the controller node

This is exactly what we would expect in a cloud compromise where the attacker pivots from the web interface into API automation.

---

# Q6 - Default Project ID Accessed by the Attacker

## Question

**What is the project ID of the default project accessed by the attacker?**

## Answer

```text id="s32ksu"
9fb84977ff7c4a0baf0d5dbb57e235c7
```

## Analysis

To answer this, HTTP POST requests involving the identity service were examined. A useful filter was:

```text id="n9s8hf"
http.request.method == "POST" && http.request.uri contains "identity"
```

One of the most important packets in the controller capture is the following request:

```http id="shaqtz"
POST /identity/v3/users HTTP/1.1
Host: 134.209.71.220
User-Agent: openstacksdk/4.6.0 keystoneauth1/5.11.1 python-requests/2.32.4 CPython/3.13.5
...
```

The JSON body of this request contains:

```json id="n6r7b0"
"default_project_id": "9fb84977ff7c4a0baf0d5dbb57e235c7"
```

So the project ID used by the attacker was:

```text id="wub9q8"
9fb84977ff7c4a0baf0d5dbb57e235c7
```

## Why this matters

In OpenStack, project IDs are important because they define the tenant or project context for resources. Once the attacker has a valid project ID, they can interact with project-scoped resources such as object storage, compute, and identity-related objects.

This project ID becomes especially important later when reconstructing the Swift endpoint URL.

---

# Q7 - OpenStack Service Responsible for Authentication and Authorization

## Question

**Which OpenStack service provides authentication and authorization for the OpenStack API?**

## Answer

```text id="ww7o8m"
Keystone
```

## Analysis

The same controller-side traffic makes it clear that the attacker’s requests are using **Keystone authentication**. The user-agent string contains:

```text id="yzitx7"
keystoneauth1/5.11.1
```

and the API requests target identity-related endpoints such as:

```text id="m7d7r4"
/identity/v3/users
/identity/v3/endpoints
```

In OpenStack, the service responsible for **authentication and authorization** is:

```text id="owdzx7"
Keystone
```

## Why this matters

Keystone is the trust anchor for OpenStack access. Once the attacker is successfully authenticated through Keystone, they can obtain and use tokens to interact with other cloud services like Swift, Nova, Glance, etc.

So Keystone is the service that enabled the rest of the attack.

---

# Q8 - Endpoint URL of the Swift Service

## Question

**What is the endpoint URL of the Swift service?**

## Answer

```text id="h1qezk"
http://134.209.71.220:8080/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7
```

## Analysis

To answer this, the identity endpoint enumeration request was examined. A useful filter was:

```text id="rl8bgx"
http.request.uri == "/identity/v3/endpoints" && http.user_agent contains "openstacksdk"
```

Following the TCP stream for the `/identity/v3/endpoints` request reveals the list of OpenStack service endpoints returned to the attacker. Among them is the Swift object storage endpoint template:

```json id="cl3h1q"
"url": "http://134.209.71.220:8080/v1/AUTH_$(project_id)s"
```

Since we already recovered the project ID from **Q6**, we can substitute it into the endpoint:

```text id="b3i0kq"
http://134.209.71.220:8080/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7
```

## Why this matters

This is the exact endpoint the attacker later uses to interact with **Swift object storage**. Once the Swift endpoint is known, the attacker can enumerate containers, list objects, and download files stored in the cloud project.

This is where the investigation transitions from **identity and access** to **data theft**.

---

# Q9 - Number of Containers Discovered by the Attacker

## Question

**How many containers were discovered by the attacker?**

## Answer

```text id="tp18sq"
3
```

## Analysis

Once the Swift endpoint was known, the next task was to see how the attacker enumerated object storage.

The traffic was filtered for requests against the project-scoped Swift endpoint:

```text id="v1m17g"
http.request.uri contains "AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7?format=json" && ip.src == 117.200.21.26
```

The relevant HTTP response contained the following headers:

```http id="cmqf04"
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-Account-Container-Count: 3
X-Account-Object-Count: 0
```

The key value here is:

```text id="u6t9ax"
X-Account-Container-Count: 3
```

So the attacker discovered:

```text id="k5fkt4"
3 containers
```

## Why this matters

This confirms that the attacker was actively enumerating the object storage account rather than blindly guessing file paths. Container enumeration is a common first step before downloading sensitive data from Swift.

---

# Q10 - Time Sensitive User Data Was Downloaded

## Question

**When did the attacker download the sensitive user data file? (UTC)**

## Answer

```text id="ht2xj6"
2025-07-01 09:45:23 UTC
```

## Analysis

To find the sensitive file download, the traffic was filtered for requests involving the known user data object:

```text id="cnl6pr"
http.request.uri contains "user-details" && ip.src == 117.200.21.26
```

This led to a single relevant request in the controller capture, showing the attacker downloading the file from object storage.

The timestamp in UTC for that request was:

```text id="kphm17"
2025-07-01 09:45:23
```

## Why this matters

This is the moment the attacker completed the **data theft objective**. Everything before this point was discovery, authentication, and enumeration. At this timestamp, the attacker successfully accessed the sensitive file containing user data.

---

# Q11 - Number of User Records in the Sensitive Data File

## Question

**How many user records are in the sensitive user data file?**

## Answer

```text id="sgyqk0"
12
```

## Analysis

To answer this, the relevant HTTP stream containing the downloaded `user-details` object was followed. The file content could then be reviewed directly in the stream output.

From the contents of the downloaded user data file, the number of user records present was determined to be:

```text id="qz3m2l"
12
```

## Why this matters

This gives a concrete measure of the scope of the data exposure. It was not just a proof-of-access event; the attacker successfully retrieved a dataset containing **12 user records**.

---

# Q12 - Username of the New Admin User Created for Persistence

## Question

**For persistence, the attacker created a new user with admin privileges. What is the username of the new user?**

## Answer

```text id="s1xltx"
jellibean
```

## Analysis

To identify persistence activity, the controller capture was searched for user creation requests. A useful filter was:

```text id="v1w9y2"
http.request.uri contains "user" && ip.src == 117.200.21.26
```

The critical request is again the POST to:

```text id="e7q1v6"
/identity/v3/users
```

The JSON payload contains the newly created user details, including the username:

```json id="xwjlwm"
"name": "jellibean"
```

So the persistence account created by the attacker was:

```text id="vf2zq7"
jellibean
```

## Why this matters

This is the attacker’s persistence mechanism. Rather than relying only on stolen credentials, the attacker created a **new cloud user account** with administrative privileges. That means even if the original compromised credentials were reset, the attacker could still return later using the new account.

---

# Q13 - Password of the New User

## Question

**What is the password of the new user?**

## Answer

```text id="k8zj2d"
P@$$word
```

## Analysis

The same user creation request also contains the password in the JSON body:

```json id="akfwlo"
"password": "P@$$word"
```

So the password assigned to the attacker-created persistence account was:

```text id="vmxk2q"
P@$$word
```

## Why this matters

This gives defenders a complete indicator for the persistence account:

* **username:** `jellibean`
* **password:** `P@$$word`

This is critical for remediation because simply knowing that a user was created is not enough; defenders need to identify and remove the exact account and any associated credentials or tokens.

---

# Q14 - MITRE ATT&CK Technique for the Persistence Action

## Question

**What is the MITRE tactic / technique ID of the technique in task 12?**

## Answer

```text id="sk3jq2"
T1136.003
```

## Analysis

The attacker created a **new cloud account** with administrative privileges. In MITRE ATT&CK, this maps to:

* **Technique:** Create Account
* **Sub-technique:** Cloud Account
* **ID:** `T1136.003`

So the correct mapping is:

```text id="d0kk7n"
T1136.003 - Create Account: Cloud Account
```

## Why this matters

This classifies the attacker’s persistence behavior in a standard defensive framework. It is not just “user creation”; it is specifically **cloud account persistence**, which is a very important category in cloud-focused incident response.

---

# Detailed Timeline of the Intrusion

Based on both packet captures, the attacker activity can be reconstructed into a coherent timeline.

## 1. Reconnaissance and Web Fuzzing

* The attacker begins by probing the web server.
* Fuzzing is performed using:

  * `ffuf@2.1.0`

## 2. Discovery of Cloud Dashboard

* Through enumeration, the attacker discovers:

  * `cloud.vantage.tech`

## 3. Dashboard Authentication Attempts

* The attacker attempts to log into the dashboard multiple times.
* Successful login occurs after:

  * **4 attempts**

## 4. OpenRC File Download

* The attacker downloads the OpenStack API remote access config file from:

  * `/dashboard/project/api_access/openrc/`
* Time:

  * **2025-07-01 09:40:29 UTC**

## 5. First Controller API Interaction

* The attacker begins interacting directly with the controller node API.
* Time:

  * **2025-07-01 09:41:44 UTC**

## 6. Keystone / Identity Interaction

* The attacker uses OpenStack SDK tooling to authenticate and interact with identity services.
* Keystone is used for auth.

## 7. Project and Endpoint Enumeration

* The attacker identifies the default project:

  * `9fb84977ff7c4a0baf0d5dbb57e235c7`
* The Swift endpoint is resolved to:

  * `http://134.209.71.220:8080/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7`

## 8. Swift Container Enumeration

* The attacker enumerates object storage and finds:

  * **3 containers**

## 9. Sensitive Data Theft

* The attacker downloads the sensitive `user-details` file.
* Time:

  * **2025-07-01 09:45:23 UTC**
* The file contains:

  * **12 user records**

## 10. Persistence

* The attacker creates a new administrative user:

  * **username:** `jellibean`
  * **password:** `P@$$word`
* MITRE ATT&CK:

  * `T1136.003`

---

# Indicators of Compromise (IOCs)

## Domains / Hosts

* `cloud.vantage.tech`
* `134.209.71.220`
* `157.230.81.229`

## Key URIs

* `/dashboard/auth/login/`
* `/dashboard/project/api_access/`
* `/dashboard/project/api_access/openrc/`
* `/identity/v3/users`
* `/identity/v3/endpoints`
* Swift endpoint under `/v1/AUTH_<project_id>`
* object path containing `user-details`

## Credentials Observed

* Dashboard credentials:

  * `admin : StrongAdminSecret`
* Attacker-created cloud account:

  * `jellibean : P@$$word`

## Tooling Observed

* `ffuf@2.1.0`
* `openstacksdk/4.6.0`
* `keystoneauth1/5.11.1`
* `python-requests/2.32.4`
* `CPython/3.13.5`

---

# MITRE ATT&CK Mapping

| Activity                              | MITRE ATT&CK Technique                                             |
| ------------------------------------- | ------------------------------------------------------------------ |
| Web fuzzing / content discovery       | T1595 / Reconnaissance (contextual)                                |
| Valid account login to dashboard      | T1078 - Valid Accounts                                             |
| Use of cloud API credentials / OpenRC | T1078 / Cloud account abuse context                                |
| Object storage enumeration            | T1526 - Cloud Service Discovery                                    |
| Data theft from Swift object storage  | T1537 / Exfiltration to Cloud Storage context depending on framing |
| Creation of new cloud admin user      | **T1136.003 - Create Account: Cloud Account**                      |

> The challenge explicitly maps the persistence action to **T1136.003**, which is the most important ATT&CK mapping in this case.

---

# Key Findings

## 1. The attacker successfully moved from web recon into cloud compromise

This was not a standalone web attack. The web application was only the first stage. The real objective was access to the **OpenStack cloud environment**.

## 2. The cloud dashboard exposure was the pivot point

The discovery of `cloud.vantage.tech` and subsequent dashboard login enabled the attacker to download the **OpenRC** file, which was the bridge into direct API access.

## 3. The attacker used legitimate cloud mechanisms after gaining access

Instead of dropping malware or exploiting the controller directly, the attacker used **normal OpenStack API workflows** through Keystone and Swift. This makes the activity look closer to legitimate admin operations, which can make detection harder.

## 4. Sensitive user data was exfiltrated from object storage

The attacker enumerated containers and downloaded a file containing **12 user records**, confirming the reported data theft.

## 5. Persistence was established in the cloud control plane

The creation of the `jellibean` admin account is one of the most important findings in the case because it means the attacker did not just steal data — they attempted to maintain access for future use.

---

# Conclusion

The **Vantage** Sherlock challenge shows a realistic **cloud intrusion workflow** where the attacker begins with web discovery, gains access to a cloud dashboard, pivots into direct **OpenStack API abuse**, steals sensitive data from **Swift object storage**, and then creates a new administrative account for persistence.

The investigation revealed the following core attack path:

1. **Web fuzzing** with `ffuf@2.1.0`
2. Discovery of **`cloud.vantage.tech`**
3. Successful dashboard login after **4 attempts**
4. Download of the **OpenRC** API config file at **2025-07-01 09:40:29 UTC**
5. Direct API interaction with the controller beginning at **2025-07-01 09:41:44 UTC**
6. Keystone-based authentication and project enumeration
7. Swift endpoint discovery and container enumeration
8. Download of sensitive user data at **2025-07-01 09:45:23 UTC**
9. Creation of a new admin user:

   * `jellibean`
   * `P@$$word`

From a defensive perspective, the most important lesson in this case is that once a cloud dashboard is exposed and valid credentials are obtained, the attacker may stop using the UI entirely and move to the **API layer**, where actions such as enumeration, storage access, and account creation can happen very quickly and often look like legitimate administrative traffic.

This makes **cloud logging, identity monitoring, storage auditing, and user creation alerting** essential for detection and response in private cloud environments.

---
