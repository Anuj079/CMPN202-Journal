---
title: Security Planning, Auditing & Threat Modeling
description: Documentation of baseline SSH enablement followed by a controlled white-box vulnerability assessment. Evaluation of default security posture across exposure, authentication resilience, and privilege boundaries to inform a STRIDE-driven hardening plan.
author: Anuj Baral
date: Week 2: 2025-12-19
---

## 1. Objectives & Scope

The primary objective of this phase is to **design a comprehensive Security Checklist** for the Week 4 hardening phase.

Rather than relying on generic "best practices," I adopted an evidence-based approach: **Audit First, Checklist Second.** By performing a Vulnerability Assessment (White Box Audit) on the default configuration, I can identify specific weaknesses and justify *why* each item on the checklist is necessary. This ensures that every security control we implement is a direct countermeasure to a demonstrated threat.

## 2. Service Configuration: Establishing the Baseline

Ubuntu Server 24.04 does not guarantee SSH server availability out of the box depending on installation path; therefore, remote management was explicitly provisioned to create a measurable, auditable management plane and a realistic attack surface.

### 2.1 SSH Installation & Activation
To enable controlled remote administration, OpenSSH Server was installed from official repositories:

**Command Executed:** 
```bash
sudo apt install openssh-server -y
sudo systemctl enable --now ssh
```

![Figure 1: Installing the OpenSSH Server package via apt.](images/week2/installing_ssh.png)

Following installation, The service usually be `inactive (dead)` by default upon installation. I explicitly enabled it to start on boot and verified it was listening for connections.

![Figure 2: Verifying the active status of the SSH Daemon.](images/week2/enabling_ssh.png)


**Configuration Analysis:**

At this point, SSH is operating under the default `/etc/ssh/sshd_config` configuration. In a default setup:

* PasswordAuthentication is typically enabled
* No rate limiting or lockout controls are enforced at the daemon level
* Restriction rules (AllowUsers/AllowGroups) are not configured



## 3. Vulnerability Audit (The "As-Is" State)

With the service active, I shifted roles to that of an internal auditor (White Box Penetration Tester) to assess the machine's security posture.

### 3.1 Network Exposure Analysis (Nmap)
I utilized **Nmap** from the host workstation to scan the Host-Only network (`192.168.56.101`). The goal was to determine if any network-level filtering (Firewall) was active.

**Audit Command:** `nmap -p- -A 192.168.56.101`

![Figure 3: Nmap scan revealing Port 22 is open and unfiltered.](images/week2/nmap.png)

**Observation:**

The scan confirms TCP/22 is open and the SSH service is externally reachable from the Host-Only segment.

**Risk Implications:**

* No network-layer filtering evidence: If the port is reachable with no filtering behavior, the environment is likely missing enforceable firewall rules at this stage.
* Service fingerprinting: The banner/version disclosure allows attackers to align the exposed software version with known vulnerabilities and attack patterns, reducing attacker effort.

### 3.2 Authentication Stress Test (Hydra)
To evaluate password-based SSH resilience, a controlled brute-force simulation was conducted using THC-Hydra. This test is useful not only for credential discovery but also for validating whether the server enforces:

* rate limiting
* lockout thresholds
* connection throttling
* automated response mechanisms

**Attack Execution:**
`hydra -l vboxuser -P custom_pass.txt ssh://192.168.56.101 -t 20`

**Performance Impact (DoS Risk):**

System load was monitored in parallel using `btop`.

![Figure 4: CPU utilization spike during the Hydra authentication flood.](images/week2/ssh.gif)

The resource spike indicates that repeated authentication attempts impose measurable cost on CPU scheduling and process handling. In real-world conditions, this behavior creates a Denial-of-Service vector, where availability is degraded even without successful authentication.

**Control Gap Identified:**

SSH at default settings does not block repeated failed attempts. Without external control (e.g., Fail2Ban) or restrictive SSH policy, brute-force attempts can persist indefinitely. The risk is dual credential compromise and service degradation via authentication floods.

### 3.3 Credential Compromise (Breach Confirmation)
Hydra successfully recovered a valid password from the supplied dictionary.

![Figure 5: Successful compromise of the SSH credentials.](images/week2/sshlogin.png)

This demonstrates that:
* password-based authentication is vulnerable when weak or guessable credentials exist
* no lockout/rate-limit mechanism prevented sustained attempts
* the authentication perimeter is insufficient without policy reinforcement

## 4. Post-Exploitation & Impact Analysis

A vulnerability assessment is incomplete without understanding impact. After gaining access, the goal is to quantify what an attacker can do with the access obtained.

### 4.1 Privilege Boundary Collapse via Misconfigured Sudo Policy

After successfully authenticating as the compromised `vboxuser`, I first enumerated the account’s privilege boundaries using:

![Figure 6: Verification of unrestricted sudo privileges.](images/week2/sudo_l.png)

The output (ALL : ALL) ALL confirms that the user is permitted to execute any command as root. This configuration represents a critical authorization weakness: while no kernel or memory corruption exploit is required, the privilege boundary between a standard user and the root account is effectively nonexistent.

To validate the practical impact of this configuration, I exploited a well-known sudo editor escape vector using a permitted interactive binary (vi). By invoking vi with sudo privileges and escaping to a shell, I obtained a root shell directly.

![Figure 7: Utilizing simple vim to gain root access.](images/week2/root_access.png)

**Finding:**
This is not a vulnerability in vi itself, but a misuse of sudo policy. Allowing unrestricted sudo access to interactive programs enables trivial escalation paths without any exploit development. Once the user password is compromised, root access becomes immediate and inevitable.

**Impact:**

At this point, the system is fully compromised:
* The attacker has unrestricted root-level control.
* All confidentiality, integrity, and availability guarantees are void.
* Additional post-exploitation demonstrations (e.g., reading /etc/shadow) become redundant, as root access inherently grants unrestricted access to all system resources.

> “This is not a software vulnerability in vim, but a misconfiguration allowing unrestricted command execution under sudo.”

## 5. Threat Modeling (STRIDE Analysis)

Based on the empirical evidence gathered above, I have developed the following STRIDE Threat Model to guide the hardening process in Week 4.

| Threat ID | Threat Category | Description of Risk |
| :--- | :--- | :--- |
| **T-01** | **Spoofing** | **Network Impersonation:** Because Port 22 accepts connections from any IP, a malicious actor can spoof a trusted IP or connect from a compromised neighbor. **Mitigation:** UFW Allow-Listing. |
| **T-02** | **Denial of Service (DoS)** | **Resource Exhaustion:** The lack of rate-limiting allowed the Hydra attack to consume 100% of available CPU cycles (Figure 2), potentially taking critical services offline. **Mitigation:** Fail2Ban. |
| **T-03** | **Elevation of Privilege** | **Root Compromise:** The unrestricted `sudo` configuration meant that a single weak password resulted in full administrative compromise. **Mitigation:** Key-Based Authentication. |


## 6. Remediation Plan (The Hardening Checklist)

Based on the audit findings and the identified threats, I have designed the following **Security Checklist** to be executed in Week 4.

### **Phase 1: Identity & Access Management (IAM)**
* [ ] **Generate SSH Key Pairs (Ed25519):** Eliminate password dependency (Mitigates T-03).
* [ ] **Disable Password Authentication:** Configure `sshd_config` to reject all password attempts.
* [ ] **Restrict Root Login:** Ensure `PermitRootLogin` is set to `no` or `prohibit-password`.

### **Phase 2: Network Defense (Firewall)**
* [ ] **Install UFW:** Enable the Uncomplicated Firewall.
* [ ] **Default Deny Policy:** Set incoming traffic to `DENY` by default.
* [ ] **Allow Management Only:** Create a rule allowing SSH (Port 22) **ONLY** from the Admin Workstation IP (Mitigates T-01).

### **Phase 3: Active Defense (IPS)**
* [ ] **Install Fail2Ban:** Deploy the Intrusion Prevention System.
* [ ] **Configure SSH Jail:** Set a ban time of 1 hour for 3 failed login attempts (Mitigates T-02).

## 7. References
1.  Canonical Ltd. (2024). *Ubuntu Server Guide: OpenSSH Server*. Available at: https://ubuntu.com/server/docs/service-openssh .
2.  Lyon, G. (2009). *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning*. Insecure.com LLC.
3.  Scarfone, K., et al. (2008). *Technical Guide to Information Security Testing and Assessment (NIST SP 800-115)*. National Institute of Standards and Technology.