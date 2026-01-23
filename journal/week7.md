---
title: Security Audit & System Evaluation
description: Final security assessment using industry-standard auditing tools (Lynis, Nmap). Comprehensive vulnerability remediation and verification of the hardened state.
author: Anuj Baral
date: Week 7: 2026-01-23
---

## 1. Objectives & Scope

The final phase of this project performs a post-hardening security audit to validate the effectiveness of the controls implemented during Weeks 4 and 5. This phase fulfills Learning Outcome 3 (LO3) by objectively assessing residual vulnerabilities and verifying that remediation actions are correctly enforced at both the host and network levels.

The audit evaluates the system from three perspectives:

1. Host Configuration Compliance (Lynis)
2. Network Exposure Verification (Nmap)
3. Service Minimization & Authentication Enforcement (systemd / sshd)

This phase does not introduce new controls. Its purpose is to measure, verify, and prove that prior security decisions achieved their intended outcome.

## 2. Audit Preparation: Tooling

All audit tooling was installed exclusively from official Ubuntu repositories to preserve system integrity and reproducibility.

Command:
```bash
sudo apt update
sudo apt install lynis -y
```

![Figure 1: Installation of Lynis security tools.](images/week7/install_tools.png)

## 3. Host-Based Security Audit (Lynis)
### 3.1 Initial Execution
A full privileged Lynis audit was executed to assess system compliance against industry best practices.

Command:
```bash
sudo lynis audit system
```

![Figure 2: Initial Lynis Hardening Score of 66.](images/week7/lynis_result.png)

**Initial Result:**
The system achieved a **Hardening Index of 66**.

> A score in the mid-60s is typical for a freshly hardened but non-compliance-focused server and confirms that major architectural protections were present, but several advanced controls were still missing.

### 3.2 **Gap Analysis (Why only 66?):**
Lynis identified the following high-impact deficiencies:
1. Insufficient Accountability
    * auditd not enabled
    * No cryptographic logging of privileged actions
2. Absence of Malware Detection
    * No rootkit or integrity scanner installed
3. Session Persistence Risk
    * No enforced idle shell timeout
    * Risk of unattended terminal hijacking
4. Permissive SSH Capabilities
    * TCP forwarding and agent forwarding enabled
    * Increased lateral-movement risk

These findings were expected and aligned with the project’s phased approach: architecture → hardening → validation.

## 4. Remediation Actions
### 4.1 Internal Accountability & Malware Defense

To establish non-repudiation and detect low-level compromise, the Linux auditing framework and a rootkit scanner were deployed.

Command:
```bash
# 1. Install System Accounting (Tracks user actions)
sudo apt install auditd audispd-plugins acct -y
sudo systemctl enable auditd --now

# 2. Install Malware Scanner (Rootkit Hunter)
sudo apt install rkhunter -y

# 3. Update the database (Fixes 'Not Found' errors)
sudo rkhunter --propupd
```

![Figure 3: Installing System Accounting Trackers.](images/week7/trackers.png)
![Figure 4: Installing  Malware Scanner .](images/week7/hunter.png)


### 4.2 Shell & Session Hardening
To mitigate session hijacking and privilege abuse via unattended terminals, global shell constraints were applied.

Command:
```bash
# Add a 5-minute (300 seconds) timeout to the global profile
echo "TMOUT=300" | sudo tee -a /etc/profile
echo "readonly TMOUT" | sudo tee -a /etc/profile
echo "export TMOUT" | sudo tee -a /etc/profile

# Enforce stricter file creation permissions (027)
sudo sed -i 's/UMASK.*022/UMASK 027/g' /etc/login.defs
```

![Figure 5: Implementing Shell & Session Hardening.](images/week7/shell.png)


### 4.3 Advanced SSH Protocol Hardening
The initial configuration allowed features often used by attackers for lateral movement (Tunneling). I modified `/etc/ssh/sshd_config` to disable these.

**Configuration Changes:**
```ini, /etc/ssh/sshd_config
# 1. Log more details (Helps Fail2Ban & Auditd)
LogLevel VERBOSE

# 2. Disconnect idle sessions (Keep Alive)
ClientAliveInterval 300
ClientAliveCountMax 0

# 3. Disable Tunneling (Stops hackers using server as a proxy)
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# 4. Disable GUI Forwarding (Headless server does not need X11)
X11Forwarding no

# 5. Limit Authentication Attempts (Stops brute force faster)
MaxAuthTries 3
MaxSessions 2

# 6. Disable TCP KeepAlive (Prevents ghost sessions)
TCPKeepAlive no
```

**Implementation:**
```bash
sudo nano /etc/ssh/sshd_config
sudo systemctl restart ssh
```

**Security Impact:**
* Eliminates SSH-based proxying
* Improves audit fidelity for Fail2Ban and auditd
* Enforces rapid session termination under abnormal behavior

## 5. Final Security Audit (Verification)

After applying the remediation measures, I re-executed the Lynis audit to quantify the improvement.

Command:
```bash
sudo lynis audit system
```

**Final Result:**
The system achieved a **Hardening Index of 73**.

![Figure 6: Improved Lynis Score after remediation.](images/week7/lynis_score_77.png)


## 6. Network Security Assessment (Nmap)

To verify the "Split-Horizon" network architecture and firewall rules, I performed an external port scan from the workstation against the server's Host-Only IP.

Command:
```bash
nmap -v -A 192.168.56.101
```

![Figure 7: Nmap scan results showing strict port filtering.](images/week7/nmap_scan.png)

**Analysis of Figure 3:**
* **Open Ports:** Only `22/tcp` (SSH) is open. This confirms that the UFW firewall is correctly dropping traffic to all other ports.
* **Service Enumeration:** Nmap correctly identified the service as `OpenSSH 9.6p1`.
* **State:** 999 ports are `filtered`, proving that the server is not exposing any unnecessary attack surface (e.g., HTTP, DNS, Telnet) to the internal network.

## 7. Service Inventory & Minimization

A key principle of server hardening is "Minimization"—running only what is strictly necessary. I audited the active system units.

Command:
```bash
systemctl list-units --type=service --state=running
```
![Figure 8: Active Service Inventory and SSH Configuration verification.](images/week7/service_audit.png)

**Justification of Running Services:**
| Service | Status | Justification |
| :--- | :--- | :--- |
| **ssh.service** | Running | Required for remote administration (Headless constraint). |
| **fail2ban.service** | Running | Required for intrusion prevention (Brute-force protection). |
| **cron.service** | Running | Required for `unattended-upgrades` scheduling. |
| **systemd-*.service** | Running | Core OS functions (logging, network, user sessions). |
| **multipathd** | Running | Default Ubuntu storage daemon (Acceptable overhead). |

**Audit Verdict:** No unauthorized or "bloatware" services (e.g., CUPS, Avahi, Apache) were found running. The system adheres to the Principle of Least Functionality.

### 7.1 Authentication Hardening Verification
I verified the SSH daemon configuration directly to ensure password authentication was disabled at the process level.

Command:
```bash
sudo sshd -T | grep -E "permitrootlogin|passwordauthentication"
```

**Result (Visible in Figure 8):**
* `passwordauthentication no`: **PASS**. (Forces Key-Based Auth).
* `permitrootlogin without-password`: **PASS**. (Prevents brute-forcing root password).

## 9. Project Conclusion

Over the course of 7 weeks, I have successfully deployed a **Tier-3 Ready Linux Infrastructure**.
1.  **Architecture:** Validated "Split-Horizon" network for secure updates.
2.  **Security:** Achieved a hardened posture (Lynis 66) with active intrusion detection.
3.  **Observability:** Implemented custom monitoring scripts detecting real-time load spikes.
4.  **Compliance:** Verified all assessment requirements (SSH Keys, UFW, No Root Login).

The system is now fully operational, secure, and documented.