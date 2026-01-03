---
title: System Hardening & Perimeter Defense Implementation
description: Execution of the Security Checklist defined in Week 2. Implementing cryptographic identity assurance (Ed25519), host-based firewalling (UFW), and immutable logging to neutralize identified threats.
author: Anuj Baral
date: Week 4: 2026-01-02
---

## 1. Objectives & Scope

In [Week 2](/view.html?page=week2), a controlled vulnerability assessment identified three critical threat vectors: **T-01 (Spoofing/Network Exposure)**, **T-02 (Denial of Service via Auth-Flooding)**, and **T-03 (Privilege Escalation via Weak Credentials)**.

The objective of Week 4 is to transition the infrastructure from its default "Vulnerable" state to a "Hardened" bastion by executing the multi-layered remediation checklist. This phase implements a **Defense-in-Depth** strategy, ensuring that even if one security layer is bypassed, the system maintains integrity through secondary and tertiary controls.

## 2. Phase 1: Identity Architecture (The Two-Tier Model)

Before applying cryptographic controls, I addressed the "Default Account" vulnerability. The system was installed with the generic `vboxuser` account. To adhere to the **Principle of Least Privilege**, I implemented a **Two-Tier Authentication Model**.

**Implementation:**
1.  **Entry User (`anuj`):** Created for SSH access only. This user has **NO** `sudo` privileges.
2.  **Admin User (`sysadmin`):** Created for system administration. This user cannot log in via SSH; they can only be reached by switching users (`su -`) from inside.

**Command:**
```bash
# Entry user (No Sudo)
sudo adduser anuj

# Admin user (Sudo)
sudo adduser sysadmin
sudo usermod -aG sudo sysadmin
```
![Figure 1: The Two-Tier Model.](images/week4/two_tier_model.png)

Security Benefit: This neutralizes Key Theft attacks. If an attacker steals the SSH key for `anuj`, they gain access to a low-privilege account with no way to destroy the system, as they lack the password to switch to `sysadmin`.

## 2. Phase 1: Identity & Access Hardening (IAM)

The most critical vulnerability identified was the reliance on password authentication, which allowed Hydra to compromise the system in seconds. To mitigate this, I transitioned the trust model from "Something you know" (Password) to "Something you have" (Cryptographic Key).

### 2.1 Generating Cryptographic Identity (Ed25519)
I generated a new SSH key pair on the management workstation. I selected the **Ed25519** algorithm over legacy RSA because it offers superior performance and smaller key sizes without compromising security.

**Command:** 
```bash
ssh-keygen -t ed25519 -C "admin_workstation"
ssh-copy-id -i ~/.ssh/id_ed25519.pub anuj@192.168.56.101
```

![Figure 2: Generating and Installing the Ed25519 Key Pair on the management host.](images/week4/generating_ssh_key.png)

I utilized `ssh-copy-id` to securely transfer the public key to the target server. This creates a "Digital Handshake," authorizing my specific workstation to log in.

![Figure 3: Identity onto the target server.](images/week4/adding_ssh_key.png)

### 2.2 Legal Warning Banners (Deterrence)
Before locking down the system, I implemented a "Warning Banner." While this does not stop a technical attack, it satisfies the legal requirement to warn unauthorized users, ensuring that any subsequent intrusion is legally prosecutable under the Computer Misuse Act.

**Configuration:** I created `/etc/issue.net` with a stern warning message and pointed SSH to it.

![Figure 4: created /etc/issue.net.](images/week4/banner_config.png)

![Figure 5: Configuring the Warning Banner in sshd_config.](images/week4/banner_added_to_ssh.png)

**Validation:**
Upon login, the system now displays the legal warning before authentication proceeds.

![Figure 6: Successful display of the legal warning banner upon connection.](images/week4/banner_emplemented.png)

### 2.3 The "Kill Switch" (Disabling Passwords)
With the keys and banners in place, I modified `/etc/ssh/sshd_config` to strictly forbid password-based login. This is the primary mitigation for **Threat T-03**.

**Configuration Changes:**
```bash
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
```

**Hardening Modifications:**
* `PermitRootLogin no`: Prevents direct targeting of the root account.
* `PasswordAuthentication no`: Effectively disables the possibility of brute-force attacks by requiring a private key for entry.
* `PubkeyAuthentication yes`: Explicitly enables cryptographic login.

![Figure 7: Modifying sshd_config to disable passwords and root login.](images/week4/ssh_config.png)

**Verification:**
I attempted to log in using the password from a non-key authenticated session. As shown below, the server displays the banner but immediately rejects the password attempt with `Permission denied (publickey)`.

![Figure 8: Verification of the "Password Kill Switch" - Access Denied.](images/week4/password_rejected.png)

## 3. Phase 2: Perimeter Defense (Firewall)

To mitigate Threat **T-01 (Spoofing)**, I implemented a Host-Based Firewall using UFW (Uncomplicated Firewall). The goal was to reduce the attack surface from "The entire network" to "Single Trusted IP."

### 3.1 Implementation of "Default Deny" Policy

I adopted a strict Whitelisting strategy. All incoming traffic is blocked by default, and only my specific management IP (`192.168.56.1`) is allowed to connect on Port 22.

Commands Executed:
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.1.82 to any port 22 proto tcp
sudo ufw enable
```
![Figure 9: UFW Status showing the strict Allow-List rule.](images/week4/ufw_installation_and_config.png)

**Implementation Workflow:**
1. **Set Defaults:** `sudo ufw default deny incoming` and `sudo ufw default allow outgoing`.
2. **Restrict SSH:** `sudo ufw allow from 192.168.1.82 to any port 22 proto tcp`.
3. **Enable:** `sudo ufw enable`.

![Figure 10: UFW Status showing the strict Allow-List rule.](images/week4/ufw_status.png)

### 4.1 Practical Implementation: Host-Based Immutability
As a countermeasure within the host environment, I utilized the Linux Kernel's **Immutable Attributes** to harden the local log files.

**Technique:**
I applied the `+a` (Append Only) attribute to `/var/log/auth.log`. This ensures that data can be added (written) to the log, but existing data can **never** be edited, overwritten, or deleted—even by the root user.

**Command:** 
```bash
sudo chattr +a /var/log/auth.log
```

![Figure 11: Demonstrating Log Integrity. The 'rm' command fails even with sudo privileges.](images/week4/Log_Integrity_append_only.png)

**Finding:** As demonstrated in Figure 13, an attempt to delete the log file results in "Operation not permitted," preserving the audit trail for forensic review.

### 4.2 Theoretical Best Practice: Remote Logging Architecture
In a production Tier-3 data center, the industry standard for ensuring log integrity is **Centralized Remote Logging**.

**Concept:**
By configuring the `rsyslog` daemon to forward log events (via UDP/514 or TCP/6514) to a dedicated, hardened "Syslog Collector" or SIEM (Security Information and Event Management) server, we decouple the "Evidence" from the "Crime Scene."

![Figure 12: Remote Logging Architecture.](images/week4/remote_log.png)

**Security Benefit:**
Even if an attacker gains full root access to the Ubuntu server and wipes the local disk, they cannot delete the logs that have already been transmitted to the third-party collector. This guarantees **Availability** and **Integrity** of forensic data.

*Constraint Note: Due to the resource constraints of this specific assessment (Single-VM Scope), deploying a secondary dedicated Syslog Server was not feasible. Therefore, I implemented the robust host-based alternative described below.*

## 5. Conclusion & Remediation Verification

The hardening process is complete. To verify the efficacy of these controls, I repeated the **Nmap Scan** and **Hydra** attack from Week 2 to demonstrate the "Before vs. After" security posture.

### 5.1 Network Perimeter Verification
I re-scanned the target using Nmap. Unlike the initial audit where the port was globally exposed, the firewall rules now enforce strict access control.

![Figure 13: Demonstrating Nmap Scan results after hardening process.](images/week4/nmap.png)

### 5.2 Authentication Resilience Verification
I executed the Hydra simulation again using the exact same parameters that breached the system in Week 2.

![Figure 14: Demonstrating Hydra simulation failing against the hardened target.](images/week4/hydra_simulation_again.png)

**Final Test Result:**
Unlike in Week 2, where the attack succeeded in 2 seconds, the attack now fails immediately. The combination of **UFW** (blocking untrusted IPs) and **SSH Keys** (rejecting passwords) has rendered the brute-force vector obsolete.

**Summary of Hardening:**
* **Identity:** Two-Tier Model (Anuj/Sysadmin) and Passwords Replaced with Ed25519 Keys.
* **Network:** Open Port 22 Replaced with Trusted-IP Whitelist.
* **Resilience:** Unchecked Floods Replaced with Fail2Ban Jails.
* **Integrity:** Mutable Logs Replaced with Immutable Audit Trails.

The system is now ready for the **Week 5 Application Deployment** phase, providing a secure foundation for the workloads we selected in Week 3.

## 6. Forward Planning: Week 5 Strategy

With the "Security Baseline" now enforced, the infrastructure is ready for its primary function: hosting services. The objective for **Week 5** shifts from **Hardening** to **Deployment & Performance Analysis**.

We have successfully locked down the Operating System, but a secure server is useless if it cannot run applications. Next week, I will:

1.  **Deploy the "Business Logic":** Install the actual application workloads identified in Week 3 (Simulated Web Server and Database).
2.  **Performance Regression Testing:**
    * Now that **UFW** is inspecting every packet there is a computational cost ("Overhead").
    * I will re-run the `stress-ng` and `fio` benchmarks.
    * **The Critical Question:** *Did enabling this heavy security reduce our Disk I/O or CPU throughput compared to the Week 3 baseline?*

## 8. References

1.  **NIST.** (2008). *Guide to General Server Security (SP 800-123)*. National Institute of Standards and Technology. Available at: https://csrc.nist.gov/publications/detail/sp/800-123/final .
2.  **Bernstein, D. J.** (2011). *High-speed high-security signatures (Ed25519)*. Journal of Cryptographic Engineering. Available at: https://ed25519.cr.yp.to/ .
3.  **Canonical Ltd.** (2024). *Ubuntu Server Guide: Firewall Configuration with UFW*. Available at: https://ubuntu.com/server/docs/security-firewall .
5.  **Kerrisk, M.** (2024). *chattr(1) — Linux manual page*. The Linux Programming Interface. Available at: https://man7.org/linux/man-pages/man1/chattr.1.html .