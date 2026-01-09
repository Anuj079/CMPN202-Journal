---
title: Advanced Security Architecture & Observability
description: Implementation of Mandatory Access Control (AppArmor), SMTP Relay Infrastructure (Postfix/Gmail), and Custom Systemd Observability Services.
author: Anuj Baral
date: Week 5: 2025-01-09
---

## 1. Objectives & Scope

Following the perimeter hardening in [Week 4](/view.html?page=week4), the system’s primary risk profile transitions from external attack vectors to post-compromise containment and operational visibility. At this stage, the assumption is no longer *"Can the system be breached?"* but rather *"How effectively can damage be limited and detected if a breach occurs?"*

A secure server must therefore demonstrate three advanced capabilities:
1. **Containment:** Prevent compromised processes from escalating beyond their intended scope.
2. **Prevention:** Actively block malicious actors attempting to force entry.
3. **Communication:** Reliably notify administrators of anomalous or critical events.
4. **Awareness:** Actively observe system health and resource exhaustion in real time.real-time.

The objective of Week 5 is to advance the system from a hardened endpoint to a self-aware security platform, capable of enforcing policy at the kernel level and autonomously reporting operational threats.

## 2. Phase 1: Mandatory Access Control (AppArmor)

Traditional Linux security relies on **Discretionary Access Control (DAC)**, where file permissions are enforced based on user identity. While effective under normal operation, DAC fails catastrophically once a privileged user is compromised.

To mitigate this systemic weakness, I implemented AppArmor, a Mandatory Access Control (MAC) framework that enforces *process-level* restrictions regardless of user privileges. Even a root-owned process is constrained by its assigned profile.

### 2.1 Installation & Capability Enablement
To manage AppArmor policies effectively, I installed the required administration utilities.
**Command:**
```bash
sudo apt update
sudo apt install apparmor-utils -y
```
**Technical Rationale:**
* `apparmor-utils` provides tooling such as `aa-status`, `aa-enforce`, and `aa-complain`, enabling real-time inspection and enforcement of kernel security profiles.

![Figure 1: Installing App Armor Utility](images/week5/app_armor.png)

### 2.2 Profile Enforcement Verification
Once installed, I verified the operational status of AppArmor and confirmed active enforcement.
Command: 

```bash
sudo aa-status
```

![Figure 2: AppArmor Status confirming 24 profiles are loaded in 'Enforce' mode.](images/week5/apparmor-status.png)

**Finding:** 
The kernel is actively enforcing profiles on critical services such as `rsyslogd` and `tcpdump`. This means that even if one of these services were exploited (e.g., via a buffer overflow), the attacker would be confined to the permissions defined in the profile and prevented from accessing arbitrary files, spawning shells, or interacting with sensitive system resources.

**Security Impact:**
AppArmor introduces a hard security boundary below user space, transforming many remote code execution vulnerabilities into contained process failures rather than full system compromises.


## 3. Phase 2: Intrusion Prevention System (Fail2Ban)

While AppArmor limits what a compromised process can *do*, it does not prevent attackers from trying to break in. To secure the SSH interface against brute-force attacks, I implemented **Fail2Ban**.

This tool functions as an active sentry: it monitors log files for malicious patterns (failed login attempts) and dynamically updates the firewall to ban the offending IP addresses.

### 3.1 Installation & Configuration
I installed the service and created a local configuration file to ensure settings persist after updates.

Command:
bash
sudo apt install fail2ban -y

![Figure 3: Installation of the Fail2Ban intrusion detection system.](images/week5/fail2ban_install.png)

I then configured the "Jail" for SSH protection.

Command:
bash
sudo nano /etc/fail2ban/jail.local

**Configuration Applied:**
```bash
[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
```

![Figure 4: Configuring the jail.local file to ban attackers after 3 attempts.](images/week5/fail2ban_config.png)

**Technical Rationale:**
* **`maxretry = 3`**: I lowered the default threshold (usually 5) to 3. This strict policy reduces the window for dictionary attacks.
* **`bantime = 1h`**: A 1-hour ban disrupts automated botnets enough to make them move on to easier targets.

### 3.2 Verification of Enforcement
After starting the service, I verified that the jail was active.

Command:
```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

![Figure 5: Active status of Fail2Ban service.](images/week5/fail2ban_ssh_status.png)

**Result:**
The service is active and running. This confirms that the intrusion detection loop is closed: `auth.log` is being read, and `iptables` rules will be generated automatically if an attack is detected.

## 4. Phase 3: SMTP Alerting Infrastructure

Observability is ineffective if alerts cannot leave the system securely. To enable outbound notifications without exposing inbound services, I implemented an SMTP relay architecture using Postfix, forwarding alerts through Google’s Gmail infrastructure.

This design avoids running a public-facing mail server while still ensuring reliable, encrypted message delivery.

### 4.1 Package Installation & Dependency Management
Command:
```bash
sudo apt install postfix mailutils libsasl2-modules -y
```

![Figure 6: Installing.](images/week5/postfix_installing_command.png)

**Component Analysis:**
* **postfix:** Message transfer agent responsible for queuing and delivery.
* **mailutils:** Provides CLI tooling for testing and automation.
* **libsasl2-modules:** Mandatory for SASL authentication with Gmail; without it, SMTP authentication fails silently.


### 4.2 Authentication Setup (Google App Passwords)
Modern email providers block standard password authentication for automated services. To comply with Google’s security model, I generated a dedicated App Password, which acts as a scoped authentication token exclusively for SMTP relay.

![Figure 7: Generating a dedicated App Password for the server.](images/week5/app_password.png)

**Security Benefit:**
The App Password can be revoked independently, minimizing blast radius in the event of credential leakage and eliminating the need to store a primary account password on the server.

### 4.3 Encrypted Relay Configuration
I configured Postfix to route all outbound mail through Gmail’s TLS-enforced relay.

Configuration:
```Ini
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
```

![Figure 8: Configuring the Postfix 'main.cf' for SASL authentication and TLS encryption.](images/week5/postfix_config.png)

Configuration Breakdown:
* `relayhost`: Offloads email delivery to Google's reliable servers.
* `smtp_tls_security_level = encrypt`: **Critical Security Control.** This forces the connection to use TLS, preventing "Man-in-the-Middle" attacks from intercepting the alerts on the wire.

### 4.4 Verification of Transport
Before deploying the monitoring script, I validated the pipeline by sending a manual test message via the command line.

Command:
```bash
echo "Test" | mail -s "SMTP Config Success" testmodel1254@gmail.com
```

![Figure 9: Confirmation of successful SMTP transmission to the administrator's inbox.](images/week5/mailsetup_comform.png)

This confirms that the notification channel is functional, encrypted, and ready for automated alerting.

## 5. Phase 3: Active Observability (Custom Monitoring Suite)

Traditional log files provide *forensic insight after failure.* For this system, I required **proactive observability** a mechanism capable of detecting anomalies as they occur and immediately notifying the administrator.

### 5.1 Custom Script Development
I developed a Bash monitoring script (`week5-monitor.sh`) to track CPU Load and RAM usage continuously. Unlike simple cron jobs, this script includes:

Key design features include:
* Floating-point threshold evaluation using awk for precision.
* Cooldown throttling (300 seconds) to prevent alert storms.
* Structured CSV logging to support future performance regression analysis.

![Figure 10: Monitoring script implementing thresholds and cooldown logic.](images/week5/monitor_code.png)

This design ensures actionable alerts without generating administrative noise.

### 5.2 systemd Daemonization
To achieve production-grade reliability, the script was deployed as a managed `systemd` service.

File: `/etc/systemd/system/week5-monitor.service`
```bash
[Unit]
Description=Week 5 Advanced Resource Monitor & Alerting
After=network.target postfix.service

[Service]
Type=simple
ExecStart=/usr/local/bin/week5-monitor.sh
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
```

![Figure 11: systemd service creation](images/week5/monitor_stress_serveice_created.png)

Command:
```bash
sudo systemctl daemon-reload
sudo systemctl start week5-monitor.service
```

**Operational Advantage:**
The monitoring service is persistent, self-healing, and starts automatically at boot ensuring uninterrupted observability without manual intervention.

> “In production, this daemon would run under a restricted service account with only CAP_SYS_RESOURCE capability.”

## 6. Phase 4: Integration Verification (The Stress Test)
To validate the end-to-end system, I simulated a controlled resource exhaustion event using stress-ng.

Command:
```bash
stress-ng --cpu 4 --timeout 20s
```

![Figure 12: Cpu stress test triggering monitoring thresholds.](images/week5/stressing_cpu.png)

**Result:**
The daemon detected the sustained CPU load exceeding the defined threshold and immediately dispatched an SMTP alert.

![Figure 13: Alert Successfully delivered via Gmail.](images/week5/mail_received.png)

This confirms that detection, notification, and transport function cohesively under adverse conditions.

## 7. Conclusion

Week 5 marks a decisive maturity milestone in the system’s security lifecycle. The server now exhibits the core traits of a professionally managed security platform:

* **Containment**: AppArmor enforces kernel-level process restrictions.
* **Prevention:** Fail2Ban blocks brute-force attempts.
* **Communication**: Secure, encrypted alerting via SMTP relay.
* **Awareness**: Real-time monitoring with autonomous response capability.

The system is no longer passive it actively defends, observes, and reports.

## 7. Forward Planning: Week 6 Strategy
With advanced security controls in place, the remaining question is cost.

In Week 6, I will quantify the performance overhead introduced by these controls through:

* Controlled regression testing (`stress-ng`, `fio`)
* Statistical analysis of CSV monitoring logs
* Measurement of security-versus-performance trade-offs

This final phase will complete the transition from secure design to measurable security engineering.

## 8. References
1. **Canonical.** (2024). AppArmor - Ubuntu Security Guide. Available at: https://ubuntu.com/server/docs/security-apparmor .
2.  **Bregman, J.** (2015). *Fail2Ban: Monitoring Logs and Banning IPs*. Linux Journal. Available at: https://www.linuxjournal.com/content/fail2ban-monitoring-logs-and-banning-ips .
3. **Postfix.org.** (2023). Postfix TLS Support. Available at: http://www.postfix.org/TLS_README.html .
4. **Freedesktop.org.** (2024). systemd.service — Service unit configuration. Available at: https://www.freedesktop.org/software/systemd/man/systemd.service.html .