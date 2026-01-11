---
title:  System Architecture & Infrastructure Deployment
description: A comprehensive technical analysis of the dual-system security architecture. Documenting the deployment of a headless Ubuntu Server 24.04 using a split-horizon network topology for secure updates within an air-gapped environment.
author: Anuj Baral
date: Week 1: 2025-12-12
---

## 1. Objectives & Scope

The objective of Phase 1 was to design and deploy a secure foundational infrastructure that emulates the operational principles of a Tier-3 data center environment. The emphasis was placed on architectural security rather than post-installation hardening, ensuring that risk reduction begins before the operating system is deployed.

This phase focused on:
* Deploying a headless Ubuntu Server 24.04 LTS
* Enforcing strict management-plane separation
* Minimizing attack surface through network and resource design
* Establishing a measurable, auditable baseline for subsequent security phases

## 2. System Architecture Design

A Dual-System Architecture was selected to clearly separate the Management Plane from the Target Server Plane:

* Administrative Workstation: Windows 11 Host (trusted operator environment)
* Target System: Ubuntu Server 24.04 LTS (headless, no desktop environment)

This mirrors the bastion-host model used in enterprise and cloud infrastructure (AWS, Azure, GCP), where administrative access is centralized and production systems are never directly exposed to untrusted networks.

Architectural Objectives

* Prevent direct internet exposure of the server
* Ensure all administrative actions are attributable
* Allow controlled, auditable update windows
* Support later security testing without redesign


### 2.1 The "Split-Horizon" Network Topology
The most critical design decision was the network isolation strategy. I explicitly rejected the use of a standalone **NAT (Network Address Translation)** or **Bridged** connection for the target machine's primary interface. While these modes offer convenience, they introduce unacceptable security risks for a vulnerability lab by exposing the server directly to the local LAN or Internet.

Instead, I implemented a **Split-Horizon** topology. This architecture maintains a strict security posture by default but allows for necessary operational maintenance.

![Figure 1: Split-Horizon Network Topology Diagram.](images/week1/architecture-diagram.png)

**Technical Analysis of Figure 1:**
* **Physical Layer (Host):** My workstation retains internet connectivity via the physical Wi-Fi adapter to access documentation and repositories.
* **Virtual Layer (Guest):** The Ubuntu VM connects primarily to the virtual switch `vboxnet0` via Adapter 1.
* **Isolation Mechanism:** The `vboxnet0` interface operates on the `192.168.56.0/24` subnet but **lacks a default gateway**. This effectively creates a "Default-Deny" network posture. Unlike a physical air-gap which allows zero communication, this software-defined isolation prevents the guest OS from routing traffic to `0.0.0.0/0` (the internet) by default, while allowing us to enable a temporary "drawbridge" (Adapter 2) for updates as detailed in Section 5.

## 3 Operating System 
I conducted a comparative analysis of Linux distributions before selecting **Ubuntu Server 24.04 LTS (Noble Numbat)**.

### 3.1 Justification for Selection
| Criteria | Ubuntu Server 24.04 | Debian 12 | CentOS Stream |
| :--- | :--- | :--- | :--- |
| **Lifecycle** | **5 Years (LTS)** | Stable | Rolling Release |
| **Kernel** | **6.8.x (Modern)** | 6.1 (Conservative) | Bleeding Edge |
| **Security** | **AppArmor (Default)** | AppArmor (Manual) | SELinux (Complex) |

* **Security & Updates:** Ubuntu's `unattended-upgrades` feature ensures timely security patching. The default inclusion of **AppArmor** provides a predefined Mandatory Access Control (MAC) framework, which is essential for the hardening tasks in Week 5.
* **Industry Standard:** Ubuntu is the dominant OS for public cloud infrastructure. Proficiency in this specific distribution directly enhances professional employability.
* **Kernel Capabilities:** The 6.8.x kernel includes modern **eBPF** (Extended Berkeley Packet Filter) support, enabling advanced observability tools that older kernels (like in Debian Stable) may lack.

## 4. Implementation Log: Hypervisor Configuration

I selected **Oracle VirtualBox 7.0** as the hypervisor due to its granular control over Host-Only networking and its ability to simulate multi-adapter environments without requiring enterprise licensing.

![Figure 2: ISO Selection and Unattended Installation Configuration.](images/week1/configuring_ubntu_iso_file.png)

![Figure 3: User Credentials Configuration creating the 'vboxuser' admin account.](images/week1/default_user_setup.png)

**Identity Management Strategy:**
As shown in Figure 3, I defined a dedicated administrative user, `vboxuser`, rather than enabling the `root` account. This adheres to the **Principle of Least Privilege**. Direct root login bypasses audit trails; using a named user with `sudo` privileges ensures that every administrative command is logged in `/var/log/auth.log`, creating a non-repudiable accountability trail.

### 4.1 Hardware Resource Allocation
I configured the Virtual Machine (VM) with specific constraints to simulate a cost-optimized cloud instance (e.g., AWS t3.small) and to force efficient resource usage (Learning Outcome 5).

![Figure 4: VirtualBox Hardware Allocation showing 2GB RAM and 2 vCPUs.](images/week1/resources_assigning.png)

* **Memory (RAM):** Allocated **2048 MB**. This is sufficient for a headless server but low enough to prevent resource contention on the host machine. A graphical desktop environment (GNOME/KDE) would require at least 4GB to run smoothly; by omitting the GUI, we reclaim these resources.
* **Processors (vCPU):** Allocated **2 CPUs**. This ensures that background processes (like the `fail2ban` service we will install later) do not block the main execution thread, preventing system hang during compilation tasks.

### 4.2 Storage Configuration
I created a **25 GB Virtual Hard Disk (VDI)**.

![Figure 5: Storage Configuration showing a 25GB dynamically allocated VDI.](images/week1/spage_management.png)

**Design Decision:**
I chose a dynamically allocated VDI over a fixed-size disk. This allows the file system to grow as needed without immediately reserving 25GB of physical storage on my laptop, optimizing the "Host" resource footprint. 25GB provides ample space for the operating system (~5GB) and future log files generated during the security auditing phase.

## 5. Network Strategy: The "Split-Horizon" Configuration

To balance the requirement for "Air-Gapped" security with the practical need to install software updates, I engineered a **Split-Horizon** network architecture using two distinct virtual adapters.

### Adapter 1: The Secure Management Interface (Host-Only)
I configured the primary adapter as **Host-Only**. This interface is always active and provides the secure SSH channel between my host and the VM.

![Figure 6: Adapter 1 configured as Host-Only for secure isolation.](images/week1/Networksetup.png)

### Adapter 2: The "Update Window" Interface (NAT)
I added a second adapter set to **NAT (Network Address Translation)**.

![Figure 7: Adapter 2 configured as NAT for temporary internet access.](images/week1/tempery_connection.png)

**Operational Workflow:**
This NAT adapter serves a specific strategic purpose. It is kept in a "disconnected" state by default. When system updates or tool installations (like `nmap`) are required, I perform the following "Maintenance Window" procedure:
1.  **Open Window:** Enable Adapter 2 via VirtualBox or CLI.
2.  **Execute:** Run `apt update` and `apt install`.
3.  **Close Window:** Disable Adapter 2 immediately.

This strategy strictly minimizes the time the server is exposed to the public internet, satisfying the isolation requirements of the assessment while maintaining system viability.

## 6. System Initialization & Verification

Upon booting the system, the Linux kernel initialized successfully.

![Figure 8: Ubuntu 24.04 Boot Sequence.](images/week1/ubuntu_installation_success_loading_.png)

I successfully logged into the system using the `vboxuser` credentials. The prompt `vboxuser@Ubuntu-Server` confirms that we are operating as a standard user, not root.

![Figure 9: Successful login showing Linux Kernel 6.8.0 and system load.](images/week1/login_after_installation.png)

**Evidence Analysis:**
The login screen confirms the system is running **Linux Kernel 6.8.0-90-generic**. This modern kernel is crucial for our future work, as it supports **eBPF** (Extended Berkeley Packet Filter), a technology we may utilize for advanced security tracing and observability in Week 6. The `System load: 0.03` metric further validates the efficiency of the headless configuration; without a GUI, the system is consuming negligible resources at idle.

![Figure 10: Comprehensive System Verification using 'uname', 'lsb_release', 'free', and 'ip addr'.](images/week1/system_verification_&_evidence.png)

The screenshot above (Figure 10) provides definitive proof of the system's baseline configuration:

1.  **OS & Kernel Identity (`uname -a` & `lsb_release -d`):**
    * **Output:** `Linux Ubuntu-Server 6.8.0-90-generic`
    * [cite_start]**Significance:** Confirms the successful deployment of Ubuntu 24.04.3 LTS[cite: 37]. The `generic` kernel indicates the OS is correctly optimized for virtualized hardware.

2.  **Resource Utilization (`free -h`):**
    * **Output:** `Total: 1.9Gi`, `Used: 363Mi`, `Available: 1.6Gi`.
    * **Significance:** This validates the "Headless" architectural decision. The system is consuming only ~360MB of RAM. A comparable desktop installation would be using over 1.5GB at idle. [cite_start]This proves that the system meets the "resource efficiency" criteria of LO5[cite: 37].

3.  **Network Topology (`ip addr`):**
    * **Interface `enp0s3`:** Assigned `192.168.56.101/24`. This is the Host-Only interface.
    * **Interface `enp0s8`:** Assigned `10.0.3.15/24`. This is the NAT interface.
    * **Significance:** The presence of both interfaces confirms the "Split-Horizon" network strategy is active. [cite_start]The Host-Only IP confirms connectivity to the management workstation, while the NAT IP confirms the capability for future updates[cite: 36, 37].

## 7. Critical Reflection
**Successes:**
The deployment was successful. The decision to use the Host machine as the SSH client (via PowerShell) rather than a second Linux VM was validated; it reduced resource overhead without compromising the security model. The **Dual-Adapter** design successfully segments management traffic from (potential) internet traffic.

**Challenges & Mitigations:**
* **Challenge:** "Split Routing." Initially, when the NAT adapter was enabled, the OS tried to route internet traffic through the Host-Only adapter because it was initialized first.
* **Solution:** By defining the NAT adapter as `optional: true` in Netplan and manually toggling it via `ip link`, I maintained strict control over the routing table.

**Security Baseline Assessment:**
While the architecture is secure, the *configuration* is currently default.
* **Risk:** Password authentication is enabled for SSH.
* **Risk:** No intrusion detection (Fail2Ban) is active.
* **Risk:** The Firewall (UFW) is inactive by default.

**Next Steps:**
In **Week 2**, I will transition from Deployment to **Defense**. I will perform a Threat Assessment (STRIDE) and implement a security baseline, including Key-Based Authentication and Firewall rules, to address the risks identified above.

## 8. References
1.  Canonical Ltd. (2024). *Ubuntu Server Documentation*. Available at: https://ubuntu.com/server/docs.
2.  Oracle. (2024). *VirtualBox User Manual: Chapter 6, Virtual Networking*. Available at: https://www.virtualbox.org/manual/ch06.html.