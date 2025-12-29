---
title: Workload Characterization & Performance Instrumentation
description: Research, selection, and deployment of industry-standard benchmarking utilities (stress-ng, fio) to establish a control baseline for measuring the performance impact of future security hardening.
author: Anuj Baral
date: Week 3: 2025-12-26
---

## 1. Objectives & Scope

With the vulnerability assessment complete in [Week 2](/view.html?page=week2), the project roadmap enters the **Preparation Phase** for system hardening. A core requirement of this module is not only to secure the server but to analyze the *impact* of those security controls on system resources.

The objective of Week 3 is to **select and deploy application workloads** that will serve as our "Control Group." By selecting specific applications that represent different types of server stress (CPU, RAM, Disk I/O), we can measure the system's performance *now* (Baseline) and compare it *after* hardening.

Before implementing cryptographic overheads (such as SSH Key exchange and encrypted tunnels in [Week 4](/view.html?page=week4)), I must first establish a **Performance Baseline**. The objective of this week is to research, select, and deploy a standardized suite of stress-testing tools. These tools will serve as the instrumentation to answer the critical question: *"Does the implementation of strict security controls degrade the system's throughput or responsiveness?"*

## 2. Methodology: Tool Selection Strategy

To ensure scientific rigor in the Week 6 stress tests, I rejected basic utilities in favor of enterprise-grade benchmarking suites. The selection criteria focused on **Granularity** (can we test specific subsystems?) and **Reproducibility** (can we repeat the test exactly?).

| Target Subsystem | Discarded Tool | Selected Tool | Justification for Selection |
| :--- | :--- | :--- | :--- |
| **CPU & Scheduler** | `stress` | **`stress-ng`** | The legacy `stress` tool only generates heat. `stress-ng` was selected because it allows targeting specific CPU opcodes and scheduler contexts, enabling us to simulate realistic encryption loads rather than just raw loops. |
| **Storage I/O** | `dd` | **`fio`** | `dd` is limited to sequential writes and relies heavily on OS caching, producing inaccurate benchmarks. `fio` (Flexible I/O Tester) was chosen for its support of Async I/O (`libaio`) and random read/write patterns, accurately modeling database workloads. |
| **Observability** | `top` | **`btop`** | Standard `top` lacks historical data visualization. `btop` was selected for its real-time graphing capabilities, allowing for the precise correlation of resource spikes with attack vectors. |

## 3. Tool Provisioning & Environment Setup

I accessed the target server (`192.168.56.101`) via the currently insecure SSH connection (as authenticated in Week 2) to provision the testing toolchain.

**Command Executed:**
```bash
sudo apt update
sudo apt install stress-ng fio btop -y
```

![Figure 1: Updating repositories and installing the stress-test toolchain.](images/week3/tool_installation.png)

**Implementation Note:** As shown in Figure 1, the package manager successfully retrieved stress-ng (v0.17.x) and fio (v3.36). Installing these tools now before the firewall is configured in Week 4 ensures we do not face dependency issues once the network is locked down.

## 4. Operational Validation (Smoke Testing)
To verify the integrity of the installed tools, I executed "Smoke Tests"—short, low-intensity runs designed to validate functionality without saturating the system.

### 4.1 CPU Subsystem Validation
I configured `stress-ng` to spawn two workers (matching the 2 vCPUs allocated in Week 1) for a strictly limited 5-second duration.

Command: 
```bash 
stress-ng --cpu 2 --timeout 5s
```

## 4.2 Storage Subsystem Validation
I executed a `fio` job targeting the virtual disk controller. The parameters were tuned to bypass filesystem buffering (`--ioengine=libaio`) to test the raw speed of the underlying virtual disk.

Command: 
```bash 
fio --name=quicktest --ioengine=libaio --rw=write --bs=4k --size=10M --numjobs=1 --time_based --runtime=5
```

![Figure 2: Validation results for stress-ng (CPU) and fio (Disk I/O).](images/week3/tool_uses.png)

**Data Analysis (Figure 2):**
* CPU: The output passed: 2: cpu (2) confirms the tool successfully interacted with the kernel scheduler to load both cores.
* Disk I/O: The fio result shows a Write Bandwidth of 203 MiB/s (IOPS: ~52k).
* Significance: This number (203 MiB/s) represents the "Unencrypted Baseline." In Week 6, after we potentially implement filesystem auditing or logging, we will compare new results against this figure to calculate the "Performance Cost of Security."


## 5. Establishing the "Idle" Baseline
Finally, before applying any hardening or load, I documented the system's resting state using btop. This control variable is essential for detecting "Resource Leaks" later in the project.

![Figure 3: System Baseline Metrics visualized in btop.](images/week3/btop.png)

**Baseline Metrics (from Figure 3):**
* CPU Load: 0-1% (Idle). The system is silent, confirming no rogue processes are consuming cycles.
* Memory Usage: ~364 MiB (of 1.92 GiB).
* Analysis: This verifies the efficacy of the "Headless" architecture chosen in Week 1. A standard GUI server would idle at >1.5GB RAM. We have ~1.5GB of headroom available for our future security services (Fail2Ban, AppArmor).

> “No concurrent VMs or host-intensive workloads were present during testing to eliminate external noise.”

## 6. Conclusion & Transition
This week’s work has successfully instrumented the environment for scientific analysis. We have defined the "Control State" of the experiment:

* Security State: Low (Default Passwords, No Firewall).
* Performance State: High (203 MiB/s Disk I/O, Low Latency).

With the tools in place and the baseline recorded, the system is ready for the major architectural changes scheduled for next week.

**Next Steps (Week 4 - Implementation):** The focus shifts to Hardening. We will execute the remediation plan from Week 2:
* Create a dedicated sysadmin identity (RBAC).
* Generate and deploy SSH Key Pairs (PKI).
* Disable Password Authentication to neutralize the brute-force vector.
* Activate the UFW Firewall to close the network perimeter.

## 7. References
* Canonical Ltd. (2024). Ubuntu Manpage: stress-ng - a tool to load and stress a computer system. Available at: https://www.google.com/search?q=https://manpages.ubuntu.com/manpages/noble/man1/stress-ng.1.html .
* Axboe, J. (2024). Fio - Flexible I/O Tester User Guide. Available at: https://fio.readthedocs.io/en/latest/ .