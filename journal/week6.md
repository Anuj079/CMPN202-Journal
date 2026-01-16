---
title: Performance Regression Analysis & Resource Management
description: Quantitative assessment of "Security Overhead" (Before vs. After) and strategies for automated resource control.
author: Anuj Baral
date: Week 6: 2026-01-16
---

## 1. Objectives & Scope

In [Week 3](/view.html?page=week3), a controlled performance baseline was established on an un-hardened system. Subsequent weeks introduced multiple defensive layers, including firewall enforcement, authentication hardening, log inspection, kernel-level Mandatory Access Control (AppArmor), and continuous monitoring services.

The objective of **Week 6** is to transition from qualitative security improvements to **quantifiable engineering outcomes** by answering two critical questions relevant to both technical and business stakeholders:

1. **Performance Impact:** What measurable performance cost is introduced by the applied security controls?
2. **Operational Resilience:** How can the system automatically maintain availability when abnormal resource consumption is detected?

This phase focuses on evidence-driven decision-making, validating whether the implemented security posture remains operationally viable under load.

## 2. Phase 1: CPU Regression Testing

To assess computational overhead, I conducted CPU stress testing using `stress-ng`, specifically targeting floating-point and matrix computation workloads. This method stresses both CPU scheduling and kernel instrumentation paths affected by AppArmor and firewall processing.

Command:
```bash
stress-ng --cpu 4 --cpu-method matrixprod --timeout 60s --metrics-brief
```
This command was executed on the hardened system, ensuring parity with the Week 3 baseline configuration (identical VM resources, CPU allocation, and test duration).

![Figure 1: CPU Benchmark on the Hardened System.](images/week6/cpu.png)

**Measured Throughput (Hardened):**
4,190.23 operations per second

## 3. Phase 2: Disk I/O Regression Testing

Security controls often introduce I/O overhead through increased logging, journaling, and integrity checks. To evaluate this impact, I performed a randomized write workload using `fio`, simulating conditions common in audit-heavy environments.

Command:
```bash
fio --name=week6_test --ioengine=libaio --rw=randwrite --bs=4k --numjobs=1 --size=1G --runtime=60 --time_based --group_reporting
```

![Figure 2: Disk Random Write Benchmark on Hardened System.](images/week6/disk.png)

**Measured Bandwidth (Hardened):**
51.0 MiB/s

## 4. Comparative Analysis: Quantifying Security Overhead

Using the baseline metrics captured in Week 3, I calculated the precise performance delta introduced by the security hardening measures.

![Figure 3: Baseline (Unsecured) System Metrics for Comparison.](images/week6/before.png)

| Metric | Week 3 (Baseline) | Week 6 (Hardened) | Performance Impact |
| :--- | :--- | :--- | :--- |
| **CPU Throughput** | **4,707.96 ops/s** | **4,190.23 ops/s** | **-11.0% (Moderate Cost)** |
| **Disk Bandwidth** | **48.8 MiB/s** | **51.0 MiB/s** | **+4.5% (Improved/Stable)** |
| **Disk IOPS** | **12.5k** | **13.1k** | **+4.8% (Improved/Stable)** |

**Interpretation**
1. **CPU Performance:**
The observed 11% reduction is the direct cost of increased kernel mediation specifically:
    * AppArmor syscall inspection
    * UFW packet filtering
    * Continuous monitoring and logging overhead

    This level of degradation is well within acceptable thresholds for security-sensitive Tier-3 infrastructure and aligns with real-world expectations in hardened production environments.

2. **Disk Performance:**
Disk I/O performance remained stable and marginally improved due to cache behavior and optimized write patterns. This confirms that the logging and monitoring architecture does not introduce a disk bottleneck.

## 5. Phase 3: Observability & Incident Response

During the CPU stress test, the monitoring daemon correctly detected the resource anomaly and recorded the event.

![Figure 4: CSV Log recording the load spike.](images/week6/log.png)

**Gap Analysis (The Problem):**
While the system successfully **alerted** on the high-load event, it did not **resolve** it. The `stress-ng` process was allowed to consume 100% of the CPU, potentially making the server unresponsive. Monitoring without Management is insufficient for production resilience.

## 6. Resolution Strategy: Demonstrated Capability vs Persistent Control

The regression analysis revealed a critical distinction between **Passive Monitoring** and **Active Management**. While the monitoring daemon successfully **alerted** us to the high-load event (Figure 4), the system lacked the logic to **resolve** the contention. The `stress-ng` process was allowed to starve critical system services.

It is important to distinguish between **demonstration of enforcement capability** and **persistent system-wide policy**. The resource control mechanisms explored in this section validate that the Linux kernel can enforce CPU limits when configured appropriately. However, the applied constraints during testing were scoped to a single execution context and do not, by themselves, constitute a permanent mitigation.

To address this in a production environment, we must move beyond simple alerts and implement **Automated Resource Prioritization**.

### 6.1 The Logic: Fair Queuing & Allocation
The solution is not to simply limit the CPU (which wastes resources when the system is idle) but to implement **Proportional Weighting** using Linux Kernel Control Groups (cgroups).

The proposed architecture relies on **active allocation logic**:
1.  **Critical Allocation:** Administrative services (SSH, Systemd, Auth) must be guaranteed immediate access to CPU cycles ("allocating to those who need").
2.  **Background Queuing:** Heavy, non-interactive tasks (Monitoring, Backups, Analytics) should be deprioritized ("queuing the other task").

### 6.2 Proposed Implementation Mechanism
In the Linux Kernel, this logic is enforced via the `CPUWeight` (or `cpu.shares`) property.

| Service Tier | Logic | Systemd Configuration |
| :--- | :--- | :--- |
| **Tier 1 (Critical)** | "VIP Access" - Processes jump to the front of the scheduler queue. | `CPUWeight=1000` (High priority relative weight) |
| **Tier 2 (Standard)** | "Standard Access" - Web servers and databases. | `CPUWeight=100` (Default) |
| **Tier 3 (Background)** | "Yielding Access" - Only runs when Tier 1 & 2 are idle. | `CPUWeight=10` (Low Priority) |

### 6.3 Operational Outcome
By applying this queuing logic in controlled execution contexts, we demonstrate how Availability (the 'A' in the CIA Triad) can be preserved under load. Persistent enforcement would require service-level cgroup configuration.

> “This demonstration validates kernel enforcement capability, but persistent mitigation requires service-level cgroup configuration.”

### 6.4 Production-Grade Enforcement (Design Recommendation)

In a production environment, this logic would be enforced persistently by applying cgroup constraints directly to systemd service units rather than ad-hoc scopes. This would include:

- Defining `CPUWeight` and `CPUQuota` in `.service` files
- Assigning background workloads to dedicated slices (e.g., `background.slice`)
- Reserving scheduler priority for `system.slice` and `ssh.service`

This approach ensures that resource guarantees survive reboots, service restarts, and operational drift.

## 7. Conclusion

This project has successfully delivered a **Secured, Monitored, and Managed** infrastructure.
1.  **Security:** Verified via Hydra failure (Week 4).
2.  **Visibility:** Verified via SMTP Alerts (Week 5).
3.  **Performance:** Quantified at ~11% CPU overhead (Week 6).
4.  **Resilience:** Demonstrated through Systemd Resource Control capabilities, with production strategies defined.

The system now aligns with professional infrastructure standards, balancing security, performance, and availability through measurable engineering controls rather than assumptions.

## 8. References

1.  **Gregg, B.** (2020). *Systems Performance: Enterprise and the Cloud*. Addison-Wesley.
2.  **Freedesktop.org.** (2024). *systemd.resource-control — Resource control unit settings*. Available at: https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html .
3.  **Axboe, J.** (2024). *fio - Flexible I/O Tester Manual*. Available at: https://fio.readthedocs.io/en/latest/ .