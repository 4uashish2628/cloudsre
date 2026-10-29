# Incident report CASE-tenant-a-016

* Tenant: `tenant-a`
* Alert window (UTC): 2026-01-05 14:44:40 - 2026-01-05 14:48:13
* Reconstructed window (UTC): 2026-01-05 14:44:30 - 2026-01-05 18:18:50
* Alerts: 10 (R4_instance_burstx3, R4_mining_pool_trafficx7)
* Reconstructed timeline: 362 events from 4 sources
* Key entities: host:vm-a-x17, host:vm-a-x18, host:vm-a-x19, host:vm-a-x20, host:vm-a-x21, host:vm-a-x22, host:vm-a-x23, ip:192.0.2.10, ip:45.9.148.21, ip:77.155.55.131, user:tenant-a/dave.a, user:tenant-a/erin.a
* CSP Dependency Index: 0.50
* Evidence isolation: {'dropped_foreign': 0, 'pseudonymised_records': 0, 'pseudonyms': 0}, residual foreign identifiers = 0
* Integrity: 50/50 sampled entries verified by Merkle proof against anchored PPL

## Timeline (first 40 events)

| UTC | source | action | principal | src | detail |
|---|---|---|---|---|---|
| 2026-01-05 14:44:30 | cloudtrail | compute.describe | dave.a | 77.155.55.131 | DescribeInstances |
| 2026-01-05 14:44:40 | cloudtrail | compute.run | dave.a | 77.155.55.131 | RunInstances |
| 2026-01-05 14:45:00 | cloudtrail | compute.run | dave.a | 77.155.55.131 | RunInstances |
| 2026-01-05 14:45:10 | cloudtrail | compute.run | dave.a | 77.155.55.131 | RunInstances |
| 2026-01-05 14:45:20 | hypervisor | hv.vm_start |  |  | domain vm-a-x17 (tenant-a) started vcpus=32 |
| 2026-01-05 14:45:26 | cloudtrail | compute.run | dave.a | 77.155.55.131 | RunInstances |
| 2026-01-05 14:45:38 | cloudtrail | compute.run | dave.a | 77.155.55.131 | RunInstances |
| 2026-01-05 14:45:40 | hypervisor | hv.vm_start |  |  | domain vm-a-x18 (tenant-a) started vcpus=32 |
| 2026-01-05 14:45:50 | hypervisor | hv.vm_start |  |  | domain vm-a-x19 (tenant-a) started vcpus=32 |
| 2026-01-05 14:45:56 | cloudtrail | compute.run | dave.a | 77.155.55.131 | RunInstances |
| 2026-01-05 14:46:06 | hypervisor | hv.vm_start |  |  | domain vm-a-x20 (tenant-a) started vcpus=32 |
| 2026-01-05 14:46:13 | cloudtrail | compute.run | dave.a | 77.155.55.131 | RunInstances |
| 2026-01-05 14:46:18 | hypervisor | hv.vm_start |  |  | domain vm-a-x21 (tenant-a) started vcpus=32 |
| 2026-01-05 14:46:36 | hypervisor | hv.vm_start |  |  | domain vm-a-x22 (tenant-a) started vcpus=32 |
| 2026-01-05 14:46:40 | vpcflow | net.flow |  | 10.1.9.17 | eni-x000017 |
| 2026-01-05 14:46:40 | hypervisor | hv.heartbeat |  |  | domain vm-a-x17 (tenant-a) heartbeat ok cpu=98% mem=41% |
| 2026-01-05 14:46:53 | hypervisor | hv.vm_start |  |  | domain vm-a-x23 (tenant-a) started vcpus=32 |
| 2026-01-05 14:47:00 | vpcflow | net.flow |  | 10.1.9.18 | eni-x000018 |
| 2026-01-05 14:47:00 | hypervisor | hv.heartbeat |  |  | domain vm-a-x18 (tenant-a) heartbeat ok cpu=99% mem=41% |
| 2026-01-05 14:47:10 | vpcflow | net.flow |  | 10.1.9.19 | eni-x000019 |
| 2026-01-05 14:47:10 | hypervisor | hv.heartbeat |  |  | domain vm-a-x19 (tenant-a) heartbeat ok cpu=99% mem=41% |
| 2026-01-05 14:47:26 | vpcflow | net.flow |  | 10.1.9.20 | eni-x000020 |
| 2026-01-05 14:47:26 | hypervisor | hv.heartbeat |  |  | domain vm-a-x20 (tenant-a) heartbeat ok cpu=97% mem=41% |
| 2026-01-05 14:47:38 | vpcflow | net.flow |  | 10.1.9.21 | eni-x000021 |
| 2026-01-05 14:47:38 | hypervisor | hv.heartbeat |  |  | domain vm-a-x21 (tenant-a) heartbeat ok cpu=98% mem=41% |
| 2026-01-05 14:47:56 | vpcflow | net.flow |  | 10.1.9.22 | eni-x000022 |
| 2026-01-05 14:47:56 | hypervisor | hv.heartbeat |  |  | domain vm-a-x22 (tenant-a) heartbeat ok cpu=97% mem=41% |
| 2026-01-05 14:48:13 | vpcflow | net.flow |  | 10.1.9.23 | eni-x000023 |
| 2026-01-05 14:48:13 | hypervisor | hv.heartbeat |  |  | domain vm-a-x23 (tenant-a) heartbeat ok cpu=97% mem=41% |
| 2026-01-05 14:51:40 | vpcflow | net.flow |  | 10.1.9.17 | eni-x000017 |
| 2026-01-05 14:52:00 | vpcflow | net.flow |  | 10.1.9.18 | eni-x000018 |
| 2026-01-05 14:52:10 | vpcflow | net.flow |  | 10.1.9.19 | eni-x000019 |
| 2026-01-05 14:52:26 | vpcflow | net.flow |  | 10.1.9.20 | eni-x000020 |
| 2026-01-05 14:52:38 | vpcflow | net.flow |  | 10.1.9.21 | eni-x000021 |
| 2026-01-05 14:52:56 | vpcflow | net.flow |  | 10.1.9.22 | eni-x000022 |
| 2026-01-05 14:53:13 | vpcflow | net.flow |  | 10.1.9.23 | eni-x000023 |
| 2026-01-05 14:56:40 | vpcflow | net.flow |  | 10.1.9.17 | eni-x000017 |
| 2026-01-05 14:56:40 | hypervisor | hv.heartbeat |  |  | domain vm-a-x17 (tenant-a) heartbeat ok cpu=96% mem=41% |
| 2026-01-05 14:57:00 | vpcflow | net.flow |  | 10.1.9.18 | eni-x000018 |
| 2026-01-05 14:57:00 | hypervisor | hv.heartbeat |  |  | domain vm-a-x18 (tenant-a) heartbeat ok cpu=99% mem=41% |

## Acquisition plan (survey Table 14)

| source | stakeholder | obtain from | dependency |
|---|---|---|---|
| cloudtrail | Cloud service owner | service owner (CSP fallback) | OP |
| hypervisor | CSP (hypervisor) | CSP | P |
| s3access | CSP (cloud storage management) | CSP | P |
| vpcflow | Virtual machine | service owner (CSP fallback) | OP |
