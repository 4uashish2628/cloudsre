# Incident report CASE-tenant-a-020

* Tenant: `tenant-a`
* Alert window (UTC): 2026-01-05 16:13:54 - 2026-01-05 16:15:26
* Reconstructed window (UTC): 2026-01-05 16:13:54 - 2026-01-05 16:19:45
* Alerts: 1 (R1_bruteforce_successx1)
* Reconstructed timeline: 95 events from 2 sources
* Key entities: host:vm-a-1, ip:185.38.151.128, user:tenant-a/deploy
* CSP Dependency Index: 0.00
* Evidence isolation: {'dropped_foreign': 0, 'pseudonymised_records': 0, 'pseudonyms': 0}, residual foreign identifiers = 0
* Integrity: 50/50 sampled entries verified by Merkle proof against anchored PPL

## Timeline (first 40 events)

| UTC | source | action | principal | src | detail |
|---|---|---|---|---|---|
| 2026-01-05 16:13:54 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for root from 185.38.151.128 port 34927 ssh2 |
| 2026-01-05 16:13:54 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:13:55 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for admin from 185.38.151.128 port 30321 ssh |
| 2026-01-05 16:13:55 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:13:56 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for deploy from 185.38.151.128 port 41073 ss |
| 2026-01-05 16:13:56 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:13:58 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for ubuntu from 185.38.151.128 port 53465 ss |
| 2026-01-05 16:13:58 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:00 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for deploy from 185.38.151.128 port 31190 ss |
| 2026-01-05 16:14:00 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:02 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for deploy from 185.38.151.128 port 36605 ss |
| 2026-01-05 16:14:02 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:03 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for deploy from 185.38.151.128 port 55567 ss |
| 2026-01-05 16:14:03 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:05 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for deploy from 185.38.151.128 port 35696 ss |
| 2026-01-05 16:14:05 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:08 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for deploy from 185.38.151.128 port 62487 ss |
| 2026-01-05 16:14:08 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:09 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for root from 185.38.151.128 port 58681 ssh2 |
| 2026-01-05 16:14:09 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:12 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for admin from 185.38.151.128 port 55128 ssh |
| 2026-01-05 16:14:12 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:15 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for ubuntu from 185.38.151.128 port 64517 ss |
| 2026-01-05 16:14:15 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:19 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for root from 185.38.151.128 port 56875 ssh2 |
| 2026-01-05 16:14:19 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:19 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for ubuntu from 185.38.151.128 port 37669 ss |
| 2026-01-05 16:14:19 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:23 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for ubuntu from 185.38.151.128 port 58025 ss |
| 2026-01-05 16:14:23 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:25 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for root from 185.38.151.128 port 57375 ssh2 |
| 2026-01-05 16:14:25 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:28 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for ubuntu from 185.38.151.128 port 36568 ss |
| 2026-01-05 16:14:28 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:31 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for root from 185.38.151.128 port 51929 ssh2 |
| 2026-01-05 16:14:31 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:35 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for deploy from 185.38.151.128 port 35734 ss |
| 2026-01-05 16:14:35 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |
| 2026-01-05 16:14:38 | syslog | auth.ssh |  | 185.38.151.128 | Failed password for admin from 185.38.151.128 port 48391 ssh |
| 2026-01-05 16:14:38 | vpcflow | net.flow |  | 185.38.151.128 | eni-a003031d0 |

## Acquisition plan (survey Table 14)

| source | stakeholder | obtain from | dependency |
|---|---|---|---|
| syslog | Virtual machine | service owner (CSP fallback) | OP |
| vpcflow | Virtual machine | service owner (CSP fallback) | OP |
