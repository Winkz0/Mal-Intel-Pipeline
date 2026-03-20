\# M2 — VM Environment



\*\*Status:\*\* Complete

\*\*Completed:\*\* 2026-03-20



\---



\## REMnux VM Specs



| Setting | Value |

|---|---|

| VM Name | REMnux-Baseline |

| Base Image | REMnux OVA (latest) |

| Memory | 4GB |

| Processors | 2 cores |

| Disk | 100GB (SCSI) |

| Network Adapter | VMnet2 (Host-only, isolated) |

| Host Platform | VMware Workstation Pro 25H2u1 |



\---



\## Network Configuration



| Setting | Value |

|---|---|

| VMnet | VMnet2 |

| Type | Host-only |

| DHCP | Disabled |

| Subnet | 10.10.10.0/24 |

| REMnux IP | 10.10.10.10/24 |

| Gateway | None |

| DNS | None |

| External Access | None - fully isolated |



\---



\## Installed Tools



| Tool | Version | Source |

|---|---|---|

| FLOSS | 3.1.1 | REMnux default |

| Capa | 9.3.1 | REMnux default |

| Python | 3.12.3 | REMnux default |

| pip3 | present | REMnux default |

| YARA | present | REMnux default |

| pefile | 2024.8.26 | pip3 install |

| DIE (diec) | present | REMnux default |



\---



\## Snapshots



| Snapshot Name | Description |

|---|---|

| Baseline - Tools Installed, Network Isolated | Clean pre-analysis state. Revert to this between analyses. |



\---



\## Notes



\- NetworkManager was set to unmanaged by default in REMnux — fixed by setting `managed=true` in `/etc/NetworkManager/NetworkManager.conf`

\- DIE is available as `diec` on REMnux, not `die`

\- pip installs temporarily required NAT (VMnet8) — adapter switched back to VMnet2 before snapshot

\- Never overwrite the baseline snapshot





