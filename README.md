# Mal-Intel-Pipeline

Modular human-in-the-loop Malware intel \& Analysis pipeline



\# Mal-Intel-Pipeline



A modular, human-in-the-loop threat intelligence and malware analysis pipeline.



Ingests threat intel feeds, acquires malware samples, performs static analysis, and generates structured analyst reports with YARA/Sigma rule suggestions — augmented by Claude AI at the synthesis layer.



\---



\## Design Philosophy



\- Human checkpoints are a first-class feature, not an afterthought

\- Claude augments analyst judgment, it does not replace it

\- Modular by design — each layer is independently functional

\- v1 scope: ingestion → static analysis → report + rules

\- Dynamic sandbox execution is v2



\---



\## Target Output Per Sample



| Output | Description |

|---|---|

| Technical Report | Structured findings, analyst-facing |

| Executive Summary | Stakeholder-facing, non-technical |

| YARA Rule | With confidence rating and reasoning |

| Sigma Rule | Mapped to CrowdStrike/Splunk log sources |

| MITRE ATT\&CK Map | TTP mapping per sample |



\---



\## Human Checkpoints



| Checkpoint | Trigger | Analyst Action |

|---|---|---|

| #1 Post-Ingestion | IOCs extracted from feeds | Review IOCs, approve samples for analysis |

| #2 Post-Static Analysis | Static analysis complete | Review findings, optionally add custom YARA rules |

| #3 Post-Synthesis | LLM output generated | Tune and annotate rules/report before export |



\---



\## Stack



| Layer | Tooling |

|---|---|

| Intel Feeds | CISA JSON, AlienVault OTX, Abuse.ch/MalwareBazaar |

| Sample Acquisition | MalwareBazaar API, VirusTotal API |

| Static Analysis | FLOSS, Capa, pefile, Detect-It-Easy |

| LLM Synthesis | Claude API |

| Report Output | Markdown → PDF (Pandoc) or Flask UI |

| Rule Validation | PyYARA, Sigma CLI |



\---



\## Milestones



| # | Milestone | Status |

|---|---|---|

| M1 | Repo \& GitHub Setup | ✅ Complete |

| M2 | VM Environment | ✅ Complete |

| M3 | API Accounts \& Keys | ✅ Complete |

| M4 | Intel Feed Ingestion | ✅ Complete |

| M5 | Sample Acquisition | 🔄 In Progress |

| M6 | Static Analysis Engine | ⬜ Not Started |

| M7 | LLM Synthesis Layer | ⬜ Not Started |

| M8 | Report Generation | ⬜ Not Started |

| M9 | Rule Validation | ⬜ Not Started |

| M10 | Delta Analysis | ⬜ Not Started |



\---



\## Repository Structure

```

mal-intel-pipeline/

├── docs/

│   ├── milestones/

│   └── architecture/

├── config/

├── pipeline/

│   ├── ingestion/

│   ├── acquisition/

│   ├── static\_analysis/

│   ├── llm\_synthesis/

│   ├── reporting/

│   ├── rule\_validation/

│   └── delta\_analysis/

├── samples/

│   ├── quarantine/

│   └── analyzed/

├── output/

│   ├── reports/

│   ├── rules/

│   │   ├── yara/

│   │   └── sigma/

│   └── logs/

├── checkpoints/

├── tests/

└── scripts/

```



\---



\## Status



\*\*Current Milestone:\*\* M1 — Repo \& GitHub Setup

\*\*Last Updated:\*\* 2026-03-19

