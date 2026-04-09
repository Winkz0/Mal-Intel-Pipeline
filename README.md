# Overview

Mal-Intel-Pipeline is a modular, human-in-the-loop malware intelligence and analysis pipeline built for security researchers and SOC analysts.

It ingests threat intelligence feeds, acquires malware samples, performs static analysis in an isolated REMnux environment, synthesizes findings via the Claude API, and generates structured analyst reports with YARA/Sigma Detection rules. This is a passion project with the desired outcome of learning more about Python, malware analysis, how intel feeds work, learning the basics of having a GitHub Repo. This project is still in its infancy, and while there is no desired "end goal" this will continue to change dynamically as time goes by and further knowledge is gained.



\# Getting Started

1. Clone the repo

2. Copy 'config/secrets.env.template' to 'config/secrets.env' and fill in your API keys (all required keys are listed in the file)

3. Set up a REMnux VM and clone the repo there as well

4 See the [session startup playbook](docs/playbook.md) for the full workflow

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





\## Milestones



| # | Milestone | Status |

|---|---|---|

| M1 | Repo \& GitHub Setup | ✅ Complete |

| M2 | VM Environment | ✅ Complete |

| M3 | API Accounts \& Keys | ✅ Complete |

| M4 | Intel Feed Ingestion | ✅ Complete |

| M5 | Sample Acquisition | ✅ Complete |

| M6 | Static Analysis Engine | ✅ Complete |

| M7 | LLM Synthesis Layer | ✅ Complete |

| M8 | Report Generation | ✅ Complete |

| M9 | Rule Validation | ✅ Complete |

| M10 | Delta Analysis | ✅ Complete |



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

\*\*copy/paste pool 🔄 In Progress ✅ Complete

\*\*Current Milestone:\*\* \ Workshopping V2 Ideas

\*\*Last Updated:\*\* 2026-04-07

