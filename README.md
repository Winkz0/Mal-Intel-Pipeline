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



\## Sample Acquisition

Programmatic sample downloads from MalwareBazaar are supported via the API ('acquire_sample.py'), but both MB and VT require paid tiers for actual file downloads. Manual acquisition on REMnux is the primary workflow:

1. Switch REMnux network adapter to NAT in VMware
2. Download the sample archive:
	'wget --header "Auth-Key: <key>" --post-data "query=get_file&sha256_hash=<HASH>" https://mb-api.abuse.ch/api/v1 -0 ~/<name>.zip'
2. Verify the download is a ZIP (not JSON error): 'file ~/<name.zip'
3. Swich REMnux network adapter back to VMnet2 (isolated)
5. Extract: '7z x -pinfected ~/<name>.zip -o/tmp/<name>/'
6. Register: 'python3 pipeline/acquisition/register_sample.py <path> --family <name> --tags <tag1,tag2>'

Samples are stored in 'samples/quarantine/' (gitignored) with JSON sidecar metadata
Samples never leave REMnux VM



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

\*\*copy/paste pool 🔄 In Progress

\*\*Current Milestone:\*\* \ M10 - Delta Analysis

\*\*Last Updated:\*\* 2026-03-30

