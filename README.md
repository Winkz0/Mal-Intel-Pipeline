# Mal-Intel-Pipeline

> A modular, human-in-the-loop malware intelligence and analysis pipeline for security researchers and SOC analysts.

[![CI](https://github.com/Winkz0/Mal-Intel-Pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/Winkz0/Mal-Intel-Pipeline/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

Mal-Intel-Pipeline ingests threat-intelligence feeds, acquires malware samples,
performs static analysis in an isolated REMnux environment, synthesizes findings
with the Claude API, and produces structured analyst reports with YARA/Sigma
detection rules and STIX 2.1 exports. A human analyst approves the work at three
checkpoints along the way.

Published analysis writeups: **https://winkz0.github.io/Mal-Intel-Pipeline/**

> **Status: complete.** All ten planned milestones (M1–M10) are implemented and the
> pipeline runs end-to-end. It remains a personal research project — started to go
> deeper on Python, malware analysis, threat-intel feeds, and detection engineering.

---

## What it does

- **Ingests** IOCs from CISA KEV, AlienVault OTX, and Abuse.ch / MalwareBazaar, then normalizes and de-duplicates them.
- **Acquires** samples from MalwareBazaar / VirusTotal into an encrypted quarantine.
- **Analyzes** samples statically on an isolated REMnux VM (FLOSS, Capa, pefile, Detect-It-Easy).
- **Synthesizes** findings with the Claude API into analyst + executive reports.
- **Generates** YARA and Sigma rules with confidence ratings and a MITRE ATT&CK mapping.
- **Validates** the generated rules, then **exports** STIX 2.1 bundles and publishes writeups.
- **Delta analysis** clusters related samples and builds an interactive threat graph.
- **RAG assistant** answers natural-language questions over the accumulated corpus.

See [`docs/architecture/overview.md`](docs/architecture/overview.md) for the full data-flow diagram.

---

## Getting started

```bash
# 1. Clone and enter the repo
git clone https://github.com/Winkz0/Mal-Intel-Pipeline.git
cd Mal-Intel-Pipeline

# 2. Install dependencies (creates ./venv and installs requirements)
make setup

# 3. Configure secrets
cp config/secrets.env.template config/secrets.env
#    then edit config/secrets.env and fill in your own API keys
```

Static analysis expects a **REMnux VM** reachable on an isolated host-only network
(see [`docs/milestones/M2-vm-environment.md`](docs/milestones/M2-vm-environment.md)).
Connection defaults live in `pipeline/utils/remote.py`.

Common tasks are wrapped in the `Makefile` — run `make help` to list them
(`make lint`, `make compile`, `make scan`, `make dashboard`).

---

## Design philosophy

- Human checkpoints are a first-class feature, not an afterthought.
- Claude augments analyst judgment; it does not replace it.
- Modular by design — each stage is independently runnable.
- Samples and secrets never enter version control.

---

## Output per sample

| Output | Description |
|---|---|
| Technical Report | Structured findings, analyst-facing |
| Executive Summary | Stakeholder-facing, non-technical |
| YARA Rule | With confidence rating and reasoning |
| Sigma Rule | Mapped to common log sources (Splunk / EDR) |
| MITRE ATT&CK Map | TTP mapping per sample |
| STIX 2.1 Bundle | Machine-readable threat-intel export |

## Human checkpoints

| Checkpoint | Trigger | Analyst action |
|---|---|---|
| #1 Post-Ingestion | IOCs extracted from feeds | Review IOCs, approve samples for analysis |
| #2 Post-Static Analysis | Static analysis complete | Review findings, optionally add custom YARA rules |
| #3 Post-Synthesis | LLM output generated | Tune and annotate rules/report before export |

---

## Stack

| Layer | Tooling |
|---|---|
| Intel feeds | CISA KEV, AlienVault OTX, Abuse.ch / MalwareBazaar |
| Sample acquisition | MalwareBazaar API, VirusTotal API |
| Static analysis | FLOSS, Capa, pefile, Detect-It-Easy (on REMnux) |
| LLM synthesis | Claude API (`anthropic`) |
| RAG assistant | ChromaDB |
| Reporting | Markdown reports, STIX 2.1 export |
| Rule validation | YARA, Sigma |
| Dashboard | Streamlit |
| Publishing | Jekyll / GitHub Pages |

---

## Milestones

| # | Milestone | Status |
|---|---|---|
| M1 | Repo & GitHub setup | ✅ Complete |
| M2 | VM environment | ✅ Complete |
| M3 | API accounts & keys | ✅ Complete |
| M4 | Intel feed ingestion | ✅ Complete |
| M5 | Sample acquisition | ✅ Complete |
| M6 | Static analysis engine | ✅ Complete |
| M7 | LLM synthesis layer | ✅ Complete |
| M8 | Report generation | ✅ Complete |
| M9 | Rule validation | ✅ Complete |
| M10 | Delta analysis | ✅ Complete |

---

## Repository structure

```
Mal-Intel-Pipeline/
├── .github/workflows/   # CI: lint, byte-compile, secret scan
├── config/              # secrets.env.template (real secrets are git-ignored)
├── docs/                # Jekyll site: architecture, milestones, analysis posts
├── pipeline/
│   ├── ingestion/       # feed ingestion, normalization, dedup, checkpoint #1
│   ├── acquisition/     # sample download into encrypted quarantine
│   ├── static_analysis/ # FLOSS / Capa / pefile / DIE runners (REMnux)
│   ├── scoring/         # triage scoring
│   ├── llm_synthesis/   # Claude synthesis + checkpoint #2/#3
│   ├── reporting/       # report + rule extraction
│   ├── rule_validation/ # YARA / Sigma validation
│   ├── delta_analysis/  # clustering + threat graph
│   ├── export/          # STIX 2.1 export, handoff
│   ├── rag/             # ChromaDB retrieval assistant
│   └── utils/           # DB, naming, REMnux remoting
├── scripts/             # operator entrypoints (ask, manual_add, draft_post)
├── samples/             # quarantine / analyzed (never committed)
├── output/              # reports, rules, logs, STIX (never committed)
├── checkpoints/         # approved manifests (never committed)
├── dashboard.py         # Streamlit analyst dashboard
└── requirements.txt
```

---

## Security notes

- Real API keys live only in `config/secrets.env`, which is git-ignored. The committed
  `config/secrets.env.template` documents the required keys with placeholder values.
- Malware samples are never committed — `samples/` and `output/` are git-ignored.
- A `detect-secrets` baseline (`.secrets.baseline`) guards against accidental secret commits and runs in CI.

## License

Released under the [MIT License](LICENSE).
