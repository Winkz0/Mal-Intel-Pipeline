## Summary

<!-- What does this change do, and which pipeline stage does it touch? -->

## Pipeline stage(s)

- [ ] Ingestion
- [ ] Acquisition
- [ ] Static analysis
- [ ] LLM synthesis
- [ ] Reporting / rule validation
- [ ] Delta analysis / export
- [ ] Tooling / docs / CI

## Checklist

- [ ] No secrets, API keys, or live sample hashes committed
- [ ] `ruff check pipeline scripts` passes
- [ ] Sources byte-compile (`python -m compileall`)
- [ ] Human-checkpoint behavior preserved where applicable
