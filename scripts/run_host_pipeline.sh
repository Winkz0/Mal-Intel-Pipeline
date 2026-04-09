#!/bin/bash
# run_host_pipeline.sh — Run the host-side pipeline stages for a sample
#
# Usage:
#   ./scripts/run_host_pipeline.sh <sha256>
#   ./scripts/run_host_pipeline.sh <sha256> --no-raw
#   ./scripts/run_host_pipeline.sh <sha256> --skip-checkpoint

if [ -z "$1" ]; then
    echo "Usage: ./scripts/run_host_pipeline.sh <sha256> [--no-raw] [--skip-checkpoint]"
    exit 1
fi

SHA256="$1"
shift
EXTRA_ARGS="$@"

echo ""
echo "============================================================"
echo "  Mal-Intel-Pipeline — Host Processing"
echo "  Sample: ${SHA256:0:16}..."
echo "============================================================"
echo ""

# Stage 1 — Synthesis
echo "[1/4] Running LLM synthesis..."
python pipeline/llm_synthesis/synthesize.py "$SHA256" $EXTRA_ARGS
if [ $? -ne 0 ]; then
    echo "[!] Synthesis failed — aborting pipeline"
    exit 1
fi

# Stage 2 — Report generation
echo ""
echo "[2/4] Generating reports..."
python pipeline/reporting/report.py "$SHA256"

# Stage 3 — Rule validation
echo ""
echo "[3/4] Validating rules..."
python pipeline/rule_validation/validate.py "$SHA256"

# Stage 4 — Delta analysis
echo ""
echo "[4/4] Running delta analysis..."
python pipeline/delta_analysis/delta.py "$SHA256"

echo ""
echo "============================================================"
echo "  Pipeline complete for ${SHA256:0:16}..."
echo "============================================================"