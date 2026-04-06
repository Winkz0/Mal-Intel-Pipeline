#!/bin/bash
# transfer.sh — SCP helper for Mal-Intel-Pipeline
# Handles file transfers between host and REMnux
#
# Usage:
#   ./scripts/transfer.sh push-checkpoint    Push latest approved manifest to REMnux
#   ./scripts/transfer.sh pull-analysis      Pull all new analysis JSONs from REMnux
#   ./scripts/transfer.sh pull <sha256>      Pull a specific analysis JSON

REMNUX_USER="remnux"
REMNUX_IP="10.10.10.10"
REMOTE_REPO="~/Mal-Intel-Pipeline"
LOCAL_REPO="$(cd "$(dirname "$0")/.." && pwd)"

case "$1" in
    push-checkpoint)
        # Find the most recent approved manifest
        MANIFEST=$(ls -t "$LOCAL_REPO/checkpoints/approved_"*.json 2>/dev/null | head -1)
        if [ -z "$MANIFEST" ]; then
            echo "[!] No approved manifest found in checkpoints/"
            exit 1
        fi
        echo "[*] Pushing $(basename "$MANIFEST") to REMnux..."
        scp "$MANIFEST" "$REMNUX_USER@$REMNUX_IP:$REMOTE_REPO/checkpoints/"
        echo "[+] Done"
        ;;

    pull-analysis)
        echo "[*] Pulling all analysis JSONs from REMnux..."
        mkdir -p "$LOCAL_REPO/output/analysis"
        scp "$REMNUX_USER@$REMNUX_IP:$REMOTE_REPO/output/analysis/*.analysis.json" \
            "$LOCAL_REPO/output/analysis/" 2>/dev/null
        COUNT=$(ls "$LOCAL_REPO/output/analysis/"*.analysis.json 2>/dev/null | wc -l)
        echo "[+] $COUNT analysis file(s) in output/analysis/"
        ;;

    pull)
        if [ -z "$2" ]; then
            echo "Usage: ./scripts/transfer.sh pull <sha256>"
            exit 1
        fi
        echo "[*] Pulling analysis for $2..."
        mkdir -p "$LOCAL_REPO/output/analysis"
        scp "$REMNUX_USER@$REMNUX_IP:$REMOTE_REPO/output/analysis/$2.analysis.json" \
            "$LOCAL_REPO/output/analysis/"
        echo "[+] Done"
        ;;

    *)
        echo "Usage: ./scripts/transfer.sh {push-checkpoint|pull-analysis|pull <sha256>}"
        echo ""
        echo "  push-checkpoint   Push latest approved manifest to REMnux"
        echo "  pull-analysis     Pull all analysis JSONs from REMnux"
        echo "  pull <sha256>     Pull a specific analysis JSON"
        exit 1
        ;;
esac