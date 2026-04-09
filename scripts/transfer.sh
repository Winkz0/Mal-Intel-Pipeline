#!/bin/bash
# transfer.sh — SCP helper for Mal-Intel-Pipeline
# Now wraps the Python remote module for consistent behavior.
#
# Usage:
#   ./scripts/transfer.sh test                Test REMnux connectivity
#   ./scripts/transfer.sh push-checkpoint     Push latest approved manifest
#   ./scripts/transfer.sh pull-analysis       Pull all new analysis JSONs
#   ./scripts/transfer.sh pull <sha256>       Pull a specific analysis JSON

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

case "$1" in
    test)
        python -c "
from pipeline.utils.remote import test_connection
if test_connection():
    print('[+] REMnux connection successful')
else:
    print('[!] REMnux connection failed')
"
        ;;

    push-checkpoint)
        python -c "
from pipeline.utils.remote import push_checkpoint
push_checkpoint()
"
        ;;

    pull-analysis)
        python -c "
from pipeline.utils.remote import pull_analysis
pulled = pull_analysis()
print(f'[+] {len(pulled)} analysis file(s) pulled')
"
        ;;

    pull)
        if [ -z "$2" ]; then
            echo "Usage: ./scripts/transfer.sh pull <sha256>"
            exit 1
        fi
        python -c "
from pipeline.utils.remote import pull_analysis
pulled = pull_analysis('$2')
if pulled:
    print(f'[+] Pulled: {pulled[0]}')
else:
    print('[!] Pull failed')
"
        ;;

    *)
        echo "Usage: ./scripts/transfer.sh {test|push-checkpoint|pull-analysis|pull <sha256>}"
        echo ""
        echo "  test              Test SSH connectivity to REMnux"
        echo "  push-checkpoint   Push latest approved manifest"
        echo "  pull-analysis     Pull all analysis JSONs"
        echo "  pull <sha256>     Pull a specific analysis JSON"
        exit 1
        ;;
esac