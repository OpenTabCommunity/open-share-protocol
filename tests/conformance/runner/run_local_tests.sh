#!/usr/bin/env bash
set -euo pipefail
DIR=$(dirname "$0")
python3 -m pip install -r "$DIR/../requirements.txt"
python3 "$DIR/generate_vectors.py"
python3 "$DIR/runner.py" "$DIR/../vectors"

echo "Local conformance run finished."
