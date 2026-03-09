#!/bin/bash
# Start WS Log Analyzer with all dependencies
DIR="$(cd "$(dirname "$0")" && pwd)"
source "$DIR/.venv/bin/activate"
streamlit run "$DIR/app.py" "$@"
