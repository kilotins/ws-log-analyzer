# WebSphere Log Analyzer

CLI tool and web GUI that analyzes WebSphere / Java logs and generates a triage report.

## Features

- Detects common WebSphere errors and message codes
- Identifies Java exceptions with root cause extraction
- Signal tagging (OOM/GC, HungThreads, DB/Pool, SSL/TLS, HTTP errors)
- Timeline histogram of events
- Secret redaction (bearer tokens, passwords, API keys)
- Generates Markdown report
- Optional AI root cause analysis via Claude
- Streamlit web GUI with file upload, report history, and download

## CLI Usage

```
./wslog.py SystemOut.log
./wslog.py SystemOut.log --top 20 --samples 10 --hist-minutes 5
./wslog.py SystemOut.log --format json
```

## GUI Usage

Install the GUI dependency:

```
pip install -e ".[gui]"
```

Run the Streamlit app:

```
streamlit run app.py
```

Then open your browser to the URL shown (typically http://localhost:8501).

Upload a `.log` or `.gz` file, adjust settings, and click **Analyze**. Reports are saved in the `reports/` directory and can be downloaded or reviewed in the **History** tab.
