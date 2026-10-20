from flask import Flask, render_template, request, jsonify
import threading
import json
import os
import re
import sys
import time
import logging
from collections import Counter

# --- Server-side scan activity log ----------------------------------------
#
# Everything printed below goes to stdout, which the launchers redirect to
# ~/labs/scanner.log. Watch it live from the server side with:
#     tail -f ~/labs/scanner.log
# or run ./scanner-start.sh in the foreground and watch this terminal.
#
# stdout/stderr are forced to line buffering: when output is redirected to a
# file Python block-buffers it, so scan progress only arrived in large chunks
# and prints interleave halfway through Flask's own lines. Line buffering
# makes every line appear the moment it is written.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(line_buffering=True, write_through=True)
    except (AttributeError, ValueError, OSError):
        pass  # older Python / already closed stream

# The front page polls /results every 300 ms, so a single scan buries its own
# progress under thousands of Flask request lines (they were more than half of
# the log). Drop those access lines and keep everything else: startup banner,
# warnings, errors and the scan activity printed below.
_ACCESS_LOG_PATTERN = re.compile(
    r"\s-\s-\s\[\d{2}/\w{3}/\d{4}\s\d{2}:\d{2}:\d{2}\]"
)


class _AccessLogFilter(logging.Filter):
    """Suppress Flask's one-line-per-request chatter."""

    def filter(self, record):
        try:
            message = record.getMessage()
        except Exception:
            return True
        return not _ACCESS_LOG_PATTERN.search(message)


logging.getLogger("werkzeug").addFilter(_AccessLogFilter())

app = Flask(__name__)


def log(message):
    """One timestamped, immediately-flushed server-side activity line."""
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def format_duration(seconds):
    """12.4s, or 3m 12.4s once a scan passes a minute."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(seconds, 60)
    return f"{int(minutes)}m {secs:0.1f}s"


class StageTimer:
    """Measures one scan stage so its duration can be reported server side."""

    def __init__(self, label):
        self.label = label
        self.started = time.monotonic()
        log(f"{self.label}: started")

    def done(self, detail=""):
        elapsed = time.monotonic() - self.started
        log(f"{self.label}: finished in {format_duration(elapsed)}"
            + (f" - {detail}" if detail else ""))
        return elapsed

# Store scan results globally
scan_results = {
    "status": "idle",
    "target": "",
    "vulnerabilities": [],
    "progress": 0,
    "total_tests": 0,
    # Live progress reporting (rendered on the front page while a scan runs).
    "activity": "Idle",
    "stages": [],
    "models": [],
}

# The ordered stages a scan moves through. The front page shows each one as
# pending -> active -> done (or error) so the tester can see exactly where the
# scan currently is.
STAGE_DEFINITIONS = [
    ("crawl", "Crawling target & discovering endpoints"),
    ("fuzz", "Fuzzing endpoints with attack payloads"),
    ("analyze", "Analyzing responses (feature extraction)"),
    ("classify", "Machine-learning classification & anomaly detection"),
    ("report", "Generating vulnerability report"),
]

# The individual models that make up the detection engine. They are surfaced
# separately so the UI can show which one is working at any given moment.
MODEL_DEFINITIONS = [
    ("scaler", "StandardScaler", "Feature normalisation"),
    ("random_forest", "Random Forest", "Supervised classifier (100 trees)"),
    ("isolation_forest", "Isolation Forest", "Unsupervised anomaly detector"),
]

# Pretty wording for the live activity line (per-model badges use the raw
# status directly).
MODEL_ACTIVITY = {
    "training": "training",
    "fitting": "fitting",
    "predicting": "predicting",
    "done": "ready",
}


def reset_scan_status():
    """(Re)initialise the live status structure that drives the front page."""
    scan_results["activity"] = "Initialising…"
    scan_results["stages"] = [
        {"id": stage_id, "label": label, "status": "pending", "detail": ""}
        for stage_id, label in STAGE_DEFINITIONS
    ]
    scan_results["models"] = [
        {
            "id": model_id,
            "label": label,
            "note": note,
            "status": "pending",
            "detail": "",
        }
        for model_id, label, note in MODEL_DEFINITIONS
    ]


def _refresh_activity():
    """Set the single activity line from whichever stage is currently active."""
    for stage in scan_results.get("stages", []):
        if stage["status"] == "active":
            detail = stage.get("detail")
            scan_results["activity"] = (
                f"{stage['label']} — {detail}" if detail else stage["label"]
            )
            return
    if scan_results.get("status") == "complete":
        scan_results["activity"] = "Scan complete"


def set_stage(stage_id, status, detail=None):
    """Update one stage's status (and optional detail) and refresh the UI."""
    for stage in scan_results.get("stages", []):
        if stage["id"] == stage_id:
            stage["status"] = status
            if detail is not None:
                stage["detail"] = detail
            break
    _refresh_activity()


def set_model(model_id, status, detail=None):
    """Record what a model is doing and surface it on the activity line."""
    for model in scan_results.get("models", []):
        if model["id"] == model_id:
            model["status"] = status
            if detail is not None:
                model["detail"] = detail
            break
    if status in MODEL_ACTIVITY:
        label = next(
            (m["label"] for m in scan_results.get("models", [])
             if m["id"] == model_id),
            model_id,
        )
        scan_results["activity"] = (
            f"{label} {MODEL_ACTIVITY[status]}"
            + (f" — {detail}" if detail else "")
        )
        # Mirror it to the server-side log so model activity is visible in
        # the terminal alongside the stage progress.
        log(f"{label} {MODEL_ACTIVITY[status]}"
            + (f" - {detail}" if detail else ""))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    target_url = request.form.get('target_url')
    if not target_url:
        return jsonify({"error": "No target URL provided"}), 400

    # Optional login details for the target (e.g. DVWA/NodeGoat account).
    # Left blank, the scanner falls back to its own known default account
    # for the detected target type so quick local testing still works.
    username = request.form.get('username') or None
    password = request.form.get('password') or None

    # The tester must explicitly confirm they are authorised to test this
    # target before any active scanning begins.
    authorized = request.form.get('authorized')
    if not authorized:
        return jsonify({
            "error": "You must confirm you are authorised to test this "
                     "target before scanning can begin."
        }), 400

    # Reset results
    scan_results['status'] = 'running'
    scan_results['target'] = target_url
    scan_results['vulnerabilities'] = []
    scan_results['progress'] = 0
    reset_scan_status()

    log("=" * 62)
    log(f"SCAN REQUEST | target={target_url}")
    log(f"Authorisation confirmed; account="
        f"{username or '(auto-selected default)'}")
    log("=" * 62)

    # Run scan in background thread
    thread = threading.Thread(
        target=run_scan,
        args=(target_url, username, password)
    )
    thread.daemon = True
    thread.start()

    return jsonify({"message": "Scan started", "target": target_url})

@app.route('/results')
def get_results():
    return jsonify(scan_results)

# Stage order used when reporting timings in the final summary.
STAGE_ORDER = [stage_id for stage_id, _ in STAGE_DEFINITIONS]


def _log_scan_summary(target_url, started_at, scan_started, durations,
                      counts, report):
    """Server-side recap: how long the scan took, what it covered, what it found."""
    finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
    total = time.monotonic() - scan_started

    log("=" * 62)
    log("SCAN SUMMARY")
    log(f"  Target          : {target_url}")
    log(f"  Started         : {started_at}")
    log(f"  Finished        : {finished_at}")
    log(f"  Total scan time : {format_duration(total)}")

    stage_bits = " | ".join(
        f"{name} {format_duration(durations[name])}"
        for name in STAGE_ORDER if name in durations
    )
    if stage_bits:
        log(f"  Stage timings   : {stage_bits}")

    log(f"  Coverage        : {counts['endpoints']} endpoints, "
        f"{counts['responses']} responses, "
        f"{counts['features']} feature vectors")
    log(f"  Raw findings    : {counts['detections']} before deduplication")

    if report:
        by_severity = Counter(v['severity'] for v in report)
        by_type = Counter(v['vulnerability_type'] for v in report)
        by_status = Counter(v.get('verification_status', 'n/a') for v in report)
        severity_bits = ", ".join(
            f"{name} {by_severity[name]}"
            for name in ('Critical', 'High', 'Medium', 'Low')
            if by_severity.get(name)
        )
        type_bits = ", ".join(f"{name} {n}" for name, n in by_type.most_common())
        status_bits = ", ".join(f"{name} {n}" for name, n in by_status.most_common())
        log(f"  Findings        : {len(report)} unique ({status_bits})")
        log(f"  By severity     : {severity_bits or 'none'}")
        log(f"  By type         : {type_bits or 'none'}")
        log(f"  Report IDs      : {report[0]['id']} ... {report[-1]['id']}"
            f" (listed in that order)")
    else:
        log("  Findings        : 0")

    log("SCAN COMPLETE")
    log("=" * 62)


def run_scan(target_url, username=None, password=None):
    """Main scan orchestrator - calls all modules"""
    from crawler.crawler import Crawler
    from fuzzer.fuzzer import Fuzzer
    from analyzer.analyzer import Analyzer
    from ml_engine.classifier import Classifier
    from reporter.reporter import Reporter

    scan_started = time.monotonic()
    started_at = time.strftime("%Y-%m-%d %H:%M:%S")
    durations = {}
    counts = {"endpoints": 0, "responses": 0, "features": 0,
              "detections": 0}
    report = []

    log(f"Scan thread started on {target_url} at {started_at}")

    try:
        # Phase 1: Crawl
        set_stage("crawl", "active", "launching crawler…")
        scan_results['progress'] = 5
        timer = StageTimer("Crawl")

        crawler = Crawler(target_url, username=username, password=password)

        try:
            endpoints = crawler.crawl(
                on_progress=lambda detail: set_stage("crawl", "active", detail)
            )
        finally:
            crawler.close()

        counts["endpoints"] = len(endpoints)
        durations["crawl"] = timer.done(
            f"{len(endpoints)} endpoints discovered"
        )
        set_stage("crawl", "done", f"{len(endpoints)} endpoints discovered")
        scan_results['progress'] = 20

        log(f"Endpoints discovered ({len(endpoints)}):")
        for i, ep in enumerate(endpoints, 1):
            log(f"  {i:>2}. {ep['url']}")

        # Phase 2: Fuzz
        set_stage("fuzz", "active", "authenticating & injecting payloads…")
        scan_results['progress'] = 25
        timer = StageTimer("Fuzzing")
        fuzzer = Fuzzer(target_url, username=username, password=password)
        responses = fuzzer.fuzz(
            endpoints,
            on_progress=lambda detail: set_stage("fuzz", "active", detail)
        )
        counts["responses"] = len(responses)
        durations["fuzz"] = timer.done(f"{len(responses)} responses collected")
        set_stage("fuzz", "done", f"{len(responses)} responses collected")
        scan_results['progress'] = 50

        # Phase 3: Analyze
        set_stage("analyze", "active", "extracting behavioural features…")
        scan_results['progress'] = 55
        timer = StageTimer("Analysis")
        analyzer = Analyzer()
        features = analyzer.extract_features(responses)
        counts["features"] = len(features)
        durations["analyze"] = timer.done(
            f"{len(features)} feature vectors built"
        )
        set_stage("analyze", "done", f"{len(features)} feature vectors built")
        scan_results['progress'] = 70

        # Phase 4: Classify
        set_stage("classify", "active", "scoring responses…")
        scan_results['progress'] = 75
        timer = StageTimer("ML classification")
        classifier = Classifier()
        detections = classifier.classify(
            features, responses, on_model=set_model
        )
        counts["detections"] = len(detections)
        durations["classify"] = timer.done(
            f"{len(detections)} raw findings"
        )
        set_stage("classify", "done", f"{len(detections)} raw findings")
        scan_results['progress'] = 90

        # Phase 5: Report
        set_stage("report", "active", "deduplicating & scoring…")
        scan_results['progress'] = 95
        timer = StageTimer("Report generation")
        reporter = Reporter()
        report = reporter.generate(detections, target_url)
        durations["report"] = timer.done(f"{len(report)} unique findings")
        scan_results['vulnerabilities'] = report
        set_stage("report", "done", f"{len(report)} unique findings")
        scan_results['status'] = 'complete'
        scan_results['progress'] = 100
        _refresh_activity()

        _log_scan_summary(target_url, started_at, scan_started, durations,
                          counts, report)

    except Exception as e:
        scan_results['status'] = 'error'
        scan_results['error'] = str(e)
        # Mark whichever stage was running as failed so the UI reflects it.
        for stage in scan_results.get('stages', []):
            if stage['status'] == 'active':
                stage['status'] = 'error'
                stage['detail'] = str(e)
        scan_results['activity'] = f"Error: {e}"
        log(f"SCAN FAILED after "
            f"{format_duration(time.monotonic() - scan_started)}: {e}")

if __name__ == '__main__':
    log("Scanner server starting on http://localhost:5000")
    log("Live scan activity will be printed here (also ~/labs/scanner.log "
        "when launched with start-lab.sh)")
    app.run(debug=True, host='0.0.0.0', port=5000)
