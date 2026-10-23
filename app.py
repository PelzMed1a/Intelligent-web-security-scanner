from flask import (Flask, render_template, request, jsonify, send_file,
                   abort)
from urllib.parse import quote
import html
import io
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
    "started_at": "",
    "finished_at": "",
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
    scan_results['started_at'] = time.strftime("%Y-%m-%d %H:%M:%S")
    scan_results['finished_at'] = ""
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

# Every finished scan is written here as JSON, so a report can be opened
# again later without re-running the scan. Older scans are kept; nothing
# is overwritten.
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'reports')


def _report_payload(target_url, report, scanned_at, finished_at=None):
    """Normalise one scan into the shape saved on disk and exported to PDF."""
    return {
        'target': target_url,
        'scanned_at': scanned_at,
        'finished_at': finished_at or time.strftime("%Y-%m-%d %H:%M:%S"),
        'finding_count': len(report),
        'vulnerabilities': report,
    }


def _save_report(target_url, report, started_at):
    """Write one scan's finished report to disk.

    The scanner's results used to live only in memory, so the moment the
    next scan started, the previous report was gone. Each scan now leaves
    a dated JSON file behind instead.

    Returns (path, payload); path is None if writing failed, but the
    payload is always returned so a PDF can still be produced on demand.
    """
    payload = _report_payload(target_url, report, started_at)
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        stamp = started_at.replace(' ', '_').replace(':', '-')
        host = re.sub(r'[^A-Za-z0-9.-]+', '_', target_url.split('//')[-1])
        path = os.path.join(REPORTS_DIR, f"scan_{stamp}_{host}.json")
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, indent=2)
        return path, payload
    except Exception as exc:
        # A report that cannot be saved must never fail the scan itself.
        log(f"  Report not saved: {exc}")
        return None, payload


def _save_report_pdf(payload, json_path):
    """Write the PDF next to the JSON. Best effort: never fails the scan."""
    try:
        from reporter.pdf_report import write_pdf
        pdf_path = json_path[:-5] + '.pdf'
        write_pdf(payload, pdf_path)
        return pdf_path
    except Exception as exc:
        log(f"  PDF not saved   : {exc}")
        return None


def _pdf_filename(payload):
    """Build a readable download name from the report metadata."""
    stamp = (str(payload.get('scanned_at') or '')
             .replace(' ', '_').replace(':', '-'))
    if not stamp:
        stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    target = str(payload.get('target') or 'scan')
    host = re.sub(r'[^A-Za-z0-9.-]+', '_', target.split('//')[-1])
    return f"scan_{stamp}_{host}.pdf"


def _pdf_response(payload, filename):
    """Turn a report payload into a downloadable PDF response."""
    try:
        from reporter.pdf_report import render_pdf_bytes
        pdf = render_pdf_bytes(payload)
    except Exception as exc:
        log(f"  PDF export failed: {exc}")
        return jsonify({"error": f"PDF export failed: {exc}"}), 500
    return send_file(io.BytesIO(pdf), mimetype='application/pdf',
                     as_attachment=True, download_name=filename)


@app.route('/reports')
def saved_reports():
    """List every report saved on disk, each with a PDF download link."""
    try:
        names = sorted(
            (n for n in os.listdir(REPORTS_DIR) if n.endswith('.json')),
            reverse=True,
        )
    except FileNotFoundError:
        names = []

    items = []
    for name in names:
        base = name[:-5]
        summary = 'Unreadable report file'
        try:
            with open(os.path.join(REPORTS_DIR, name),
                      encoding='utf-8') as fh:
                data = json.load(fh)
            summary = (f"{data.get('target') or 'Unknown target'} - "
                       f"{data.get('finding_count', 0)} findings - "
                       f"{data.get('scanned_at') or 'time not recorded'}")
        except Exception:
            pass
        items.append(
            f'<li><a href="/reports/{quote(base)}.pdf">{html.escape(base)}</a>'
            f'<span class="meta">{html.escape(summary)}</span></li>'
        )

    if items:
        body = f'<ul>{"".join(items)}</ul>'
    else:
        body = '<p class="meta">No reports have been saved yet. Run a scan.</p>'

    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Saved scan reports</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0D1B2A;
         color: #e2e8f0; margin: 0; padding: 40px; }}
  h1 {{ font-size: 20px; color: #14b8a6; margin-bottom: 4px; }}
  p.lead {{ color: #94a3b8; margin-bottom: 24px; font-size: 13px; }}
  ul {{ list-style: none; padding: 0; max-width: 860px; }}
  li {{ background: #16283d; border: 1px solid #22334a;
        border-radius: 8px; padding: 14px 18px; margin-bottom: 10px; }}
  a {{ color: #5eead4; text-decoration: none; font-weight: 600;
       font-size: 14px; }}
  a:hover {{ text-decoration: underline; }}
  .meta {{ display: block; color: #94a3b8; font-size: 12px;
           margin-top: 4px; }}
  .back {{ display: inline-block; margin-top: 20px; font-size: 13px; }}
</style></head>
<body>
  <h1>Saved scan reports</h1>
  <p class="lead">Every finished scan is kept here. Download any report as
     a PDF, or open the scanner to run a new scan.</p>
  {body}
  <a class="back" href="/">&larr; Back to the scanner</a>
</body></html>"""
    return page


@app.route('/reports/<path:filename>')
def download_saved_report(filename):
    """Download one previously saved report as a PDF."""
    safe = os.path.basename(filename)
    if not safe.endswith('.pdf'):
        abort(404)
    json_path = os.path.join(REPORTS_DIR, safe[:-4] + '.json')
    if not os.path.isfile(json_path):
        abort(404)
    try:
        with open(json_path, encoding='utf-8') as fh:
            payload = json.load(fh)
    except Exception as exc:
        log(f"  Report unreadable: {exc}")
        abort(500)
    return _pdf_response(payload, safe)


@app.route('/report/latest.pdf')
def download_latest_report():
    """Download the most recent completed scan as a PDF."""
    if scan_results.get('status') != 'complete':
        return jsonify({
            "error": "No completed scan to export yet."
        }), 400
    payload = _report_payload(
        scan_results.get('target', ''),
        scan_results.get('vulnerabilities') or [],
        scan_results.get('started_at') or '',
        scan_results.get('finished_at') or None,
    )
    return _pdf_response(payload, _pdf_filename(payload))


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
    scan_results['started_at'] = started_at
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
        scan_results['finished_at'] = time.strftime("%Y-%m-%d %H:%M:%S")
        _refresh_activity()

        saved_report, payload = _save_report(target_url, report, started_at)
        if saved_report:
            log(f"  Saved report    : {saved_report}")
            saved_pdf = _save_report_pdf(payload, saved_report)
            if saved_pdf:
                log(f"  Saved PDF       : {saved_pdf}")

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
