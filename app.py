from flask import Flask, render_template, request, jsonify
import threading
import json
import os

app = Flask(__name__)

# Store scan results globally
scan_results = {
    "status": "idle",
    "target": "",
    "vulnerabilities": [],
    "progress": 0,
    "total_tests": 0
}

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

def run_scan(target_url, username=None, password=None):
    """Main scan orchestrator - calls all modules"""
    from crawler.crawler import Crawler
    from fuzzer.fuzzer import Fuzzer
    from analyzer.analyzer import Analyzer
    from ml_engine.classifier import Classifier
    from reporter.reporter import Reporter

    try:
        # Phase 1: Crawl
        print(f"[*] Starting crawl on {target_url}")

        crawler = Crawler(target_url, username=username, password=password)

        try:
            endpoints = crawler.crawl()
            print("=" * 60)
            print(f"Endpoints found: {len(endpoints)}")
            for i, ep in enumerate(endpoints, 1):
                print(f"{i}. {ep['url']}")
            print("=" * 60)
        finally:
            crawler.close()

        scan_results['progress'] = 20
        print(f"[*] Found {len(endpoints)} endpoints")

        # Phase 2: Fuzz
        print("[*] Starting fuzzing phase")
        fuzzer = Fuzzer(target_url, username=username, password=password)
        responses = fuzzer.fuzz(endpoints)
        scan_results['progress'] = 50
        print(f"[*] Collected {len(responses)} responses")

        # Phase 3: Analyze
        print("[*] Analyzing responses")
        analyzer = Analyzer()
        features = analyzer.extract_features(responses)
        scan_results['progress'] = 70
        print(f"[*] Extracted features from {len(features)} responses")

        # Phase 4: Classify
        print("[*] Running ML classification")
        classifier = Classifier()
        detections = classifier.classify(features, responses)
        scan_results['progress'] = 90
        print(f"[*] Detected {len(detections)} potential vulnerabilities")

        # Phase 5: Report
        print("[*] Generating report")
        reporter = Reporter()
        report = reporter.generate(detections, target_url)
        scan_results['vulnerabilities'] = report
        scan_results['status'] = 'complete'
        scan_results['progress'] = 100
        print("[*] Scan complete!")

    except Exception as e:
        scan_results['status'] = 'error'
        scan_results['error'] = str(e)
        print(f"[!] Error during scan: {e}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
