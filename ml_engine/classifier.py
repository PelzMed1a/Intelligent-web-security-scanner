import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

class Classifier:
    def __init__(self):
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10,
            min_samples_split=2
        )
        self.iso_model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def _generate_training_data(self):
        """
        Generate synthetic training data based on known
        vulnerability behavioral patterns, calibrated for
        local testing environments (low network latency).
        """
        np.random.seed(42)
        n_normal = 300
        n_vuln = 150

        # ── Normal responses ─────────────────────────────────────────
        normal_data = np.column_stack([
            np.random.uniform(0.001, 0.05, n_normal),  # F1: response time (fast, local)
            np.random.uniform(0.0, 0.01, n_normal),     # F2: time deviation
            np.full(n_normal, 200),                     # F3: status code
            np.zeros(n_normal),                         # F4: status changed
            np.random.randint(1000, 5000, n_normal),    # F5: content length
            np.random.uniform(0, 50, n_normal),         # F6: length deviation
            np.random.uniform(0.95, 1.05, n_normal),   # F7: length ratio
            np.zeros(n_normal),                         # F8: error keywords
            np.zeros(n_normal),                         # F9: sensitive data
            np.zeros(n_normal),                         # F10: xss reflected
            np.zeros(n_normal),                         # F11: redirect
            np.zeros(n_normal),                         # F12: server error
            np.zeros(n_normal),                         # F13: content type change
            np.random.randint(0, 5, n_normal),          # F14: payload type
            np.zeros(n_normal)                          # F15: timeout
        ])
        normal_labels = np.zeros(n_normal)

        # ── SQL Injection responses (local timing) ─────────────────────
        sqli_data = np.column_stack([
            np.random.uniform(0.003, 0.08, n_vuln//3), # F1: still fast locally, but distinguishable
            np.random.uniform(0.002, 0.05, n_vuln//3), # F2: slightly higher deviation
            np.random.choice([200, 500], n_vuln//3),    # F3: status
            np.random.randint(0, 2, n_vuln//3),         # F4: status change
            np.random.randint(500, 8000, n_vuln//3),    # F5: content length
            np.random.uniform(200, 3000, n_vuln//3),    # F6: high deviation
            np.random.uniform(0.5, 2.5, n_vuln//3),    # F7: high ratio
            np.random.randint(1, 5, n_vuln//3),         # F8: error keywords
            np.zeros(n_vuln//3),                        # F9: sensitive data
            np.zeros(n_vuln//3),                        # F10: xss
            np.zeros(n_vuln//3),                        # F11: redirect
            np.random.randint(0, 2, n_vuln//3),         # F12: server error
            np.zeros(n_vuln//3),                        # F13: content type
            np.ones(n_vuln//3),                         # F14: sqli payload
            np.zeros(n_vuln//3)                         # F15: timeout
        ])
        sqli_labels = np.ones(n_vuln//3)

        # ── XSS responses ─────────────────────────────────────────────
        xss_data = np.column_stack([
            np.random.uniform(0.001, 0.04, n_vuln//3), # F1: normal local time
            np.random.uniform(0.0, 0.01, n_vuln//3),   # F2: low deviation
            np.full(n_vuln//3, 200),                    # F3: 200 OK
            np.zeros(n_vuln//3),                        # F4: no status change
            np.random.randint(2000, 8000, n_vuln//3),   # F5: larger content
            np.random.uniform(500, 2000, n_vuln//3),    # F6: length change
            np.random.uniform(1.2, 2.5, n_vuln//3),    # F7: higher ratio
            np.zeros(n_vuln//3),                        # F8: no db errors
            np.zeros(n_vuln//3),                        # F9: no sensitive
            np.random.randint(1, 4, n_vuln//3),         # F10: xss reflected
            np.zeros(n_vuln//3),                        # F11: no redirect
            np.zeros(n_vuln//3),                        # F12: no server error
            np.zeros(n_vuln//3),                        # F13: content type
            np.full(n_vuln//3, 2),                      # F14: xss payload
            np.zeros(n_vuln//3)                         # F15: no timeout
        ])
        xss_labels = np.ones(n_vuln//3)

        # ── Path Traversal responses ──────────────────────────────────
        path_data = np.column_stack([
            np.random.uniform(0.001, 0.05, n_vuln//3), # F1: response time
            np.random.uniform(0.0, 0.02, n_vuln//3),   # F2: deviation
            np.random.choice([200, 403], n_vuln//3),    # F3: status
            np.random.randint(0, 2, n_vuln//3),         # F4: status change
            np.random.randint(500, 10000, n_vuln//3),   # F5: content length
            np.random.uniform(100, 5000, n_vuln//3),    # F6: deviation
            np.random.uniform(0.8, 3.0, n_vuln//3),    # F7: ratio
            np.zeros(n_vuln//3),                        # F8: no db errors
            np.random.randint(0, 3, n_vuln//3),         # F9: sensitive data
            np.zeros(n_vuln//3),                        # F10: no xss
            np.zeros(n_vuln//3),                        # F11: no redirect
            np.zeros(n_vuln//3),                        # F12: no server error
            np.random.randint(0, 2, n_vuln//3),         # F13: content change
            np.full(n_vuln//3, 3),                      # F14: path payload
            np.zeros(n_vuln//3)                         # F15: no timeout
        ])
        path_labels = np.ones(n_vuln//3)

        # ── Combine all data ──────────────────────────────────────────
        X = np.vstack([normal_data, sqli_data, xss_data, path_data])
        y = np.concatenate([
            normal_labels, sqli_labels, xss_labels, path_labels
        ])

        return X, y

    def _train(self):
        """Train both ML models on generated training data"""
        print("[*] Training ML models...")
        X, y = self._generate_training_data()

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Split for evaluation
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )

        # Train Random Forest
        self.rf_model.fit(X_train, y_train)

        # Train Isolation Forest on normal data only
        normal_indices = y_train == 0
        self.iso_model.fit(X_train[normal_indices])

        # Evaluate
        y_pred = self.rf_model.predict(X_test)
        print("\n[*] Random Forest Performance:")
        print(classification_report(y_test, y_pred,
            target_names=['Normal', 'Vulnerability']))

        self.is_trained = True
        print("[*] Models trained successfully")

    def classify(self, feature_list, responses):
        """Classify responses using ML and behavioral evidence."""

        if not self.is_trained:
            self._train()

        detections = []
        print(f"[DEBUG] FEATURE COUNT: {len(feature_list)}")

        if not feature_list:
            print("[!] No features to classify")
            return detections

        X = np.array([f['features'] for f in feature_list])
        X_scaled = self.scaler.transform(X)

        rf_predictions = self.rf_model.predict(X_scaled)
        rf_probabilities = self.rf_model.predict_proba(X_scaled)
        iso_predictions = self.iso_model.predict(X_scaled)

        for i, (feat, rf_pred, iso_pred) in enumerate(
            zip(feature_list, rf_predictions, iso_predictions)
        ):
            print(
                f"[CHECK] {i} | "
                f"type={feat.get('payload_type')} | "
                f"payload={feat.get('payload')!r} | "
                f"status={feat.get('status_code')} | "
                f"time={feat.get('response_time')} | "
                f"errors={feat.get('error_count')} | "
                f"sensitive={feat.get('sensitive_count')} | "
                f"features={feat.get('features')}"
            )

            payload_type = feat.get('payload_type', 'baseline')

            if payload_type == 'baseline':
                continue

            response_text = feat.get('response_text', '').lower()
            payload = feat.get('payload', '').lower()

            rf_detected = rf_pred == 1
            iso_detected = iso_pred == -1

            if rf_pred == 1:
                rf_confidence = float(rf_probabilities[i][1])
            else:
                rf_confidence = float(rf_probabilities[i][0])

            # -----------------------------
            # BEHAVIORAL EVIDENCE
            # -----------------------------

            error_evidence = feat.get('error_count', 0) > 0
            sensitive_evidence = feat.get('sensitive_count', 0) > 0

            xss_evidence = (
                len(feat.get('features', [])) > 9
                and feat['features'][9] > 0
            )

            server_error = feat.get('status_code', 0) >= 500
            timing_evidence = feat.get('response_time', 0) > 3.0

            # -----------------------------
            # BASELINE COMPARISON
            # -----------------------------

            baseline = {}

            if responses and i < len(responses):
                baseline = responses[i].get('baseline', {}) or {}

            baseline_length_changed = False

            if baseline:
                baseline_length = baseline.get(
                    'content_length',
                    feat['features'][4]
                )

                current_length = feat['features'][4]

                if baseline_length > 0:
                    ratio = current_length / baseline_length
                    length_difference = abs(
                        current_length - baseline_length
                    )

                    # Detect meaningful response-size changes.
                    if (
                        ratio > 1.03
                        or ratio < 0.97
                        or length_difference >= 100
                    ):
                        baseline_length_changed = True

            # SQLi-specific behavioural evidence
            sqli_behavior = False

            if payload_type == 'sqli':
                if baseline_length_changed:
                    sqli_behavior = True

            # -----------------------------
            # XSS REFLECTION
            # -----------------------------

            xss_direct = False

            if payload_type == 'xss':
                xss_markers = [
                    '<script>',
                    '<img',
                    'onerror=',
                    'onload=',
                    '<svg',
                    'onfocus=',
                    'javascript:'
                ]

                for marker in xss_markers:
                    if (
                        marker in payload
                        and marker in response_text
                    ):
                        xss_direct = True
                        break

            # -----------------------------
            # SQL INJECTION
            # -----------------------------

            sqli_evidence = False

            if payload_type == 'sqli':
                sql_markers = [
                    'sql syntax',
                    'mysql',
                    'mysqli',
                    'pdoexception',
                    'sqlstate',
                    'postgresql',
                    'sqlite',
                    'ora-',
                    'unclosed quotation',
                    'quoted string',
                    'database error'
                ]

                if any(
                    marker in response_text
                    for marker in sql_markers
                ):
                    sqli_evidence = True

                if error_evidence:
                    sqli_evidence = True

                if server_error:
                    sqli_evidence = True

                if timing_evidence:
                    sqli_evidence = True

            # -----------------------------
            # PATH TRAVERSAL
            # -----------------------------

            path_evidence = False

            if payload_type == 'path_traversal':

                path_markers = [
                    'root:x:',
                    '/bin/bash',
                    '/etc/passwd',
                    'uid=',
                    'gid=',
                    'daemon:x:',
                    'www-data:x:'
                ]

                if any(marker in response_text for marker in path_markers):
                    path_evidence = True

            # -----------------------------
            # COMMAND INJECTION
            # -----------------------------

            command_evidence = False

            if payload_type == 'cmd_injection':
                command_markers = [
                    'uid=',
                    'gid=',
                    'root:',
                    'www-data',
                    'total ',
                    'directory of',
                    '/bin/',
                    'windows\\system32'
                ]

                if any(
                    marker in response_text
                    for marker in command_markers
                ):
                    command_evidence = True

                if sensitive_evidence:
                    command_evidence = True

                if server_error:
                    command_evidence = True

                if timing_evidence:
                    command_evidence = True

            # -----------------------------
            # ML DETECTION
            # -----------------------------

           

            ml_detected = rf_detected or iso_detected


            # -----------------------------
            # MAJOR BEHAVIOR CHANGE
            # -----------------------------

            major_behavior_change = (
                server_error
                or timing_evidence
                or sensitive_evidence
                or xss_evidence
                or baseline_length_changed
                or error_evidence
            )



            # -----------------------------
            # DIRECT EVIDENCE
            # -----------------------------

            direct_evidence = (
                sqli_evidence
                or xss_direct
                or path_evidence
                or command_evidence
            )

 

            # -----------------------------
            # DETECTION SCORE
            # -----------------------------

            evidence_score = 0

            if rf_detected:
                evidence_score += 1

            if iso_detected:
                evidence_score += 1

            if error_evidence:
                evidence_score += 3

            if sensitive_evidence:
                evidence_score += 4

            if xss_direct:
                evidence_score += 4

            if xss_evidence:
                evidence_score += 2

            if server_error:
                evidence_score += 2

            if timing_evidence:
                evidence_score += 2

            if baseline_length_changed:
                evidence_score += 1

            if sqli_evidence:
                evidence_score += 4

            if path_evidence:
                evidence_score += 4

            if command_evidence:
                evidence_score += 4

            # -----------------------------
            # CONFIRMATION
            # -----------------------------

            confirmed = False

            # Confirm when direct vulnerability evidence exists
            if direct_evidence:
                confirmed = True

            # For SQL injection, a meaningful response-size change
            # from the baseline is evidence on DVWA low security.
            if payload_type == 'sqli' and baseline_length_changed:
                confirmed = True

            # ML anomaly plus behavioral change
            if ml_detected and major_behavior_change:
                confirmed = True

            # -----------------------------
            # DEBUG
            # -----------------------------

            print(
                f"[DEBUG] {payload_type} | "
                f"RF={rf_detected} | "
                f"ISO={iso_detected} | "
                f"error={error_evidence} | "
                f"sensitive={sensitive_evidence} | "
                f"xss={xss_evidence} | "
                f"500={server_error} | "
                f"timing={timing_evidence} | "
                f"length_change={baseline_length_changed} | "
                f"score={evidence_score} | "
                f"confirmed={confirmed}"
            )

            if not confirmed:
                continue

            # -----------------------------
            # VULNERABILITY TYPE
            # -----------------------------

            vuln_type = self._get_vuln_type(feat)

            # -----------------------------
            # SEVERITY
            # -----------------------------

            severity = self._calculate_severity(
                feat,
                rf_confidence
            )

            # -----------------------------
            # EVIDENCE
            # -----------------------------

            evidence = self._get_evidence(feat)

            if xss_direct:
                evidence.append(
                    "XSS payload was reflected in the HTTP response."
                )

            if sqli_evidence:
                evidence.append(
                    "SQL injection response behaviour detected."
                )

            if path_evidence:
                evidence.append(
                    "Path traversal indicators detected."
                )

            if command_evidence:
                evidence.append(
                    "Command injection indicators detected."
                )

            if sensitive_evidence:
                evidence.append(
                    "Sensitive system information was detected."
                )

            if server_error:
                evidence.append(
                    "Server returned an HTTP 5xx response."
                )

            if timing_evidence:
                evidence.append(
                    "Response time exceeded the configured threshold."
                )

            if baseline_length_changed:
                evidence.append(
                    "Response length changed significantly from baseline."
                )

            if iso_detected:
                evidence.append(
                    "Isolation Forest identified anomalous response behaviour."
                )

            if rf_detected:
                evidence.append(
                    "Random Forest classified the response as suspicious."
                )

            evidence = list(dict.fromkeys(evidence))

            # -----------------------------
            # DETECTION OBJECT
            # -----------------------------

            detection = {
                'url': feat.get('url', ''),
                'input_field': feat.get('input_field', ''),
                'payload': feat.get('payload', ''),
                'vulnerability_type': vuln_type,
                'severity': severity,
                'confidence': round(
                    rf_confidence * 100,
                    2
                ),
                'rf_detected': bool(rf_detected),
                'iso_detected': bool(iso_detected),
                'response_time': feat.get(
                    'response_time',
                    0
                ),
                'status_code': feat.get(
                    'status_code',
                    0
                ),
                'error_indicators': feat.get(
                    'error_count',
                    0
                ),
                'sensitive_data': feat.get(
                    'sensitive_count',
                    0
                ),
                'evidence': evidence
            }

            detections.append(detection)

        print(
            f"[*] Classification complete: "
            f"{len(detections)} vulnerabilities detected"
        )

        return detections

    def _calculate_severity(self, feat, confidence):
        """Calculate severity based on observed evidence rather than ML confidence."""

        # Highest confidence evidence
        if feat['sensitive_count'] > 0:
            return "Critical"

        # Strong evidence
        if feat['error_count'] > 0:
            return "High"

        # Possible time-based attack
        if feat['response_time'] > 3.0:
            return "High"

        # Server crash caused by payload
        if feat['status_code'] == 500:
            return "High"

        # Behavioural anomaly only
        return "Medium"

    def _get_evidence(self, feat):
        """Generate human-readable evidence"""
        evidence = []

        if feat['error_count'] > 0:
            evidence.append(
                f"Database error keywords detected in response ({feat['error_count']} occurrences)"
            )
        if feat['sensitive_count'] > 0:
            evidence.append(
                f"Sensitive system data found in response ({feat['sensitive_count']} indicators)"
            )
        if feat['response_time'] > 3.0:
            evidence.append(
                f"Abnormal response time: {feat['response_time']:.2f}s (possible time-based injection)"
            )
        if feat['status_code'] == 500:
            evidence.append("Server returned HTTP 500 error (possible injection-triggered crash)")
        if not evidence:
            evidence.append(
                "The Isolation Forest model identified a significant deviation from the baseline response behaviour after the payload was submitted."
            )

        return evidence

    def _get_vuln_type(self, feat):
        """Map payload type to vulnerability name."""
        mapping = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'path_traversal': 'Path Traversal',
            'cmd_injection': 'Command Injection'
        }

        return mapping.get(
            feat.get('payload_type', 'baseline'),
            'Unknown'
        )
