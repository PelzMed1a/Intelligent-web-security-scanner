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
        """Classify responses using ML plus behavioral and technical evidence."""
        if not self.is_trained:
            self._train()
        detections = []
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
            payload_type = feat.get('payload_type', 'baseline')
            # Never report the normal baseline request.
            if payload_type == 'baseline':
                continue
            rf_detected = bool(rf_pred == 1)
            iso_detected = bool(iso_pred == -1)
            # Probability of the vulnerability class.
            rf_confidence = float(rf_probabilities[i][1])
            # ---------------------------------------------------------
            # OBSERVABLE TECHNICAL EVIDENCE
            # ---------------------------------------------------------
            error_evidence = feat.get('error_count', 0) > 0
            sensitive_evidence = feat.get('sensitive_count', 0) > 0
            server_error = feat.get('status_code', 0) >= 500
            timeout_evidence = feat.get('timeout', 0) == 1
            baseline = feat.get('baseline', {}) or {}
            baseline_time = baseline.get(
                'response_time',
                feat.get('response_time', 0)
            )
            response_time = feat.get('response_time', 0)
            time_anomaly = (
                response_time >= 3.0
                and response_time > baseline_time + 2.0
            )
            baseline_length = baseline.get(
                'content_length',
                feat.get('content_length', 0)
            )
            content_length = feat.get('content_length', 0)
            # A reflected payload changes the response size by roughly its
            # own length. Only a change MUCH larger than the payload (for
            # example extra database rows being returned) is treated as a
            # real anomaly, so simple input reflection is no longer mistaken
            # for a boolean SQL injection.
            content_anomaly = (
                baseline_length > 0
                and abs(content_length - baseline_length)
                > (len(feat.get('payload', '')) + 150)
            )
            status_changed = feat.get('status_changed', 0) == 1
            # ---------------------------------------------------------
            # PAYLOAD REFLECTION
            # ---------------------------------------------------------
            response_text = feat.get('response_text', '').lower()
            payload = feat.get('payload', '').lower()
            payload_reflected = (
                bool(payload)
                and len(payload) >= 3
                and payload in response_text
            )
            # Unescaped reflection is a real XSS signal, but ONLY for XSS
            # payloads and ONLY when the full payload came back verbatim.
            # (The old feat['xss_reflected'] counted substrings such as
            # "alert(" that survive HTML-escaping, which flagged safe pages.)
            xss_reflection = (
                payload_type == 'xss'
                and len(payload) >= 3
                and payload in response_text
            )
            # ---------------------------------------------------------
            # STRONG, OBSERVABLE EVIDENCE
            #
            # Machine-learning votes (rf/iso) and a bare status change are
            # ADVISORY only and are deliberately NOT in this list. The ML
            # models are trained on synthetic data and flag almost every
            # real response as anomalous, so on their own they must not
            # confirm a finding.
            # ---------------------------------------------------------
            # CONFIRMED tier: evidence that is very hard to produce by
            # accident -- a genuine SQL/database error, real sensitive
            # data disclosure, or the payload coming back completely
            # unescaped. A bare server crash (500) is deliberately NOT in
            # this list: many things unrelated to the specific
            # vulnerability being tested can crash a route (a bad
            # type-coercion, an unhandled exception on a non-SQL/NoSQL
            # backend, etc.), so a 500 with no other corroborating
            # evidence does not by itself prove the vulnerability type
            # under test. This matters for targets like NodeGoat, which
            # has no SQL database at all -- a 500 there can never be a
            # genuine "SQL error", only a crash.
            confirmed_evidence = (
                error_evidence
                or sensitive_evidence
                or xss_reflection
            )
            # POTENTIAL tier: real, observable, but softer signals that
            # still deserve a human's attention -- a timing spike, a
            # large size change, a timeout, or a bare server crash with
            # no other corroborating evidence.
            potential_evidence = (
                timeout_evidence
                or time_anomaly
                or content_anomaly
                or server_error
            )
            strong_evidence = confirmed_evidence or potential_evidence
            technical_evidence = strong_evidence
            behavioral_evidence = (
                content_anomaly
                or time_anomaly
                or status_changed
            )
            ml_evidence = rf_detected or iso_detected
            # ---------------------------------------------------------
            # DECISION
            #
            # A payload is only reported when it produced STRONG,
            # observable evidence. Payloads that were tested but produced
            # no real signal are no longer added to the report (this is
            # what removes the flood of false positives).
            #
            # The verification_status further splits that evidence into
            # two honest tiers instead of one blanket label, so the
            # report (and UI) can show a real difference between a
            # near-certain finding and one that still needs a human to
            # check it.
            # ---------------------------------------------------------
            if not strong_evidence:
                continue
            verification_status = "Confirmed" if confirmed_evidence else "Potential"
            # ---------------------------------------------------------
            # EVIDENCE SCORE
            # ---------------------------------------------------------
            evidence_score = 0
            if error_evidence:
                evidence_score += 3
            if sensitive_evidence:
                evidence_score += 4
            if server_error:
                evidence_score += 2
            if timeout_evidence:
                evidence_score += 2
            if time_anomaly:
                evidence_score += 2
            if xss_reflection:
                evidence_score += 3
            if payload_reflected:
                evidence_score += 3
            if content_anomaly:
                evidence_score += 2
            if status_changed:
                evidence_score += 2
            if rf_detected:
                evidence_score += 1
            if iso_detected:
                evidence_score += 1
            # ---------------------------------------------------------
            # SEVERITY
            # ---------------------------------------------------------
            severity = self._calculate_severity(
                feat,
                rf_confidence
            )
            # ---------------------------------------------------------
            # DETECTION
            # ---------------------------------------------------------
            detection = {
                'url': feat.get('url', ''),
                'input_field': feat.get('input_field', ''),
                'payload': feat.get('payload', ''),
                'payload_type': payload_type,
                'vulnerability_type': self._get_vuln_type(feat),
                'severity': severity,
                'confidence': round(
                    rf_confidence * 100,
                    2
                ),
                'rf_detected': rf_detected,
                'iso_detected': iso_detected,
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
                'evidence': self._get_evidence(
                    feat,
                    xss_reflection=xss_reflection,
                    content_anomaly=content_anomaly
                ),
                'evidence_score': evidence_score,
                'technical_evidence': technical_evidence,
                'behavioral_evidence': behavioral_evidence,
                'verification_status': verification_status
            }
            detections.append(detection)
        confirmed = sum(
            1
            for d in detections
            if d.get('verification_status') == 'Confirmed'
        )
        potential = len(detections) - confirmed
        print(
            f"[*] Classification complete: "
            f"{len(detections)} findings with evidence detected"
        )
        print(
            f"[*] Confirmed findings (strong evidence): "
            f"{confirmed}"
        )
        print(
            f"[*] Potential findings requiring verification: "
            f"{potential}"
        )
        return detections
    def _get_vuln_type(self, feat):
        """Map payload type to vulnerability name"""
        mapping = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'path_traversal': 'Path Traversal',
            'cmd_injection': 'Command Injection'
        }
        return mapping.get(feat['payload_type'], 'Unknown')
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
    def _get_evidence(self, feat, xss_reflection=False, content_anomaly=False):
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
        if xss_reflection:
            evidence.append(
                "The submitted payload was found reflected verbatim and unescaped in the HTTP response body, meaning a browser rendering this response would execute it."
            )
        if feat['response_time'] > 3.0:
            evidence.append(
                f"Abnormal response time: {feat['response_time']:.2f}s (possible time-based injection)"
            )
        if feat['status_code'] == 500:
            evidence.append("Server returned HTTP 500 error (possible injection-triggered crash)")
        if content_anomaly:
            evidence.append(
                "Response size changed by an amount far larger than the payload itself compared to the baseline request."
            )
        if not evidence:
            evidence.append(
                "The Isolation Forest model identified a significant deviation from the baseline response behaviour after the payload was submitted."
            )
        return evidence
