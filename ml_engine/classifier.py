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
        """Classify each response as normal or vulnerable"""
        if not self.is_trained:
            self._train()

        detections = []

        if not feature_list:
            print("[!] No features to classify")
            return detections

        # Extract feature vectors
        X = np.array([f['features'] for f in feature_list])
        X_scaled = self.scaler.transform(X)

        # Random Forest predictions (0=normal, 1=vulnerable)
        rf_predictions = self.rf_model.predict(X_scaled)
        rf_probabilities = self.rf_model.predict_proba(X_scaled)
        # Isolation Forest predictions (-1=anomaly, 1=normal)
        iso_predictions = self.iso_model.predict(X_scaled)

        # Combine both models - flag if EITHER detects anomaly
        for i, (feat, rf_pred, iso_pred) in enumerate(
            zip(feature_list, rf_predictions, iso_predictions)
        ):
            rf_confidence = rf_probabilities[i][1] if rf_pred == 1 else rf_probabilities[i][0]
            is_vulnerable = rf_pred == 1 or iso_pred == -1

            if is_vulnerable and feat['payload_type'] != 'baseline':
                severity = self._calculate_severity(feat, rf_confidence)
                detection = {
                    'url': feat['url'],
                    'input_field': feat['input_field'],
                    'payload': feat['payload'],
                    'vulnerability_type': self._get_vuln_type(feat),
                    'severity': severity,
                    'confidence': round(rf_confidence * 100, 2),
                    'rf_detected': bool(rf_pred == 1),
                    'iso_detected': bool(iso_pred == -1),
                    'response_time': feat['response_time'],
                    'status_code': feat['status_code'],
                    'error_indicators': feat['error_count'],
                    'sensitive_data': feat['sensitive_count'],
                    'evidence': self._get_evidence(feat)
                }
                detections.append(detection)

        print(f"[*] Classification complete: {len(detections)} vulnerabilities detected")
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
        """Calculate CVSS-based severity rating"""
        score = confidence * 10

        if feat['sensitive_count'] > 0:
            score += 3
        if feat['error_count'] > 2:
            score += 2
        if feat['response_time'] > 3.0:
            score += 2
        if feat['status_code'] == 500:
            score += 1

        if score >= 9:
            return 'Critical'
        elif score >= 7:
            return 'High'
        elif score >= 4:
            return 'Medium'
        else:
            return 'Low'

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
