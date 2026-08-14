import re
import numpy as np
class Analyzer:
    def __init__(self):
        # Error keywords that indicate something went wrong server-side
        self.error_keywords = [
            'you have an error in your sql syntax',
            'warning: mysql',
            'mysql_fetch',
            'mysql_query',
            'mysqli_query',
            'mysqli_fetch',
            'pg_query',
            'postgresql',
            'sqlite error',
            'sqlite3.operationalerror',
            'ora-',
            'sqlstate[',
            'syntax error in sql',
            'unclosed quotation mark',
            'quoted string not properly terminated',
            'invalid sql statement',
            'database error',
            'pdoexception',
            'sql syntax error',
            'odbc sql server driver',
            'microsoft ole db provider for sql server'
        ]
        # Sensitive keywords that should never appear in responses
        self.sensitive_keywords = [
            'root:x', '/bin/bash', '/etc/passwd', 'uid=', 'gid=',
            'windows\\system32', 'boot.ini', 'win.ini',
            'administrator:', 'passwd:', 'shadow:'
        ]
        # XSS reflection indicators
        self.xss_keywords = [
             'alert(', 'onerror=', 'onload=',
            'javascript:', '<iframe', '<svg', 'onfocus='
        ]
    def extract_features(self, responses):
        """Extract 15 behavioral features from each response"""
        feature_list = []
        for resp in responses:
            if resp is None:
                continue
            features = self._extract_single(resp)
            if features:
                feature_list.append(features)
        print(f"[*] Extracted features from {len(feature_list)} responses")
        return feature_list
    def _extract_single(self, resp):
        """Extract all 15 features from a single response"""
        try:
            baseline = resp.get('baseline', {})
            response_text = resp.get('response_text', '').lower()
            headers = resp.get('headers', {})
            # ── Feature 1: Response Time ──────────────────────────────
            response_time = resp.get('response_time', 0)
            # ── Feature 2: Response Time Deviation from Baseline ─────
            baseline_time = baseline.get('response_time', response_time) if baseline else response_time
            time_deviation = abs(response_time - baseline_time)
            # ── Feature 3: HTTP Status Code ───────────────────────────
            status_code = resp.get('status_code', 200)
            # ── Feature 4: Status Code Change from Baseline ───────────
            baseline_status = baseline.get('status_code', 200) if baseline else 200
            status_changed = 1 if status_code != baseline_status else 0
            # ── Feature 5: Content Length ─────────────────────────────
            content_length = resp.get('content_length', 0)
            # ── Feature 6: Content Length Deviation from Baseline ─────
            baseline_length = baseline.get('content_length', content_length) if baseline else content_length
            length_deviation = abs(content_length - baseline_length)
            # ── Feature 7: Content Length Ratio ──────────────────────
            if baseline_length > 0:
                length_ratio = content_length / baseline_length
            else:
                length_ratio = 1.0
            # ── Feature 8: Error Keyword Presence ────────────────────
            error_count = sum(1 for kw in self.error_keywords
                            if kw in response_text)
            # ── Feature 9: Sensitive Data Exposure ───────────────────
            # Exclude any keyword that is already part of the PAYLOAD
            # itself (e.g. a path-traversal payload literally contains
            # "/etc/passwd"). Otherwise a page that simply echoes back
            # what you typed -- without disclosing anything -- looks
            # identical to a real disclosure.
            payload_lower = resp.get('payload', '').lower()
            sensitive_count = sum(1 for kw in self.sensitive_keywords
                                if kw in response_text and kw not in payload_lower)
            # ── Feature 10: XSS Reflection Detection ─────────────────
            payload = resp.get('payload', '').lower()
            xss_reflected = 0
            if any(xss in payload for xss in ['<script>', 'alert(', 'onerror']):
                xss_reflected = sum(1 for kw in self.xss_keywords
                                  if kw in response_text)
            # ── Feature 11: Redirect Count ────────────────────────────
            redirect_count = 1 if status_code in [301, 302, 303, 307, 308] else 0
            # ── Feature 12: Server Error Indicator ───────────────────
            server_error = 1 if status_code >= 500 else 0
            # ── Feature 13: Content Type Change ──────────────────────
            content_type = headers.get('Content-Type', '').lower()
            baseline_ct = baseline.get('headers', {}).get(
                'Content-Type', content_type).lower() if baseline else content_type
            content_type_changed = 1 if content_type != baseline_ct else 0
            # ── Feature 14: Payload Type Encoding ────────────────────
            payload_type = resp.get('payload_type', 'baseline')
            payload_map = {
                'baseline': 0, 'sqli': 1,
                'xss': 2, 'path_traversal': 3, 'cmd_injection': 4
            }
            payload_encoded = payload_map.get(payload_type, 0)
            # ── Feature 15: Timeout Indicator ────────────────────────
            timeout = 1 if resp.get('timeout', False) else 0
            # ── Assemble feature vector ───────────────────────────────
            feature_vector = [
                response_time,       # F1
                time_deviation,      # F2
                status_code,         # F3
                status_changed,      # F4
                content_length,      # F5
                length_deviation,    # F6
                length_ratio,        # F7
                error_count,         # F8
                sensitive_count,     # F9
                xss_reflected,       # F10
                redirect_count,      # F11
                server_error,        # F12
                content_type_changed,# F13
                payload_encoded,     # F14
                timeout              # F15
            ]
            print(
                f"[DEBUG] {payload_type} | "
                f"status={status_code} "
                f"baseline_status={baseline_status} "
                f"length={content_length} "
                f"baseline_length={baseline_length} "
                f"length_diff={length_deviation} "
                f"error={error_count} "
                f"sensitive={sensitive_count} "
                f"xss={xss_reflected} "
                f"time={response_time:.2f}s"
            )
            return {
                'features': feature_vector,
                'url': resp.get('url', ''),
                'payload': resp.get('payload', ''),
                'payload_type': payload_type,
                'input_field': resp.get('input_field', ''),
                'status_code': status_code,
                'response_time': response_time,
                'error_count': error_count,
                'sensitive_count': sensitive_count,
                'xss_reflected': xss_reflected,
                'content_length': content_length,
                'content_type': content_type,
                'timeout': timeout,
                'baseline': {
                    'response_time': baseline_time,
                    'status_code': baseline_status,
                    'content_length': baseline_length,
                    'headers': baseline.get('headers', {})
                },
                'time_deviation': time_deviation,
                'length_deviation': length_deviation,
                'length_ratio': length_ratio,
                'status_changed': status_changed,
                'content_type_changed': content_type_changed,
                'response_text': resp.get(
                    'response_text', ''
                )
            }
        except Exception as e:
            print(f"[!] Feature extraction error: {e}")
            return None
