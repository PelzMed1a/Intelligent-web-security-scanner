from datetime import datetime
class Reporter:
    def __init__(self):
        self.cvss_scores = {
            'Critical': 9.5,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5
        }
    def generate(self, detections, target_url):
        """Generate structured vulnerability report"""
        print("[*] Generating vulnerability report...")

        # Deduplicate by (url, field, vulnerability_type), but keep the
        # STRONGEST finding for each group, not just the first payload
        # that happened to be tried. Payloads are tested in a fixed
        # order, so a weak boolean SQLi payload (' OR '1'='1) often runs
        # before the payload that actually triggers a real database
        # error or leaks a file -- without this, the report would show
        # the weak "Potential" result and silently discard the much
        # stronger "Confirmed" one found moments later on the same field.
        best_by_key = {}
        for detection in detections:
            dedup_key = (
                detection['url'],
                detection['input_field'],
                detection['vulnerability_type']
            )
            existing = best_by_key.get(dedup_key)
            if existing is None or self._is_stronger(detection, existing):
                best_by_key[dedup_key] = detection

        report = []
        for i, detection in enumerate(best_by_key.values()):
            report_entry = {
                'id': f"VULN-{i+1:03d}",
                'target_url': target_url,
                'vulnerable_url': detection['url'],
                'input_field': detection['input_field'],
                'vulnerability_type': detection['vulnerability_type'],
                'severity': detection['severity'],
                'cvss_score': self.cvss_scores.get(
                    detection['severity'], 0.0
                ),
                'confidence': detection['confidence'],
                'rf_detected': detection['rf_detected'],
                'iso_detected': detection['iso_detected'],
                'payload_used': detection['payload'],
                'response_time': round(detection['response_time'], 3),
                'status_code': detection['status_code'],
                'evidence': self._build_evidence_summary(detection),
                'description': self._get_description(detection),
                'impact': self._get_impact(
                    detection['vulnerability_type']
                ),
                'recommendation': self._get_recommendation(
                    detection['vulnerability_type']
                ),
                'reproduction_steps': self._get_reproduction(detection),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'detection_method': self._get_detection_method(detection),
                'verification_status': self._get_verification_status(detection)
            }
            report.append(report_entry)
        # Sort by severity
        severity_order = {
            'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3
        }
        report.sort(key=lambda x: severity_order.get(x['severity'], 4))
        print(f"[*] Report generated: {len(report)} unique vulnerabilities")
        return report
    def _is_stronger(self, a, b):
        """True if detection `a` is stronger evidence than `b` for the
        same (url, field, vulnerability_type) group. Confirmed always
        outranks Potential; within the same tier, the higher evidence
        score (computed by the classifier) wins; ties fall back to
        whichever had the higher ML confidence."""
        tier = {'Confirmed': 1, 'Potential': 0}
        a_tier = tier.get(a.get('verification_status'), 0)
        b_tier = tier.get(b.get('verification_status'), 0)
        if a_tier != b_tier:
            return a_tier > b_tier
        a_score = a.get('evidence_score', 0)
        b_score = b.get('evidence_score', 0)
        if a_score != b_score:
            return a_score > b_score
        return a.get('confidence', 0) > b.get('confidence', 0)
    def _get_description(self, detection):
        """Return a description that reflects what was ACTUALLY observed
        for THIS finding, not a generic statement for the vulnerability
        type. A Confirmed finding names the specific hard evidence found;
        a Potential finding keeps the original, honestly-worded caveat."""
        vuln_type = detection.get('vulnerability_type', '')
        status = detection.get('verification_status', 'Potential')
        error_count = detection.get('error_indicators', 0)
        sensitive_count = detection.get('sensitive_data', 0)
        status_code = detection.get('status_code', 0)

        if status != 'Confirmed':
            potential_descriptions = {
                "SQL Injection":
                    "The submitted SQL payload caused the application to respond differently from its normal behaviour. No direct database errors or sensitive information were observed during automated testing. This finding should be treated as a potential SQL Injection vulnerability and manually verified.",
                "Cross-Site Scripting (XSS)":
                    "The submitted XSS payload produced an abnormal application response. Although successful script execution was not confirmed, the behaviour suggests a potential Cross-Site Scripting vulnerability requiring manual verification.",
                "Path Traversal":
                    "A path traversal payload caused an unusual application response. No sensitive files were disclosed during automated testing, but the endpoint should be manually verified for possible directory traversal weaknesses.",
                "Command Injection":
                    "A command injection payload resulted in abnormal application behaviour. Automated testing did not confirm successful command execution; therefore, manual verification is recommended."
            }
            return potential_descriptions.get(
                vuln_type,
                "Potential security weakness detected. Manual verification is recommended."
            )

        # CONFIRMED -- name the specific hard evidence that was found,
        # instead of a generic line that could contradict the Evidence
        # section sitting right next to it.
        if vuln_type == "SQL Injection":
            if error_count > 0:
                return ("The submitted SQL payload caused the application to return a genuine "
                    "database error, indicating the input was interpreted as part of the SQL "
                    "query rather than as safe data. This is direct technical evidence of a "
                    "SQL Injection vulnerability.")
            if sensitive_count > 0:
                return ("The submitted SQL payload caused the application to disclose sensitive "
                    "system or database information in its response, directly confirming a "
                    "SQL Injection vulnerability.")
            if status_code >= 500:
                return ("The submitted SQL payload caused the application to crash with a "
                    "server error, indicating the query was broken by unsanitised input. This "
                    "directly confirms a SQL Injection vulnerability.")
            return ("The submitted SQL payload produced strong, directly observed evidence of "
                "SQL Injection during automated testing.")

        if vuln_type == "Cross-Site Scripting (XSS)":
            return ("The submitted XSS payload was reflected back by the application completely "
                "unescaped, meaning a browser rendering this response would execute the "
                "injected script. This directly confirms a Cross-Site Scripting vulnerability.")

        if vuln_type == "Command Injection":
            if sensitive_count > 0:
                return ("The submitted command injection payload caused the server to execute "
                    "an operating-system command and return its real output (including "
                    "sensitive system data) in the HTTP response. This directly confirms "
                    "remote command execution.")
            if status_code >= 500:
                return ("The submitted command injection payload caused the server to crash, "
                    "indicating the payload reached the underlying shell. This directly "
                    "confirms a Command Injection vulnerability.")
            return ("The submitted command injection payload produced strong, directly "
                "observed evidence of command execution during automated testing.")

        if vuln_type == "Path Traversal":
            return ("The submitted path traversal payload caused the application to disclose "
                "the contents of a sensitive system file, directly confirming a Path Traversal "
                "vulnerability.")

        return "This finding was confirmed with direct technical evidence during automated testing."
    def _get_impact(self, vuln_type):
        """Return impact statement for each vulnerability type"""
        impacts = {
            'SQL Injection': [
                'Unauthorised access to sensitive database records',
                'Authentication bypass allowing admin access',
                'Complete database extraction or destruction',
                'Potential server compromise via stacked queries'
            ],
            'Cross-Site Scripting (XSS)': [
                'Session cookie theft leading to account takeover',
                'Malicious script execution in victim browsers',
                'Credential harvesting through fake login forms',
                'Malware distribution to application users'
            ],
            'Path Traversal': [
                'Exposure of sensitive system configuration files',
                'Access to user credentials and password hashes',
                'Disclosure of application source code',
                'Server infrastructure reconnaissance'
            ],
            'Command Injection': [
                'Remote code execution on the server',
                'Complete system compromise',
                'Data exfiltration from the server',
                'Installation of backdoors or malware'
            ]
        }
        return impacts.get(vuln_type, ['Unknown impact'])
    def _get_recommendation(self, vuln_type):
        """Return fix recommendation for each vulnerability type"""
        recommendations = {
            'SQL Injection': (
                'Use parameterised queries or prepared statements for all '
                'database interactions. Never concatenate user input '
                'directly into SQL queries. Implement input validation '
                'and use an ORM (Object Relational Mapper). Apply '
                'principle of least privilege to database accounts.'
            ),
            'Cross-Site Scripting (XSS)': (
                'Implement strict output encoding for all user-supplied '
                'data before rendering in HTML. Use Content Security '
                'Policy (CSP) headers. Validate and sanitise all input '
                'on both client and server side. Use modern frameworks '
                'that auto-escape output by default.'
            ),
            'Path Traversal': (
                'Validate and sanitise all file path inputs. Use a '
                'whitelist of allowed files or directories. Implement '
                'proper access controls and avoid passing user input '
                'directly to file system functions. Use realpath() to '
                'resolve and validate file paths.'
            ),
            'Command Injection': (
                'Avoid passing user input to system commands entirely. '
                'If unavoidable, use parameterised APIs instead of '
                'shell execution. Implement strict input validation '
                'using whitelists. Run application with minimal '
                'operating system privileges.'
            )
        }
        return recommendations.get(
            vuln_type, 'Implement proper input validation and output encoding.'
        )
    def _get_reproduction(self, detection):
        """Generate manual verification steps."""
        return [
            f"1. Navigate to: {detection['url']}",
            f"2. Locate the input field: '{detection['input_field']}'",
            f"3. Enter the following payload: {detection['payload']}",
            "4. Submit the form and observe the application's response.",
            "",
            "5. Manual Verification",
            "   • Check whether database error messages are returned.",
            "   • Check whether authentication is bypassed.",
            "   • Check whether sensitive information is disclosed.",
            "   • Check whether the application's behaviour changes unexpectedly.",
            "",
            "6. Automated Observation",
            f"   • The scanner observed an HTTP {detection['status_code']} response in {detection['response_time']:.2f} seconds.",
            f"   • {' '.join(detection['evidence'])}",
            "",
            "7. Conclusion",
              f"   • This finding is currently classified as {self._get_verification_status(detection)}.",
            "   • Manual penetration testing is recommended before confirming exploitation."
        ]
    def _build_evidence_summary(self, detection):
        """Build a clear, human-readable evidence summary."""
        evidence = []
        # HTTP response information
        evidence.append(
            f"HTTP Status Code: {detection['status_code']}"
        )
        evidence.append(
            f"Response Time: {detection['response_time']:.3f} seconds"
        )
        # Database error indicators
        if detection['error_indicators'] > 0:
            evidence.append(
                f"Database error indicators detected ({detection['error_indicators']})"
            )
        else:
            evidence.append(
                "No database error indicators detected."
            )
        # Sensitive data indicators
        if detection['sensitive_data'] > 0:
            evidence.append(
                f"Sensitive data indicators detected ({detection['sensitive_data']})"
            )
        else:
            evidence.append(
                "No sensitive information disclosed."
            )
        # Machine learning confidence
        evidence.append(
            f"Machine Learning Confidence: {detection['confidence']}%"
        )
        # Existing evidence generated by classifier
        evidence.extend(detection['evidence'])
        return evidence
    def _get_detection_method(self, detection):
        """Return the detection technique used."""
        if detection.get("rf_detected") and detection.get("iso_detected"):
            return "Random Forest + Isolation Forest (Hybrid Machine Learning Analysis)"
        elif detection.get("rf_detected"):
            return "Random Forest Classification"
        elif detection.get("iso_detected"):
            return "Isolation Forest Behavioural Analysis (Machine Learning)"
        return "Rule-Based Detection"
    def _get_verification_status(self, detection):
        """Return verification status determined by the classifier."""
        status = detection.get(
            'verification_status',
            'Potential'
        )
        if status == 'Confirmed':
            return 'Confirmed'
        if status == 'Evidence Detected':
            return 'Evidence Detected'
        return 'Potential'
