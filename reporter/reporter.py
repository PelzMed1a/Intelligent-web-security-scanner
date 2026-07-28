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

        report = []
        seen = set()

        for i, detection in enumerate(detections):
            # Deduplicate similar findings
            dedup_key = (
                detection['url'],
                detection['input_field'],
                detection['vulnerability_type']
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

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
                'evidence': detection['evidence'],
                'description': self._get_description(
                    detection['vulnerability_type']
                ),
                'impact': self._get_impact(
                    detection['vulnerability_type']
                ),
                'recommendation': self._get_recommendation(
                    detection['vulnerability_type']
                ),
                'reproduction_steps': self._get_reproduction(detection),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'detection_method': self._get_detection_method(detection)
            }
            report.append(report_entry)

        # Sort by severity
        severity_order = {
            'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3
        }
        report.sort(key=lambda x: severity_order.get(x['severity'], 4))

        print(f"[*] Report generated: {len(report)} unique vulnerabilities")
        return report

    def _get_description(self, vuln_type):
        """Return description for each vulnerability type"""
        descriptions = {
            'SQL Injection': (
                'SQL Injection occurs when malicious SQL code is inserted '
                'into an input field and executed by the database. This '
                'allows attackers to read, modify, or delete database '
                'contents and bypass authentication mechanisms.'
            ),
            'Cross-Site Scripting (XSS)': (
                'XSS vulnerabilities allow attackers to inject malicious '
                'scripts into web pages viewed by other users. This can '
                'lead to session hijacking, credential theft, and '
                'malicious redirects.'
            ),
            'Path Traversal': (
                'Path Traversal allows attackers to access files and '
                'directories outside the intended web root directory. '
                'Attackers can read sensitive system files including '
                'configuration files and password files.'
            ),
            'Command Injection': (
                'Command Injection allows attackers to execute arbitrary '
                'operating system commands on the server. This can lead '
                'to complete system compromise and data theft.'
            )
        }
        return descriptions.get(vuln_type, 'Unknown vulnerability type detected.')

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
        """Generate step-by-step reproduction instructions"""
        return [
            f"1. Navigate to: {detection['url']}",
            f"2. Locate the input field: '{detection['input_field']}'",
            f"3. Enter the following payload: {detection['payload']}",
            f"4. Submit the form and observe the response",
            f"5. Expected: Server responds with status {detection['status_code']} "
            f"in {detection['response_time']:.2f}s",
            f"6. Vulnerability confirmed if: "
            + (", ".join(detection['evidence']))
        ]

    def _get_detection_method(self, detection):
        """Describe which models detected this vulnerability"""
        methods = []

        if detection['rf_detected']:
            methods.append("Random Forest Classification")

        if detection['iso_detected']:
            methods.append("Isolation Forest Behavioral Analysis")

        if len(methods) == 2:
            return "ML Ensemble (Random Forest + Isolation Forest)"

        if methods:
            return methods[0]

        return "Rule-Based Detection"
