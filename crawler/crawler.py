import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from crawler.selenium_renderer import SeleniumRenderer


# NodeGoat default seeded account (created by its own db-reset).
NODEGOAT_USER = "user1"
NODEGOAT_PASS = "User1_123"


class Crawler:

    def __init__(self, base_url, username=None, password=None):
        self.base_url = base_url.rstrip("/")
        self.visited = set()
        self.endpoints = []

        # Credentials supplied by the security tester through the scan
        # form. If left blank, we fall back to the known default account
        # for the detected target so quick local testing still works.
        self.username = username or None
        self.password = password or None

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Scanner Research Tool)"
        })

        # Selenium renderer
        self.renderer = SeleniumRenderer(headless=True)

        # Pick the right login routine for the target. NodeGoat is a
        # Node.js app that logs in completely differently from DVWA, so
        # we detect it (it runs on :4000 / :3000 or the URL names it) and
        # use its own authentication flow.
        self.target_type = self._target_type()
        if self.target_type == "nodegoat":
            print("[*] NodeGoat detected")
            self._login_nodegoat()
        elif "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            print("[*] DVWA detected")
            self._login()
        else:
            print("[*] Non-DVWA target detected - skipping auto-login")

    def _target_type(self):
        """Identify the target so we apply the correct login routine."""
        url = self.base_url.lower()
        if ":4000" in url or ":3000" in url or "nodegoat" in url:
            return "nodegoat"
        return "dvwa"

    def _login_nodegoat(self):
        """Authenticate with NodeGoat using its /login form."""
        try:
            login_url = urljoin(self.base_url + "/", "login")

            # Fetch the login page to obtain a session cookie and the
            # CSRF token (NodeGoat serves an empty token and accepts it,
            # but we still read and resend whatever is there).
            response = self.session.get(login_url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            token_field = soup.find("input", {"name": "_csrf"})
            csrf = token_field.get("value", "") if token_field else ""

            login_data = {
                "userName": self.username or NODEGOAT_USER,
                "password": self.password or NODEGOAT_PASS,
                "_csrf": csrf
            }

            login_response = self.session.post(
                login_url,
                data=login_data,
                timeout=10,
                allow_redirects=False,
                headers={"Referer": login_url}
            )

            location = login_response.headers.get("Location", "")
            last = location.rstrip("/").rsplit("/", 1)[-1]

            # Success = redirect to a page that is NOT /login.
            if (login_response.status_code in (301, 302, 303, 307, 308)
                    and last != "login"):
                print(f"[*] Logged into NodeGoat successfully (-> {location})")
                return True

            # Fallback: confirm by fetching an authenticated page.
            dash = self.session.get(
                urljoin(self.base_url + "/", "dashboard"),
                timeout=10,
                allow_redirects=False
            )
            if dash.status_code == 200:
                print("[*] Logged into NodeGoat successfully")
                return True

            print("[!] NodeGoat authentication failed")
            return False

        except Exception as e:
            print(f"[!] NodeGoat login failed: {e}")
            return False

    def _login(self):
        """Authenticate with DVWA and set security level to LOW."""

        try:
            login_url = urljoin(self.base_url + "/", "login.php")

            # Step 1: Get login page and CSRF token
            response = self.session.get(
                login_url,
                timeout=10,
                allow_redirects=True
            )

            print(f"[*] Login page status: {response.status_code}")

            soup = BeautifulSoup(response.text, "html.parser")

            token_field = soup.find(
                "input",
                {"name": "user_token"}
            )

            if not token_field:
                print("[!] DVWA login token not found")
                return False

            token = token_field.get("value", "")

            print(f"[*] DVWA login token: {token}")

            # Step 2: Submit login
            login_data = {
                "username": self.username or "admin",
                "password": self.password or "password",
                "Login": "Login",
                "user_token": token
            }

            login_response = self.session.post(
                login_url,
                data=login_data,
                timeout=10,
                allow_redirects=False,
                headers={
                    "Referer": login_url
                }
            )

            print(
                f"[*] Login response: "
                f"{login_response.status_code} "
                f"{login_response.headers.get('Location', '')}"
            )

            # DVWA normally redirects to index.php after successful login.
            location = login_response.headers.get("Location", "")

            if "index.php" not in location:
                print("[!] DVWA authentication failed")

                # Get the redirected login page to expose the error
                check_response = self.session.get(
                    login_url,
                    timeout=10
                )

                check_soup = BeautifulSoup(
                    check_response.text,
                    "html.parser"
                )

                messages = check_soup.find_all(
                    "div",
                    class_="message"
                )

                for message in messages:
                    print(
                        f"[!] DVWA: "
                        f"{message.get_text(strip=True)}"
                    )

                return False

            # Step 3: Verify authenticated session
            index_url = urljoin(self.base_url + "/", "index.php")

            index_response = self.session.get(
                index_url,
                timeout=10,
                allow_redirects=False
            )

            print(
                f"[*] Authentication verification: "
                f"{index_response.status_code} "
                f"{index_response.headers.get('Location', '')}"
            )

            if (
                index_response.status_code in (301, 302, 303, 307, 308)
                and "login.php" in index_response.headers.get(
                    "Location", ""
                )
            ):
                print("[!] Session is not authenticated")
                return False

            print("[*] Logged into DVWA successfully")

            # Step 4: Set DVWA security level to LOW
            self._set_security_low()

            return True

        except Exception as e:
            print(f"[!] Login failed: {e}")
            return False

    def _set_security_low(self):
        """Set DVWA security level to LOW."""

        try:
            security_url = urljoin(
                self.base_url + "/",
                "security.php"
            )

            # Get a fresh session token
            response = self.session.get(
                security_url,
                timeout=10
            )

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            token_field = soup.find(
                "input",
                {"name": "user_token"}
            )

            token = (
                token_field.get("value", "")
                if token_field
                else ""
            )

            security_data = {
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": token
            }

            security_response = self.session.post(
                security_url,
                data=security_data,
                timeout=10,
                allow_redirects=True,
                headers={
                    "Referer": security_url
                }
            )

            # Check the security cookie
            security_cookie = self.session.cookies.get(
                "security"
            )

            if security_cookie == "low":
                print("[*] DVWA security level set to LOW")
            else:
                print(
                    "[!] Could not confirm LOW security level"
                )

        except Exception as e:
            print(
                f"[!] Failed to set DVWA security level: {e}"
            )

    def crawl(self):
        """Crawl the target and find all testable endpoints."""

        print(f"[*] Crawling {self.base_url}")

        self._crawl_page(self.base_url)

        print(
            f"[*] Found {len(self.endpoints)} "
            f"testable endpoints"
        )

        return self.endpoints

    def _crawl_page(self, url):
        """Recursively crawl pages and extract forms."""

        if url in self.visited:
            return

        # Never follow logout links -- doing so destroys the crawler's
        # authenticated session and every page afterwards bounces to the
        # login screen.
        if "logout" in url.lower():
            return

        parsed_base = urlparse(self.base_url)
        parsed_url = urlparse(url)

        # Stay on the same host
        if parsed_url.netloc != parsed_base.netloc:
            return

        # Limit crawler depth/size
        if len(self.visited) >= 50:
            return

        self.visited.add(url)

        print(f"[CRAWLING] {url}")

        try:
            response = self.session.get(
                url,
                timeout=10,
                allow_redirects=True
            )

            # Detect authentication redirects. DVWA bounces to login.php;
            # NodeGoat bounces to /login. If a page we requested ends up
            # at the login screen, our session is not authorised for it.
            final_url = response.url

            bounced_to_login = (
                "login.php" in final_url
                or (
                    final_url.rstrip("/") != url.rstrip("/")
                    and final_url.rstrip("/").rsplit("/", 1)[-1] == "login"
                )
            )
            if bounced_to_login:
                print(
                    f"[!] Authentication redirect detected: "
                    f"{url}"
                )
                return

            if response.status_code != 200:
                print(
                    f"[!] HTTP {response.status_code}: "
                    f"{url}"
                )
                return

            html = response.text

            soup = BeautifulSoup(
                html,
                "html.parser"
            )

            # Extract forms
            forms = soup.find_all("form")

            for form in forms:
                endpoint = self._extract_form_data(
                    url,
                    form
                )

                if endpoint:
                    # Avoid duplicate endpoints
                    if endpoint not in self.endpoints:
                        self.endpoints.append(endpoint)

                        print(
                            f"[ENDPOINT] "
                            f"{endpoint['method']} "
                            f"{endpoint['url']}"
                        )

            # Extract links
            links = soup.find_all(
                "a",
                href=True
            )

            for link in links:
                href = link.get("href", "").strip()

                if not href:
                    continue

                # Ignore javascript links
                if href.lower().startswith("javascript:"):
                    continue

                # Ignore fragments
                if href.startswith("#"):
                    continue

                # Ignore logout links
                if "logout" in href.lower():
                    continue

                full_url = urljoin(
                    url,
                    href
                )

                parsed = urlparse(full_url)

                # Only follow links on the same host
                if parsed.netloc == parsed_base.netloc:

                    # Remove fragments
                    clean_url = parsed._replace(
                        fragment=""
                    ).geturl()

                    self._crawl_page(clean_url)

        except requests.RequestException as e:
            print(
                f"[!] Request error crawling "
                f"{url}: {e}"
            )

        except Exception as e:
            print(
                f"[!] Error crawling "
                f"{url}: {e}"
            )

    def _extract_form_data(self, page_url, form):
        """Extract form action, method, fuzzable inputs, and the
        submit/hidden fields that must be replayed unmodified.
        DVWA's PHP only runs the vulnerable code when the form's
        Submit button is present in the request (isset($_GET['Submit'])),
        so submit/hidden fields must be captured, not discarded."""

        try:
            action = form.get("action", "")
            method = form.get(
                "method",
                "get"
            ).upper()

            form_url = (
                urljoin(page_url, action)
                if action
                else page_url
            )

            inputs = []
            extra_fields = []

            for input_field in form.find_all(
                ["input", "textarea", "select"]
            ):

                field_name = input_field.get(
                    "name",
                    ""
                )

                field_type = input_field.get(
                    "type",
                    "text"
                )

                field_value = input_field.get(
                    "value",
                    ""
                )

                if not field_name:
                    continue

                if field_type in ["submit", "hidden"]:
                    extra_fields.append({
                        "name": field_name,
                        "value": field_value
                    })
                    continue

                if field_type in ["button", "image"]:
                    continue

                inputs.append({
                    "name": field_name,
                    "type": field_type,
                    "value": field_value
                })

            if inputs:
                return {
                    "url": form_url,
                    "method": method,
                    "inputs": inputs,
                    "extra_fields": extra_fields,
                    "page": page_url
                }

        except Exception as e:
            print(
                f"[!] Error extracting form: {e}"
            )

        return None

    def close(self):
        """Close Selenium renderer."""

        self.renderer.close()
