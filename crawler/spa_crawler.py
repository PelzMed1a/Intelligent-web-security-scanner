import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from crawler.selenium_renderer import SeleniumRenderer


class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited = set()
        self.endpoints = []
        self.session = requests.Session()
        self.renderer = SeleniumRenderer(headless=True)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Scanner Research Tool)'
        })

        # Selenium renderer
        self.renderer = SeleniumRenderer(headless=True)

        # Login to DVWA automatically only if target is DVWA
        if 'localhost' in base_url and '3000' not in base_url:
            self._login()
        else:
            print("[*] Non-DVWA target detected - skipping auto-login")

    def _login(self):
        """Log into DVWA before crawling"""
        try:
            login_url = urljoin(self.base_url, '/login.php')

            response = self.session.get(login_url, timeout=10)
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

            security_url = urljoin(self.base_url, '/security.php')
            self.session.post(
                security_url,
                data={
                    'security': 'low',
                    'seclev_submit': 'Submit',
                    'user_token': token
                },
                timeout=10
            )

            print("[*] Logged into DVWA successfully")

        except Exception as e:
            print(f"[!] Login failed: {e}")

    def crawl(self):
        """Crawl the target and find all testable endpoints"""
        print(f"[*] Crawling {self.base_url}")
        self._crawl_page(self.base_url)
        print(f"[*] Found {len(self.endpoints)} testable endpoints")
        return self.endpoints

    def _crawl_page(self, url):
        """Recursively crawl pages and extract forms"""

        if url in self.visited:
            return

        if not url.startswith(self.base_url):
            return

        if len(self.visited) > 50:
            return

        self.visited.add(url)
        print(f"[CRAWLING] {url}")

        try:
            html = self.renderer.render(url)

            soup = BeautifulSoup(html, "html.parser")

            forms = soup.find_all("form")
            for form in forms:
                endpoint = self._extract_form_data(url, form)
                if endpoint:
                    self.endpoints.append(endpoint)

            links = soup.find_all("a", href=True)
            for link in links:
                full_url = urljoin(url, link["href"])
                parsed = urlparse(full_url)

                if parsed.netloc == urlparse(self.base_url).netloc:
                    self._crawl_page(full_url)

            # DIscover Angular/SPA hash routes
            for link in soup.find_all("a"):

                href = link.get("href")

                if href and href.startswitch("#/"):

                    full_url = self.base_url.rstrip("/") + "/" + href
                    
                    if full_url not in self.visited:
                        print(f"[SPA ROUTE] {full_url}")
                        self._crawl_page(full_url)

            # Discover buttons with router links
            buttons = soup.find_all(["button", "mat-button"])

            print(f"[INFO] Found {len(buttons)} buttons")

        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")

    def _extract_form_data(self, page_url, form):
        """Extract form action, method and input fields"""

        try:
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            form_url = urljoin(page_url, action) if action else page_url

            inputs = []

            for input_field in form.find_all(['input', 'textarea', 'select']):
                field_name = input_field.get('name', '')
                field_type = input_field.get('type', 'text')
                field_value = input_field.get('value', '')

                if field_name and field_type not in ['submit', 'button', 'hidden', 'image']:
                    inputs.append({
                        'name': field_name,
                        'type': field_type,
                        'value': field_value
                    })

            if inputs:
                return {
                    'url': form_url,
                    'method': method,
                    'inputs': inputs,
                    'page': page_url
                }

        except Exception as e:
            print(f"[!] Error extracting form: {e}")

        return None

    def close(self):
        """Close Selenium browser"""
        self.renderer.close()
