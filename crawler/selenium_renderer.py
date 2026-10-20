import os
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service


class SeleniumRenderer:
    """Optional JavaScript renderer, hardened to run fully offline.

    Only constructed on demand (see ``Crawler._get_renderer``); a normal
    scan never creates one. Every background-network feature of Chromium is
    disabled so the tool never reaches out to the internet during a local
    scan.
    """

    def __init__(self, headless=True):
        options = Options()

        # Resolve the Chromium / chromedriver locations, allowing overrides
        # through the environment for non-Kali installations.
        options.binary_location = os.environ.get(
            "SCANNER_CHROMIUM", "/usr/bin/chromium"
        )
        driver_path = os.environ.get(
            "SCANNER_CHROMEDRIVER", "/usr/bin/chromedriver"
        )

        if headless:
            options.add_argument("--headless=new")

        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")

        # --- Offline / no-internet hardening ---------------------------
        # Stop Chromium from doing anything on the network that is not the
        # target itself (update checks, safe-browsing lookups, telemetry,
        # first-run sign-in, DNS pre-fetch, etc.).
        options.add_argument("--disable-background-networking")
        options.add_argument("--disable-component-update")
        options.add_argument("--disable-domain-reliability")
        options.add_argument("--disable-client-side-phishing-detection")
        options.add_argument("--disable-sync")
        options.add_argument("--disable-default-apps")
        options.add_argument("--disable-extensions")
        options.add_argument("--no-first-run")
        options.add_argument("--no-default-browser-check")
        options.add_argument("--disable-background-timer-throttling")
        options.add_argument("--metrics-recording-only")
        options.add_argument("--safebrowsing-disable-auto-update")
        options.add_argument("--disable-features=Translate,BackForwardCache")

        self.driver = webdriver.Chrome(
            service=Service(driver_path),
            options=options
        )

    def render(self, url, wait=3):
        self.driver.get(url)
        time.sleep(wait)
        return self.driver.page_source

    def close(self):
        self.driver.quit()
