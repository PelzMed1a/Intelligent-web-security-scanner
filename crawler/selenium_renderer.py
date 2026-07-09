from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import time


class SeleniumRenderer:
    def __init__(self, headless=True):
        options = Options()

        # Explicitly use Chromium
        options.binary_location = "/usr/bin/chromium"

        if headless:
            options.add_argument("--headless=new")

        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")

        self.driver = webdriver.Chrome(
            service=Service("/usr/bin/chromedriver"),
            options=options
        )

    def render(self, url, wait=3):
        self.driver.get(url)
        time.sleep(wait)
        return self.driver.page_source

    def close(self):
        self.driver.quit()
