import os
import time
import unittest

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


REMOTE_URL = os.getenv("SELENIUM_REMOTE_URL", "http://selenium-chromium:4444/wd/hub")
ADMIN_URL = os.getenv("ANYNS_ADMIN_URL", "http://anyns-admin-api:8080")


class AdminUIWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
        deadline = time.time() + 120
        last_error = None
        while time.time() < deadline:
            try:
                cls.driver = webdriver.Remote(command_executor=REMOTE_URL, options=options)
                cls.driver.set_window_size(1440, 1000)
                cls.driver.get(ADMIN_URL)
                WebDriverWait(cls.driver, 60).until(EC.title_contains("anyNS"))
                WebDriverWait(cls.driver, 60).until(
                    EC.visibility_of_element_located((By.XPATH, "//h2[contains(., 'DNS 服务运行概览')]"))
                )
                return
            except WebDriverException as error:
                last_error = error
                try:
                    cls.driver.quit()
                except (AttributeError, WebDriverException):
                    pass
                time.sleep(2)
        raise RuntimeError(f"Selenium or admin UI did not become ready: {last_error}")

    @classmethod
    def tearDownClass(cls):
        if not hasattr(cls, "driver"):
            return
        get_log = getattr(cls.driver, "get_log", None)
        severe = [] if get_log is None else [
            entry for entry in get_log("browser") if entry.get("level") == "SEVERE"
        ]
        cls.driver.quit()
        if severe:
            raise AssertionError(f"browser console contains severe errors: {severe}")

    def nav(self, label):
        button = WebDriverWait(self.driver, 30).until(
            EC.element_to_be_clickable((By.XPATH, f"//nav//button[.//span[normalize-space()='{label}']]"))
        )
        button.click()

    def test_capability_aware_admin_workflow(self):
        labels = {
            element.text.strip()
            for element in self.driver.find_elements(By.CSS_SELECTOR, "nav button span")
            if element.text.strip()
        }
        self.assertTrue({"总览", "PowerDNS", "插件", "DNS 安全", "审计日志", "配置"}.issubset(labels))

        self.nav("PowerDNS")
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., '权威与递归服务')]"))
        )
        page_text = self.driver.find_element(By.CSS_SELECTOR, "main").text
        self.assertIn("Authoritative", page_text)
        self.assertIn("Recursor", page_text)
        manage = WebDriverWait(self.driver, 30).until(
            EC.element_to_be_clickable((By.XPATH, "//tr[td/strong[contains(., 'anyns.test')]]//button[contains(., '管理记录')]"))
        )
        manage.click()
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., 'anyns.test')]"))
        )
        workspace_text = self.driver.find_element(By.CSS_SELECTOR, "main").text
        self.assertIn("HNS 链上委派", workspace_text)
        self.assertIn("DNS 记录", workspace_text)

        editor = self.driver.find_element(By.CSS_SELECTOR, ".record-editor")
        selects = editor.find_elements(By.CSS_SELECTOR, "select")
        selects[0].send_keys("TXT")
        name = editor.find_element(By.CSS_SELECTOR, "input")
        name.clear()
        name.send_keys("_selenium")
        content = editor.find_element(By.CSS_SELECTOR, "textarea")
        content.send_keys("automation=ok")
        editor.find_element(By.XPATH, ".//button[contains(., '保存记录')]").click()
        record_row = WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//tr[td/strong[normalize-space()='_selenium']]"))
        )
        self.assertIn("automation=ok", record_row.text)
        record_row.find_element(By.CSS_SELECTOR, "button[title='删除记录']").click()
        WebDriverWait(self.driver, 30).until_not(
            EC.presence_of_element_located((By.XPATH, "//tr[td/strong[normalize-space()='_selenium']]"))
        )

        self.driver.find_element(By.CSS_SELECTOR, "button[aria-label='返回域名列表']").click()
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h3[contains(., '托管域名')]"))
        )

        self.nav("插件")
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., '去中心化域名插件')]"))
        )
        def hns_toggle():
            row = self.driver.find_element(By.XPATH, "//tr[td/strong[normalize-space()='hns']]")
            return row.find_element(By.CSS_SELECTOR, "button[role='switch']")

        toggle = WebDriverWait(self.driver, 30).until(lambda _: hns_toggle())
        initial = toggle.get_attribute("aria-checked")
        toggle.click()
        WebDriverWait(self.driver, 30).until(
            lambda _: hns_toggle().get_attribute("aria-checked") != initial
        )
        hns_toggle().click()
        WebDriverWait(self.driver, 30).until(
            lambda _: hns_toggle().get_attribute("aria-checked") == initial
        )

        self.nav("配置")
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., '统一配置')]"))
        )
        save = self.driver.find_element(By.XPATH, "//button[contains(., '保存并重载')]")
        self.assertFalse(save.is_enabled())
        self.assertIn("不可写", self.driver.find_element(By.CSS_SELECTOR, "main").text)

        self.driver.set_window_size(390, 844)
        menu = WebDriverWait(self.driver, 30).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[aria-label='打开导航']"))
        )
        menu.click()
        self.nav("总览")
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., 'DNS 服务运行概览')]"))
        )


if __name__ == "__main__":
    unittest.main()
