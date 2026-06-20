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

    def open_mobile_nav(self, label):
        menu = WebDriverWait(self.driver, 30).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button[aria-label='打开导航']"))
        )
        menu.click()
        self.nav(label)

    def test_capability_aware_admin_workflow(self):
        labels = {
            element.text.strip()
            for element in self.driver.find_elements(By.CSS_SELECTOR, "nav button span")
            if element.text.strip()
        }
        self.assertTrue(
            {"总览", "PowerDNS", "Certificates", "插件", "DNS 安全", "审计日志", "配置"}.issubset(labels)
        )

        self.nav("PowerDNS")
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., '权威与递归服务')]"))
        )
        page_text = self.driver.find_element(By.CSS_SELECTOR, "main").text
        self.assertIn("Authoritative", page_text)
        self.assertIn("Recursor", page_text)
        self.driver.find_element(By.XPATH, "//button[normalize-space()='传统 DNS']").click()
        zone_input = self.driver.find_element(
            By.XPATH, "//label[span[normalize-space()='Zone 名称']]//input"
        )
        zone_input.send_keys("selenium.test")
        self.driver.find_element(By.XPATH, "//button[contains(., '添加域名')]").click()
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., 'selenium.test')]"))
        )
        workspace_text = self.driver.find_element(By.CSS_SELECTOR, "main").text
        self.assertIn("权威 DNS 委派", workspace_text)
        self.assertIn("DNS 记录", workspace_text)
        refresh_input = self.driver.find_element(
            By.XPATH, "//article[header//h3[contains(., 'SOA')]]//label[span[normalize-space()='Refresh']]//input"
        )
        refresh_input.clear()
        refresh_input.send_keys("7200")
        self.driver.find_element(
            By.XPATH, "//article[header//h3[contains(., 'SOA')]]//button[contains(., '保存 SOA')]"
        ).click()
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//tr[td/span[contains(., 'SOA')] and td[contains(., '7200')]]"))
        )

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

        back_button = self.driver.find_element(By.CSS_SELECTOR, "button[aria-label='返回域名列表']")
        self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", back_button)
        self.driver.execute_script("arguments[0].click();", back_button)
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h3[contains(., '托管域名')]"))
        )
        zone_row = self.driver.find_element(
            By.XPATH, "//tr[td/strong[contains(., 'selenium.test')]]"
        )
        zone_row.find_element(By.CSS_SELECTOR, "button[title='删除 Zone']").click()
        WebDriverWait(self.driver, 30).until_not(
            EC.presence_of_element_located(
                (By.XPATH, "//tr[td/strong[contains(., 'selenium.test')]]")
            )
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

        self.nav("Certificates")
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located(
                (By.XPATH, "//*[contains(., 'Certificate issuance is not configured.')]")
            )
        )
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h3[contains(., 'Trust root')]"))
        )
        certificate_text = self.driver.find_element(By.CSS_SELECTOR, "main").text
        self.assertIn("ACME / PUBLIC WEBPKI", certificate_text)
        self.assertIn("persisted jobs:", certificate_text)
        self.assertIn("Key material and storage paths are never displayed.", certificate_text)
        self.assertNotIn("/var/lib", certificate_text)
        self.assertNotIn("-----BEGIN", certificate_text)
        time.sleep(6)

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

    def test_unicode_hns_zone_workflow(self):
        self.driver.set_window_size(1440, 1000)
        self.driver.get(ADMIN_URL)
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., 'DNS 服务运行概览')]"))
        )
        self.nav("PowerDNS")
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., '权威与递归服务')]"))
        )

        display_name = f"验收{int(time.time()) % 1000000}"
        punycode_name = display_name.encode("idna").decode("ascii")
        zone_input = self.driver.find_element(
            By.XPATH, "//label[span[normalize-space()='HNS 名称']]//input"
        )
        zone_input.send_keys(display_name)
        preview = WebDriverWait(self.driver, 10).until(
            EC.visibility_of_element_located((By.CSS_SELECTOR, ".idna-preview"))
        )
        self.assertIn(display_name, preview.text)
        self.assertIn(punycode_name, preview.text)

        add_zone = self.driver.find_element(By.XPATH, "//button[contains(., '添加域名')]")
        self.assertFalse(add_zone.is_enabled())
        glue_ipv4 = self.driver.find_element(
            By.XPATH, "//label[span[normalize-space()='Glue IPv4']]//input"
        )
        glue_ipv4.send_keys("192.0.2.53")
        self.assertTrue(add_zone.is_enabled())
        add_zone.click()
        try:
            outcome = WebDriverWait(self.driver, 30).until(
                lambda driver: (
                    driver.find_elements(By.XPATH, f"//h2[contains(., '{display_name}')]")
                    or driver.find_elements(By.CSS_SELECTOR, ".toast.error")
                )
            )
            if "toast error" in (outcome[0].get_attribute("class") or ""):
                self.fail(f"Unicode HNS zone creation failed: {outcome[0].text}")
            workspace_text = self.driver.find_element(By.CSS_SELECTOR, "main").text
            self.assertIn(f"Punycode {punycode_name}.", workspace_text)
            self.assertIn("SOA", workspace_text)
            self.assertIn("NS", workspace_text)
            self.assertIn("A", workspace_text)
        finally:
            back_buttons = self.driver.find_elements(By.CSS_SELECTOR, "button[aria-label='返回域名列表']")
            if back_buttons:
                self.driver.execute_script(
                    "arguments[0].scrollIntoView({block: 'center'});", back_buttons[0]
                )
                WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable(
                        (By.CSS_SELECTOR, "button[aria-label='返回域名列表']")
                    )
                ).click()
                WebDriverWait(self.driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//h3[contains(., '托管域名')]"))
                )
            rows = self.driver.find_elements(
                By.XPATH, f"//tr[td/strong[normalize-space()='{display_name}']]"
            )
            if rows:
                rows[0].find_element(By.CSS_SELECTOR, "button[title='删除 Zone']").click()
                WebDriverWait(self.driver, 30).until_not(
                    EC.presence_of_element_located(
                        (By.XPATH, f"//tr[td/strong[normalize-space()='{display_name}']]")
                    )
                )

    def test_mobile_hns_soa_update_workflow(self):
        self.driver.set_window_size(390, 844)
        self.driver.get(ADMIN_URL)
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., 'DNS 服务运行概览')]"))
        )
        self.open_mobile_nav("Certificates")
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h3[contains(., 'Trust root')]"))
        )
        certificate_text = self.driver.find_element(By.CSS_SELECTOR, "main").text
        self.assertIn("ACME / PUBLIC WEBPKI", certificate_text)
        self.assertIn("Key material and storage paths are never displayed.", certificate_text)
        self.assertNotIn("/var/lib", certificate_text)
        self.assertNotIn("-----BEGIN", certificate_text)
        self.open_mobile_nav("PowerDNS")
        WebDriverWait(self.driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//h2[contains(., '权威与递归服务')]"))
        )

        display_name = f"m{int(time.time()) % 1000000}"
        zone_input = self.driver.find_element(
            By.XPATH, "//label[span[normalize-space()='HNS 名称']]//input"
        )
        zone_input.send_keys(display_name)
        glue_ipv4 = self.driver.find_element(
            By.XPATH, "//label[span[normalize-space()='Glue IPv4']]//input"
        )
        glue_ipv4.send_keys("192.0.2.53")
        add_zone = self.driver.find_element(By.XPATH, "//button[contains(., '添加域名')]")
        self.assertTrue(add_zone.is_enabled())
        self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", add_zone)
        self.driver.execute_script("arguments[0].click();", add_zone)

        try:
            WebDriverWait(self.driver, 30).until(
                EC.visibility_of_element_located((By.XPATH, f"//h2[contains(., '{display_name}')]"))
            )
            refresh_input = WebDriverWait(self.driver, 30).until(
                EC.visibility_of_element_located((
                    By.XPATH,
                    "//article[header//h3[contains(., 'SOA')]]//label[span[normalize-space()='Refresh']]//input",
                ))
            )
            self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", refresh_input)
            refresh_input.clear()
            refresh_input.send_keys("8100")
            save_soa = self.driver.find_element(
                By.XPATH, "//article[header//h3[contains(., 'SOA')]]//button[contains(., '保存 SOA')]"
            )
            self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", save_soa)
            self.driver.execute_script("arguments[0].click();", save_soa)
            WebDriverWait(self.driver, 30).until(
                EC.visibility_of_element_located((By.XPATH, "//tr[td/span[contains(., 'SOA')] and td[contains(., '8100')]]"))
            )
        finally:
            back_buttons = self.driver.find_elements(By.CSS_SELECTOR, "button[aria-label='返回域名列表']")
            if back_buttons:
                self.driver.execute_script(
                    "arguments[0].scrollIntoView({block: 'center'});", back_buttons[0]
                )
                self.driver.execute_script("arguments[0].click();", back_buttons[0])
                WebDriverWait(self.driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//h3[contains(., '托管域名')]"))
                )
            rows = self.driver.find_elements(
                By.XPATH, f"//tr[td/strong[normalize-space()='{display_name}']]"
            )
            if rows:
                rows[0].find_element(By.CSS_SELECTOR, "button[title='删除 Zone']").click()
                WebDriverWait(self.driver, 30).until_not(
                    EC.presence_of_element_located(
                        (By.XPATH, f"//tr[td/strong[normalize-space()='{display_name}']]")
                    )
                )


if __name__ == "__main__":
    unittest.main()
