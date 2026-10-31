import time
import os
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.edge.options import Options

PREVIEW_DIR = Path("plan/reports/preview/revision2")
PREVIEW_DIR.mkdir(parents=True, exist_ok=True)

options = Options()
options.add_argument("--headless=new")
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--log-level=3")

driver = webdriver.Edge(options=options)

try:
    # 1. Desktop Preview Rev 2
    print("[1/3] Desktop Gorunusu (Revision 2) Render Edilir...")
    driver.set_window_size(1280, 850)
    driver.get("http://127.0.0.1:5173/desktop")
    time.sleep(2)
    desktop_png = PREVIEW_DIR / "desktop_preview_rev2.png"
    driver.save_screenshot(str(desktop_png))
    print(f"  -> Saxlanildi: {desktop_png} ({desktop_png.stat().st_size} bayt)")

    # 2. Mobile Preview Rev 2
    print("[2/3] Mobil PWA Gorunusu (Revision 2) Render Edilir...")
    driver.set_window_size(420, 860)
    driver.get("http://127.0.0.1:5173/mobile")
    time.sleep(2)
    mobile_png = PREVIEW_DIR / "mobile_preview_rev2.png"
    driver.save_screenshot(str(mobile_png))
    print(f"  -> Saxlanildi: {mobile_png} ({mobile_png.stat().st_size} bayt)")

    # 3. Admin Dashboard Preview Rev 2
    print("[3/3] Admin Dashboard Gorunusu (Revision 2) Render Edilir...")
    driver.set_window_size(1400, 920)
    driver.get("http://127.0.0.1:5173/admin")
    time.sleep(2)
    admin_png = PREVIEW_DIR / "admin_preview_rev2.png"
    driver.save_screenshot(str(admin_png))
    print(f"  -> Saxlanildi: {admin_png} ({admin_png.stat().st_size} bayt)")

    print("[SUCCESS] Butun yeni screenshot-lar xetasiz saxlanildi!")

finally:
    driver.quit()
