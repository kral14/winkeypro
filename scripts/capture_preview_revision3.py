import os
import sys
import time
import json
from selenium import webdriver
from selenium.webdriver.edge.options import Options

def run_capture():
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plan", "reports", "preview", "revision3"))
    os.makedirs(out_dir, exist_ok=True)

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--hide-scrollbars")

    driver = webdriver.Edge(options=options)
    
    results = {}

    try:
        # Mobil cihazlar - CDP Device Metrics Override ilə DƏQİQ 360, 390, 430 px
        mobile_devices = [
            {"width": 360, "height": 780, "name": "mobile_preview_360px.png", "device": "Android Small (360x780)"},
            {"width": 390, "height": 844, "name": "mobile_preview_390px.png", "device": "iPhone 13/14 (390x844)"},
            {"width": 430, "height": 932, "name": "mobile_preview_430px.png", "device": "iPhone 14/15 Pro Max (430x932)"},
        ]

        for dev in mobile_devices:
            driver.set_window_size(dev["width"] + 50, dev["height"] + 100)
            driver.execute_cdp_cmd("Emulation.setDeviceMetricsOverride", {
                "width": dev["width"],
                "height": dev["height"],
                "deviceScaleFactor": 2,
                "mobile": True
            })
            
            driver.get("http://127.0.0.1:5173/mobile")
            time.sleep(1.5)

            overflow_info = driver.execute_script("""
                const scrollWidth = document.documentElement.scrollWidth;
                const bodyScroll = document.body.scrollWidth;
                const winWidth = window.innerWidth;
                const hasOverflow = (scrollWidth > winWidth) || (bodyScroll > winWidth);
                return {
                    winWidth: winWidth,
                    scrollWidth: scrollWidth,
                    bodyScroll: bodyScroll,
                    hasOverflow: hasOverflow
                };
            """)

            filepath = os.path.join(out_dir, dev["name"])
            driver.save_screenshot(filepath)
            size = os.path.getsize(filepath)

            results[dev["name"]] = {
                "device": dev["device"],
                "exact_viewport": f"{dev['width']}x{dev['height']}",
                "size_bytes": size,
                "path": filepath,
                "overflow_info": overflow_info
            }
            print(f"[OK] Captured {dev['name']} ({size} bytes, winWidth={overflow_info['winWidth']}). Overflow: {overflow_info['hasOverflow']}")

        # Clear device override for desktop & admin
        driver.execute_cdp_cmd("Emulation.clearDeviceMetricsOverride", {})
        
        # Desktop (1280x850)
        driver.set_window_size(1280, 850)
        driver.get("http://127.0.0.1:5173/desktop")
        time.sleep(1.5)
        desk_path = os.path.join(out_dir, "desktop_preview_rev3.png")
        driver.save_screenshot(desk_path)
        desk_size = os.path.getsize(desk_path)
        results["desktop_preview_rev3.png"] = {
            "device": "Desktop Shell (1280x850)",
            "size_bytes": desk_size,
            "path": desk_path
        }
        print(f"[OK] Captured desktop_preview_rev3.png ({desk_size} bytes)")

        # Admin (1280x900)
        driver.set_window_size(1280, 900)
        driver.get("http://127.0.0.1:5173/admin")
        time.sleep(1.5)
        admin_path = os.path.join(out_dir, "admin_preview_rev3.png")
        driver.save_screenshot(admin_path)
        admin_size = os.path.getsize(admin_path)
        results["admin_preview_rev3.png"] = {
            "device": "Admin Dashboard (1280x900)",
            "size_bytes": admin_size,
            "path": admin_path
        }
        print(f"[OK] Captured admin_preview_rev3.png ({admin_size} bytes)")

    finally:
        driver.quit()

    with open(os.path.join(out_dir, "render_audit.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_capture()
