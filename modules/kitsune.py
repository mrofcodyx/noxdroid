import os
import requests
from utils.common import clear_screen

ADB = "adb"

def install_kitsune_magisk():
    clear_screen()
    print("\033[96m→ Installing Magisk \033[0m\n")
    print("\033[93mprerequisites:\033[0m")
    print("- Root enabled on Nox")
    print("- System Disk Writable enabled\n")
    input("→ Press Enter to continue...")
    try:
        resp = requests.get("https://api.github.com/repos/1q23lyc45/KitsuneMagisk/releases/latest", timeout=10)
        resp.raise_for_status()
        ver = resp.json()['tag_name']
        apk_url = ""
        for asset in resp.json()['assets']:
            if asset['name'].endswith(".apk"):
                apk_url = asset['browser_download_url']
                break
        if not apk_url:
            raise Exception("APK not found.")
        apk_name = f"KitsuneMagisk-{ver}.apk"
        print(f"→ Downloading {apk_name}...")
        r = requests.get(apk_url)
        open(apk_name, "wb").write(r.content)
        print("→ Installing...")
        os.system(f"{ADB} install -r {apk_name}")
        print("\n\033[92m✔ Magisk successfully installed on Nox!\033[0m\n")
        print("\033[93m→ Action required:\033[0m")
        print("  1. Open the 'Magisk' app in the emulator.")
        print("  2. Tap 'Install Magisk'.")
        print("  3. Choose 'Direct Install (modify/system direct)'.")
        print("  4. Disable Boot Root option in Nox Player settings.")
        print("  5. restart Nox Player\n")
    except Exception as e:
        print(f"\033[91m✖ Erro: {e}\033[0m")
    input("→ Press Enter to continue...")
    clear_screen()
