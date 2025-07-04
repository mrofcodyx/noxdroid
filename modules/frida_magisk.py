import os
import requests
import time
from utils.common import clear_screen
from modules.mafrida_config import config_mafrida  # certifique-se de importar

ADB = "adb"

def install_magisk_frida_module():
    print("\033[96m→ Installing Mafrida as a Magisk module...\033[0m")
    try:
        response = requests.get("https://api.github.com/repos/theShinigami/MaFrida/releases/latest", timeout=10)
        response.raise_for_status()
        latest = response.json()
        version = latest['tag_name']
        zip_name = ""
        download_url = ""

        for asset in latest['assets']:
            if asset['name'].endswith(".zip"):
                zip_name = asset['name']
                download_url = asset['browser_download_url']
                break

        if not download_url:
            raise Exception("Could not find .zip module in latest release.")

        print(f"\033[96m→ Downloading Mafrida {version} ({zip_name})...\033[0m")
        r = requests.get(download_url)
        with open(zip_name, "wb") as f:
            f.write(r.content)

        print("\033[96m→ Uploading and installing on the emulator...\033[0m")
        os.system(f"{ADB} push {zip_name} /sdcard/Download/")
        os.system(f"{ADB} shell su -c 'magisk --install-module /sdcard/Download/{zip_name}'")

        print("\033[92m✔ Mafrida installed successfully.\033[0m")
        print("\033[93m→ Restarting Nox to activate the module...\033[0m")
        os.system(f"{ADB} reboot")

        config_mafrida()

    except Exception as e:
        print(f"\033[91m✖ Installation failed: {e}\033[0m")
    clear_screen()
