import time
import requests
import os

ADB = "adb"

def get_latest_frida_version():
    try:
        response = requests.get("https://api.github.com/repos/frida/frida/releases/latest", timeout=10)
        response.raise_for_status()
        return response.json()["tag_name"].lstrip("v")
    except Exception as e:
        print(f"\033[93m⚠ Failed to get latest version of Frida. Using fallback: 17.2.6 ({e})\033[0m")
        return "17.2.6"

def config_mafrida():
    print("\033[96m→ Waiting 50 seconds for Nox to restart...\033[0m")
    for i in range(50, 0, -1):
        print(f"\r\033[96m  {i}s remaining... waiting for boot\033[0m", end="", flush=True)
        time.sleep(1)

    print("\n\033[96m→ Getting latest version of Frida-Server...\033[0m")
    version = get_latest_frida_version()
    print(f"\033[92m✔ Latest version of Frida-Server: {version}\033[0m")

    print("\033[96m→ Setting up Mafrida...\033[0m")
    os.system(f"{ADB} shell su -c 'mafrida kill'")
    os.system(f"{ADB} shell su -c 'mafrida --set {version}'")
    os.system(f"{ADB} shell su -c 'mafrida download'")
    os.system(f"{ADB} shell su -c 'mafrida start'")
    os.system(f"{ADB} shell su -c 'mafrida enable'")

    print("\n\033[92m✔ Mafrida successfully configured!\033[0m")
    input("→ Press Enter to continue...")
