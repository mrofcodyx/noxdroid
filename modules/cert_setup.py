import os
import time
import requests
from OpenSSL import crypto

ADB = "adb"

def setup_cert_nox():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(
        "\033[96m→ Setting Up Burp Certificate...\033[0m\n"
        "\033[96m  Before proceeding:\033[0m\n"
        "  - Ensure Burp Suite is running on port 8080.\n"
        "  - Set emulator proxy: Settings → Network → Proxy\n"
        "    → Host: 127.0.0.1, Port: 8080\n"
        "\033[96m  Waiting 20s for proxy setup...\033[0m\n"
    )

    for i in range(20, 0, -1):
        print(f"\r\033[96m  {i}s left...\033[0m", end="", flush=True)
        time.sleep(1)
    print("\r\033[96m  Downloading certificate...\033[0m")
    try:
        response = requests.get("http://127.0.0.1:8080/cert")
        with open("cacert.der", "wb") as f:
            f.write(response.content)
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, open("cacert.der", "rb").read())
        pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        with open("portswigger.crt", "wb") as f:
            f.write(pem)
        print("\033[96m  Pushing certificate...\033[0m")
        os.system(f"{ADB} push portswigger.crt /sdcard/portswigger.crt")
        print("\033[96m  Fetching latest AlwaysTrustUserCerts version...\033[0m")
        try:
            response = requests.get("https://api.github.com/repos/NVISOsecurity/AlwaysTrustUserCerts/releases/latest", timeout=5)
            response.raise_for_status()
            module_version = response.json()["tag_name"]
            filename = f"AlwaysTrustUserCerts_{module_version}.zip"
            module_url = f"https://github.com/NVISOsecurity/AlwaysTrustUserCerts/releases/download/{module_version}/{filename}"
        except (requests.RequestException, KeyError) as e:
            print(f"\033[93m→ Failed to fetch latest version: {e}\033[0m")
            print("\033[93m→ Falling back to v1.3\033[0m")
            module_version = "v1.3"
            filename = f"AlwaysTrustUserCerts_{module_version}.zip"
            module_url = f"https://github.com/NVISOsecurity/AlwaysTrustUserCerts/releases/download/{module_version}/{filename}"
        print(f"\033[96m  Downloading AlwaysTrustUserCerts {module_version}...\033[0m")
        r = requests.get(module_url)
        r.raise_for_status()
        with open(filename, "wb") as f:
            f.write(r.content)
        print("\033[96m  Installing Magisk module...\033[0m")
        os.system(f"{ADB} push {filename} /data/local/tmp/")
        os.system(f"{ADB} shell su -c 'magisk --install-module /data/local/tmp/{filename}'")
        print(
            "\033[92m✔ Module installed.\033[0m\n"
            "\n\033[93m→ Action Required:\033[0m\n"
            "  1. Go to Settings → Security → Encryption & Credentials\n"
            "  2. Select 'Install from SD card'\n"
            "  3. Choose '/sdcard/portswigger.crt'\n"
            "  4. Name it 'portswigger'\n"
            "\033[96m  Waiting 65s for installation...\033[0m"
        )
        for i in range(65, 0, -1):
            print(f"\r\033[96m  {i}s left...\033[0m", end="", flush=True)
            time.sleep(1)
        print("\r\033[96m  Rebooting emulator...\033[0m")
        os.system(f"{ADB} reboot")
        print("\033[92m✔ Setup complete. Emulator rebooting.\033[0m")
    except Exception as e:
        print(f"\033[91m✖ Failed: {e}\033[0m")
    input("\033[96m→ Press Enter to continue...\033[0m")
    os.system('cls' if os.name == 'nt' else 'clear')
