import os
from core.banner import display_banner

SCRIPT_MAP = {
    "1": ("List installed app", None),
    "2": ("Bypass SSL Pinning (SSL-BYE)", "SSL-BYE.js"),
    "3": ("Bypass Root-1 (ROOTER)", "ROOTER.js"),
    "4": ("Bypass SSL + Root (PintooR)", "PintooR.js"),
    "5": ("Bypass Root-2 (natpacket)", "disable-root-detection.js"),
    "6": ("Bypass Root + SSL (0xCD4)", "android-unpinning.js"),
    "7": ("Bypass Root + SSL + Emulator (kaungkhantpy)", "frida-adv.js"),
    "8": ("Bypass Emulator Detection (u0pattern)", "Anti-EmuDetector.js"),
    "9": ("Best unified script (Root + SSL + Frida + Emulator)", "bypass.js"),
    "10": ("Back to main menu", None)
}

def frida_tool_options():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        display_banner()
        print("\n\033[96mFrida Tools:\033[0m\n")
        for key, (desc, _) in SCRIPT_MAP.items():
            print(f"{key}. {desc}")
        choice = input("\n→ Choose: ").strip()

        if choice == "1":
            os.system("frida-ps -Uai")
            input("\n→ Press Enter to continue...")
        elif choice in SCRIPT_MAP and choice != "10":
            pkg = input("→ Package name (e.g. com.example.app): ").strip()
            script = SCRIPT_MAP[choice][1]
            if script:
                script_path = f"./Fripts/{script}"
                cmd = f"frida -U -f {pkg} -l {script_path}"
                os.system(cmd)
                input("\n→ Press Enter to continue...")
        elif choice == "10":
            break
        else:
            print("\n\033[91m✖ Invalid option.\033[0m")
            time.sleep(1)
