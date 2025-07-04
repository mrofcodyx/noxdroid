from core.env_check import initial_environment_check, check_python, check_adb, check_python_path
from core.banner import display_banner
from core.installer import install_tool
from modules.kitsune import install_kitsune_magisk
from modules.frida_magisk import install_magisk_frida_module
from modules.cert_setup import setup_cert_nox
from modules.frida_tools import frida_tool_options
from modules.mafrida_config import config_mafrida

import os

def display_main_menu():
    while True:
        os.system('cls' if os.name=='nt' else 'clear')
        display_banner()
        print("\n\033[96mMain Menu:\033[0m")
        print("1. Install Kitsune (Magisk)")
        print("2. Install Mafrida Module")
        print("3. Setup Burp Cert (Nox)")
        print("4. Frida Tools")
        print("5. Install CLI Tools (frida, objection...)")
        print("6. Exit")
        choice = input("→ Choose: ")
        if choice == "1":
            install_kitsune_magisk()
        elif choice == "2":
            install_magisk_frida_module()
        elif choice == "3":
            setup_cert_nox()
        elif choice == "4":
            frida_tool_options()
        elif choice == "5":
            tool = input("→ Tool name: ")
            install_tool(tool)
        elif choice == "6":
            print("✔ Exiting.")
            break

if __name__ == "__main__":
    initial_environment_check()
    display_main_menu()