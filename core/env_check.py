import os
import sys
import shutil
import time

from utils.common import clear_screen


def initial_environment_check():
    clear_screen()
    print("\033[96m→ Initializing NoxDroid Environment...\033[0m")
    spinner = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    checks = [
        ("Python Installation", check_python),
        ("Python PATH", check_python_path),
        ("ADB Availability", check_adb)
    ]
    results = []
    for i, (name, chk) in enumerate(checks):
        print(f"\033[96m{name}...\033[0m ", end="", flush=True)
        for _ in range(8):
            sys.stdout.write(f"\r\033[96m{name}... {spinner[i % len(spinner)]}\033[0m")
            sys.stdout.flush()
            time.sleep(0.15)
        ok, det = chk()
        results.append((name, ok, det))
        status = "\033[92m✔\033[0m" if ok else "\033[91m✖\033[0m"
        print(f"\r\033[96m{name}: {status}")
        time.sleep(0.3)

    all_ok = all(ok for _, ok, _ in results)
    print("\n\033[96m→ Check Results:\033[0m")
    for n, ok, det in results:
        s = "\033[92m✔\033[0m" if ok else "\033[91m✖\033[0m"
        print(f"  {s} {n}")
        if not ok:
            print(f"    \033[93m→ {det}\033[0m")

    print(f"\n{ '\033[92m✔ All systems ready!\033[0m' if all_ok else '\033[91m⚠ Fix issues to proceed.\033[0m' }")
    time.sleep(1.5)
    print("\033[96m→ Loading menu...\033[0m")
    time.sleep(1)

def check_python():
    if "Microsoft\\WindowsApps\\python.exe" in sys.executable:
        return False, "Install Python from python.org, not Microsoft Store."
    return True, "Python installed."

def check_python_path():
    if not shutil.which("python"):
        return False, "Add Python to system PATH."
    return True, "Python in PATH."

def check_adb():
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.exists(os.path.join(d, "adb.exe" if os.name == 'nt' else "adb")):
            return True, "ADB found."
    return False, "Add ADB (Nox Player) to PATH."
