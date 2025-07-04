def display_banner():
    banner = r"""
     [:: NoxDroid ::]
     (\_/)
    ( •_•)   Android Toolkit
    />🍃    by Mr_ofcodyx
"""
    try:
        from termcolor import colored, cprint
        print(colored(banner, 'green', attrs=['bold']))
    except ImportError:
        print("\033[92m" + banner + "\033[0m")
        print("\033[1;33m[DEBUG] Using ANSI colors (termcolor not installed)\033[0m")

