import subprocess

def install_tool(tool):
    subprocess.run(['pip', 'install', tool])