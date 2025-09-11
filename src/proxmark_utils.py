import subprocess
import os
import sys
from pathlib import Path

pm3_dirs = []

def run_command(*command):
    try:
        if len(command) == 1:
            cmd = command[0]
        else:
            cmd = list(command)
        result = subprocess.run(cmd, shell=os.name == 'nt', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode in (0, 1):
            return result.stdout.decode("utf-8").strip()
        return None
    except Exception:
        return None

def testCommands(directories, command, arguments=""):
    for directory in directories:
        if directory is None:
            continue
        cmd_list = [directory + "/" + command, arguments]
        print("    Trying:", directory, end=" ... ")
        if run_command(cmd_list):
            return Path(directory)
    return None

def get_proxmark3_location():
    print("Checking program: pm3")
    if os.environ.get('PROXMARK3_DIR'):
        if run_command(os.environ['PROXMARK3_DIR'] + "/bin/pm3", "--help"):
            return Path(os.environ['PROXMARK3_DIR'])
        else:
            print("Warning: PROXMARK3_DIR environment variable points to the wrong folder, ignoring")
    brew_install = run_command(["brew", "--prefix", "proxmark3"])
    if brew_install:
        print("Found installation via Homebrew!")
        return Path(brew_install)
    which_pm3 = run_command(["which", "pm3"])
    if which_pm3:
        which_pm3 = Path(which_pm3)
        pm3_location = which_pm3.parent.parent
        print(f"Found global installation ({pm3_location})!")
        return pm3_location
    pm3_dirs_result = testCommands(pm3_dirs, "bin/pm3", "--help")
    if pm3_dirs_result:
        print(f"Found installation in {pm3_dirs_result}!")
        return pm3_dirs_result
    print("Failed to find working 'pm3' command. You can set the Proxmark3 directory via the 'PROXMARK3_DIR' environment variable.")
    sys.exit(-1)
