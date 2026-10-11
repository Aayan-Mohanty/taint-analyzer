# EXPECT: command_injection at line 7
import os

def ping():
    host = input("Host: ").strip()
    cmd = f"ping -c 1 {host}"
    os.system(cmd)
