import os

LOG_PATH = "log/sample.log"

def audit_logs():
    if not os.path.exists(LOG_PATH):
        print("[-] Log file not found.")
        return

    print("[*] Scanning Mjölnir logs for security flags...")
    with open(LOG_PATH, "r") as f:
        for line in f:
            if "ALERT" in line or "WARN" in line:
                print(line.strip())

if __name__ == "__main__":
    audit_logs()
