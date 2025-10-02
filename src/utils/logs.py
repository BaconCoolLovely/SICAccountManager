from datetime import datetime

def log_action(action: str, performed_by: str):
    with open("watcherdog_audit.log", "a") as f:
        timestamp = datetime.utcnow().isoformat()
        f.write(f"[{timestamp}] {performed_by}: {action}\n")
