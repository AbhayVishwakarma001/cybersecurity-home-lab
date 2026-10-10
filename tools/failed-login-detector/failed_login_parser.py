"""Parse SSH-style authentication logs and flag repeated failed passwords."""
import re
from collections import defaultdict
from pathlib import Path

FAILURE_THRESHOLD = 3  # Flag only when count > 3 (four or more)
LOG_FILE = Path(__file__).with_name("sample_auth.log")
FAILED_LOGIN_PATTERN = re.compile(r"Failed password.*from (\d{1,3}(?:\.\d{1,3}){3})")

def main():
    counts = defaultdict(int)
    with LOG_FILE.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                counts[match.group(1)] += 1
    print("=== Failed Login Summary ===")
    for ip, count in sorted(counts.items()):
        flag = "  <-- FLAGGED (possible brute force)" if count > FAILURE_THRESHOLD else ""
        print(f"{ip}: {count} failed attempts{flag}")

if __name__ == "__main__":
    main()
