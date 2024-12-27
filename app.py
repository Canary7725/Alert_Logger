import re

def parse_logs_and_alert(log_file_path):
    
    suspicious_patterns = {
        "Failed Login Attempt": re.compile(r"failed login", re.IGNORECASE),
        "Unauthorized Access": re.compile(r"unauthorized access", re.IGNORECASE),
        "Malicious Activity Detected": re.compile(r"malicious activity detected", re.IGNORECASE),
    }

    try:
        with open(log_file_path, "r") as log_file:
            for line_number, line in enumerate(log_file, 1):
                for alert_name, pattern in suspicious_patterns.items():
                    if pattern.search(line):
                        print(f"ALERT: {alert_name.upper()} DETECTED AT LINE {line_number}")
                        print(f"-> Log Entry: {line.strip()}")
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
    except Exception as e:
        print(f"An error occurred while processing the log file: {e}")

# Example usage
if __name__ == "__main__":
    log_file_path = input("Enter the path to the log file: ").strip()
    parse_logs_and_alert(log_file_path)
