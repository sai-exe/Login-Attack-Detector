import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path


MAX_ATTEMPTS = 5
TIME_WINDOW = 60

DEFAULT_LOG_FILE = Path("data/login_logs.csv")

REQUIRED_COLUMNS = {
    "timestamp",
    "username",
    "ip_address",
    "status",
}


def analyze_logs(log_file=None, max_attempts=None, time_window=None):
    """
    Analyze login records and detect potential brute-force activity.

    Returns login statistics, IP analysis, and security alerts.
    """

    log_file = Path(log_file) if log_file else DEFAULT_LOG_FILE
    if max_attempts is None:
        max_attempts = MAX_ATTEMPTS
    if time_window is None:
        time_window = TIME_WINDOW

    if max_attempts < 1 or time_window < 1:
        raise ValueError("Detection settings must be positive.")

    if not log_file.is_file():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    records = []
    failed_attempts = defaultdict(list)

    successful_attempts = 0
    failed_count = 0

    with log_file.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("The CSV file is empty.")

        reader.fieldnames = [
            name.strip() for name in reader.fieldnames
        ]

        missing = REQUIRED_COLUMNS - set(reader.fieldnames)

        if missing:
            raise ValueError(
                "Missing required columns: " + ", ".join(sorted(missing))
            )

        for line_number, row in enumerate(reader, start=2):
            try:
                timestamp = datetime.strptime(
                    row["timestamp"].strip(),
                    "%Y-%m-%d %H:%M:%S"
                )

                username = row["username"].strip()
                ip = row["ip_address"].strip()
                status = row["status"].strip().upper()

                if not username or not ip:
                    raise ValueError("Username and IP cannot be empty.")

                if status not in {"SUCCESS", "FAILED"}:
                    raise ValueError(
                        "Status must be SUCCESS or FAILED."
                    )

            except (ValueError, AttributeError) as error:
                raise ValueError(
                    f"Invalid data on CSV line {line_number}: {error}"
                ) from error

            record = {
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "username": username,
                "ip_address": ip,
                "status": status,
            }

            records.append(record)

            if status == "SUCCESS":
                successful_attempts += 1
            else:
                failed_count += 1
                failed_attempts[ip].append(timestamp)

    alerts = []

    for ip, timestamps in failed_attempts.items():
        timestamps.sort()

        left = 0
        max_count = 0

        for right in range(len(timestamps)):
            while (
                timestamps[right] - timestamps[left]
            ).total_seconds() > time_window:
                left += 1

            max_count = max(max_count, right - left + 1)

        if max_count >= max_attempts:
            risk_score = min(
                100,
                round((max_count / max_attempts) * 75)
            )

            alerts.append({
                "ip": ip,
                "attempts": max_count,
                "risk_score": risk_score,
                "risk": "HIGH",
                "time_window": time_window,
                "status": "Detected",
            })

   # Analyze risk for every IP address, including successful logins.
    ip_analysis = []
    ip_failed_counts = defaultdict(int)
    ip_success_counts = defaultdict(int)

    for record in records:
        ip = record["ip_address"]

        if record["status"] == "FAILED":
            ip_failed_counts[ip] += 1
        else:
            ip_success_counts[ip] += 1

    for ip in sorted(set(ip_failed_counts) | set(ip_success_counts)):
        total_failed = ip_failed_counts[ip]

        matching_alert = next(
            (alert for alert in alerts if alert["ip"] == ip),
            None
        )

        if matching_alert:
            risk = "HIGH"
            detected = True
        elif total_failed >= 3:
            risk = "MEDIUM"
            detected = False
        else:
            risk = "LOW"
            detected = False

        ip_analysis.append({
            "ip": ip,
            "failed_attempts": total_failed,
            "successful_attempts": ip_success_counts[ip],
            "risk": risk,
            "detected": detected,
        })

    ip_analysis.sort(
        key=lambda item: item["failed_attempts"],
        reverse=True
    )

    return {
        "total_attempts": len(records),
        "failed_attempts": failed_count,
        "successful_attempts": successful_attempts,
        "unique_ips": len({
            record["ip_address"] for record in records
        }),
        "suspicious_ips": len(alerts),
        "alerts": alerts,
        "ip_analysis": ip_analysis,
        "records": records,
        "max_attempts": max_attempts,
        "time_window": time_window,
        "source_file": log_file.name,
    }


if __name__ == "__main__":
    try:
        results = analyze_logs()

        print("\n===== LOGIN ATTACK DETECTOR =====")
        print("Total Attempts:", results["total_attempts"])
        print("Failed Attempts:", results["failed_attempts"])
        print("Successful Attempts:", results["successful_attempts"])
        print("Unique IPs:", results["unique_ips"])
        print("Detected Attacks:", results["suspicious_ips"])

        for alert in results["alerts"]:
            print("\nPOSSIBLE BRUTE-FORCE ATTACK")
            print("IP Address:", alert["ip"])
            print("Attempts:", alert["attempts"])
            print("Risk Score:", alert["risk_score"], "/100")
            print("Risk Level:", alert["risk"])

    except (OSError, ValueError) as error:
        print("Analysis failed:", error)