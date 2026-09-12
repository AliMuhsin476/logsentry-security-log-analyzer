## CREATED BY ALİ MUHSİN TAYFUN

from pathlib import Path
import re
from datetime import datetime, timedelta


def read_log_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            log_lines = log_file.readlines()
            return log_lines

    except FileNotFoundError:
        print("Error: Log file not found.")
        return []

def detect_log_format(log_records):
    for line in log_records:
        lowercase_line = line.lower()

        if "sshd[" in lowercase_line:
            return "Linux SSH"

        if (
            "login_failed" in lowercase_line
            or "login_success" in lowercase_line
        ):
            return "LogSentry Custom"

    return "Unknown"
def find_failed_logins(log_records):
    failed_logins = []

    failure_indicators = (
        "LOGIN_FAILED",
        "Failed password",
        "authentication failure",
    )

    for line in log_records:
        if any(
            indicator.lower() in line.lower()
            for indicator in failure_indicators
        ):
            failed_logins.append(line.strip())

    return failed_logins


def extract_ip_address(log_line):
    ip_pattern = r"(?:ip=|from\s+)(\d{1,3}(?:\.\d{1,3}){3})"

    match = re.search(
        ip_pattern,
        log_line,
        re.IGNORECASE,
    )

    if match:
        return match.group(1)

    return None
def extract_timestamp(log_line):
    custom_pattern = (
        r"^(\d{4}-\d{2}-\d{2} "
        r"\d{2}:\d{2}:\d{2})"
    )

    custom_match = re.search(custom_pattern, log_line)

    if custom_match:
        timestamp_text = custom_match.group(1)

        return datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S",
        )

    linux_pattern = (
        r"^([A-Z][a-z]{2}\s+"
        r"\d{1,2}\s+"
        r"\d{2}:\d{2}:\d{2})"
    )

    linux_match = re.search(linux_pattern, log_line)

    if linux_match:
        current_year = datetime.now().year
        timestamp_text = linux_match.group(1)

        return datetime.strptime(
            f"{current_year} {timestamp_text}",
            "%Y %b %d %H:%M:%S",
    )

    return None

def count_failed_attempts_by_ip(failed_records):
    ip_counts = {}

    for record in failed_records:
        ip_address = extract_ip_address(record)

        if ip_address is None:
            continue

        if ip_address in ip_counts:
            ip_counts[ip_address] += 1
        else:
            ip_counts[ip_address] = 1

    return ip_counts


def determine_risk_level(attempt_count):
    if attempt_count >= 5:
        return "HIGH"

    elif attempt_count >= 3:
        return "MEDIUM"

    else:
        return "LOW"


def detect_brute_force_attacks(ip_attempt_counts, threshold=5):
    suspicious_ips = []

    for ip_address, attempt_count in ip_attempt_counts.items():
        if attempt_count >= threshold:
            suspicious_ips.append(ip_address)

    return suspicious_ips
def detect_brute_force_in_time_window(
    failed_records,
    threshold=5,
    window_minutes=5,
):
    events_by_ip = {}

    for record in failed_records:
        ip_address = extract_ip_address(record)
        timestamp = extract_timestamp(record)

        if ip_address is None or timestamp is None:
            continue

        if ip_address not in events_by_ip:
            events_by_ip[ip_address] = []

        events_by_ip[ip_address].append(timestamp)

    suspicious_ips = []
    time_window = timedelta(minutes=window_minutes)

    for ip_address, timestamps in events_by_ip.items():
        timestamps.sort()

        for start_index in range(len(timestamps)):
            window_attempts = 0
            start_time = timestamps[start_index]

            for timestamp in timestamps[start_index:]:
                if timestamp - start_time <= time_window:
                    window_attempts += 1
                else:
                    break

            if window_attempts >= threshold:
                suspicious_ips.append(ip_address)
                break

    return suspicious_ips

def main():
    project_folder = Path(__file__).resolve().parent.parent
    sample_file = project_folder / "sample_logs" / "spread_out_attempts.txt"

    log_records = read_log_file(sample_file)
    failed_records = find_failed_logins(log_records)

    print("\nExtracted timestamps:")

    for record in failed_records:
        timestamp = extract_timestamp(record)
        print(timestamp)


    ip_attempt_counts = count_failed_attempts_by_ip(failed_records)
    suspicious_ips = detect_brute_force_in_time_window(
        failed_records,
        threshold=5,
        window_minutes=5,
    )

    print(f"Total log records: {len(log_records)}")
    print(f"Failed login attempts: {len(failed_records)}")
    print("\nFailed login attempts by IP:")

    for ip_address, attempt_count in ip_attempt_counts.items():
        risk_level = determine_risk_level(attempt_count)
        attempt_label = "attempt" if attempt_count == 1 else "attempts"

        print(
            f"{ip_address:<15} : "
            f"{attempt_count:>2} {attempt_label:<8} | "
            f"Risk: {risk_level}"
        )

    print("\nPotential brute-force attacks:")

    if suspicious_ips:
        for ip_address in suspicious_ips:
            print(
                f"[ALERT] Possible brute-force attack detected "
                f"from {ip_address}!"
            )
    else:
        print("No potential brute-force attacks detected.")


if __name__ == "__main__":
    main()