from pathlib import Path


def read_log_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            log_lines = log_file.readlines()
            return log_lines

    except FileNotFoundError:
        print("Error: Log file not found.")
        return []


def find_failed_logins(log_records):
    failed_logins = []

    for line in log_records:
        if "LOGIN_FAILED" in line:
            failed_logins.append(line.strip())

    return failed_logins


def extract_ip_address(log_line):
    parts = log_line.split("ip=", 1)

    if len(parts) == 2:
        return parts[1].strip()

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


def main():
    project_folder = Path(__file__).resolve().parent.parent
    sample_file = project_folder / "sample_logs" / "sample_auth.txt"

    log_records = read_log_file(sample_file)
    failed_records = find_failed_logins(log_records)
    ip_attempt_counts = count_failed_attempts_by_ip(failed_records)
    suspicious_ips = detect_brute_force_attacks(ip_attempt_counts)

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