import re
import csv
from collections import Counter

# Configuration
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

# Functions
def parse_log_file(log_file):
    with open(log_file, "r") as file:
        lines = file.readlines()
    return lines

def count_requests_by_ip(lines):
    ip_counts = Counter()
    for line in lines:
        ip = line.split()[0]
        ip_counts[ip] += 1
    return ip_counts

def most_accessed_endpoint(lines):
    endpoint_counts = Counter()
    for line in lines:
        match = re.search(r'"(GET|POST|PUT|DELETE) (.*?) HTTP', line)
        if match:
            endpoint = match.group(2)
            endpoint_counts[endpoint] += 1
    return endpoint_counts.most_common(1)[0]  # Most accessed endpoint

def detect_suspicious_activity(lines, threshold):
    failed_attempts = Counter()
    for line in lines:
        if "401" in line or "Invalid credentials" in line:
            ip = line.split()[0]
            failed_attempts[ip] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

def save_to_csv(ip_counts, endpoint, suspicious_ips):
    with open(OUTPUT_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        # Write IP Request Counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow(endpoint)

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main Function
def main():
    lines = parse_log_file(LOG_FILE)

    # Analyze log file
    ip_counts = count_requests_by_ip(lines)
    endpoint = most_accessed_endpoint(lines)
    suspicious_ips = detect_suspicious_activity(lines, FAILED_LOGIN_THRESHOLD)

    # Print results
    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip:15} {count}")

    print("\nMost Accessed Endpoint:")
    print(f"{endpoint[0]} (Accessed {endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:15} {count} failed login attempts")

    # Save results to CSV
    save_to_csv(ip_counts, endpoint, suspicious_ips)

if __name__ == "__main__":
    main()
