import os
import re
import csv
from collections import defaultdict

# File paths
LOG_FILE = "sample.log"  # Update this path if the file is in a different location
OUTPUT_CSV = "log_analysis_results.csv"

# Threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(log_file):
    """Parses the log file and extracts relevant information."""
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    with open(log_file, "r") as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            ip_requests[ip] += 1

            # Extract endpoint and status code
            endpoint_match = re.search(r'\"(?:GET|POST|PUT|DELETE) (.+?) HTTP', line)
            status_code_match = re.search(r'\" (\d{3})', line)
            if endpoint_match and status_code_match:
                endpoint = endpoint_match.group(1)
                status_code = status_code_match.group(1)
                endpoint_requests[endpoint] += 1

                # Count failed login attempts
                if status_code == "401" or "Invalid credentials" in line:
                    failed_login_attempts[ip] += 1

    return ip_requests, endpoint_requests, failed_login_attempts

def get_sorted_requests(data):
    """Sorts the request data in descending order of counts."""
    return sorted(data.items(), key=lambda x: x[1], reverse=True)

def save_to_csv(ip_requests, endpoint, endpoint_count, failed_logins):
    """Saves the analysis results to a CSV file."""
    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests:
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([endpoint, endpoint_count])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins:
            writer.writerow([ip, count])

def main():
    # Debugging: Print current working directory
    print("Current working directory:", os.getcwd())
    
    # Ensure the log file exists
    if not os.path.exists(LOG_FILE):
        print(f"Error: Log file '{LOG_FILE}' not found.")
        return

    # Parse the log file
    ip_requests, endpoint_requests, failed_login_attempts = parse_log_file(LOG_FILE)

    # Sort results
    sorted_ip_requests = get_sorted_requests(ip_requests)
    most_accessed_endpoint, most_accessed_count = get_sorted_requests(endpoint_requests)[0]
    suspicious_ips = [(ip, count) for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD]

    # Display results
    print("\nRequests per IP Address:")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips:
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(sorted_ip_requests, most_accessed_endpoint, most_accessed_count, suspicious_ips)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
