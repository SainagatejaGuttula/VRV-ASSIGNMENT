import re
import csv
from collections import Counter

# Constants
LOG_FILE = "sample.log"
CSV_OUTPUT_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Reads the log file and parses lines into structured data."""
    log_entries = []
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>[A-Z]+) (?P<endpoint>/\S*) HTTP/1\.\d" (?P<status>\d+)'
    )

    with open(file_path, "r") as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                log_entries.append(match.groupdict())
    return log_entries

def count_requests_per_ip(log_entries):
    """Counts the number of requests per IP address."""
    ip_count = Counter(entry["ip"] for entry in log_entries)
    return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

def most_frequent_endpoint(log_entries):
    """Finds the most frequently accessed endpoint."""
    endpoint_count = Counter(entry["endpoint"] for entry in log_entries)
    most_common = endpoint_count.most_common(1)
    return most_common[0] if most_common else ("None", 0)

def detect_suspicious_activity(log_entries, threshold=5):
    ip_failed_logins = {}
    for entry in log_entries:
        print(f"Analyzing entry: {entry}")  # Debug print
        if (entry["method"] == "POST" and 
            entry["endpoint"] == "/login" and 
            (entry["status"] == "401" or entry["status"] == "403")):
            ip_address = entry["ip"]
            ip_failed_logins[ip_address] = ip_failed_logins.get(ip_address, 0) + 1
    
    print("Failed login attempts:", ip_failed_logins)  # Debug print
    
    suspicious_ips = {ip: count for ip, count in ip_failed_logins.items() if count >= threshold}
    print("Suspicious IPs:", suspicious_ips)  # Debug print
    
    return suspicious_ips


def save_results_to_csv(ip_requests, most_accessed, suspicious_activities):
    """Saves the analysis results to a CSV file."""
    with open(CSV_OUTPUT_FILE, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        
        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)
        writer.writerow([])

        # Most Accessed Endpoint
        writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
        writer.writerow(most_accessed)
        writer.writerow([])

        # Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activities.items())

def main():
    log_entries = parse_log_file(LOG_FILE)

    # Core functionalities
    ip_requests = count_requests_per_ip(log_entries)
    most_accessed = most_frequent_endpoint(log_entries)
    suspicious_activities = detect_suspicious_activity(log_entries)  # Now passing parsed log entries

    # Display results
    print("Requests per IP:")
    print(f"{'IP Address':<20}{'Request Count'}")
    for ip, count in ip_requests:
        print(f"{ip:<20}{count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts'}")
    for ip, count in suspicious_activities.items():
        print(f"{ip:<20}{count}")
    
    # Save to CSV
    save_results_to_csv(ip_requests, most_accessed, suspicious_activities)
    print(f"\nResults saved to {CSV_OUTPUT_FILE}")

if __name__ == "__main__":
    main()
