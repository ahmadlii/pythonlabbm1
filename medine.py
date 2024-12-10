import re
import json
import csv
from collections import defaultdict

log_data = """
192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] "GET /home HTTP/1.1" 200 3020
"""

threat_data = [
    {"IP": "192.168.1.11", "Description": "Suspicious activity detected"},
    {"IP": "10.0.0.50", "Description": "Known malicious IP"},
    {"IP": "172.16.0.5", "Description": "Brute-force attack reported"}
]

log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"POST /login HTTP/1.1" (?P<status>\d+)'

failed_attempts = defaultdict(int)

for line in log_data.splitlines():
    match = re.search(log_pattern, line)
    if match:
        ip = match.group("ip")
        status = int(match.group("status"))
        if status == 401:  
            failed_attempts[ip] += 1

high_risk_ips = {ip: count for ip, count in failed_attempts.items() if count > 5}

threat_ips = {entry["IP"]: entry["Description"] for entry in threat_data if entry["IP"] in failed_attempts}

combined_data = []
for ip, count in failed_attempts.items():
    data = {"IP": ip, "Failed Attempts": count}
    if ip in threat_ips:
        data["Threat Description"] = threat_ips[ip]
    combined_data.append(data)

with open("log_analysis.txt", "w") as text_file:
    for ip, count in failed_attempts.items():
        text_file.write(f"{ip}: {count} failed attempts\n")


csv_columns = ['IP', 'Date', 'HTTP Method', 'Failed Attempts']

with open("log_analysis.csv", "w", newline='') as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
    writer.writeheader()
    for line in log_data.splitlines():
        match = re.search(log_pattern, line)
        if match:
            ip = match.group("ip")
            date = re.search(r'\[(.*?)\]', line).group(1)
            http_method = re.search(r'"(.*?) HTTP/1.1"', line).group(1)
            status = int(match.group("status"))
            failed_attempts_count = failed_attempts[ip]
            writer.writerow({'IP': ip, 'Date': date, 'HTTP Method': http_method, 'Failed Attempts': failed_attempts_count})

with open("failed_logins.json", "w") as json_file:
    json.dump(high_risk_ips, json_file, indent=4)

with open("threat_ips.json", "w") as json_file:
    json.dump(threat_ips, json_file, indent=4)

with open("combined_security_data.json", "w") as json_file:
    json.dump(combined_data, json_file, indent=4)

print("Analiz tamamlandı. Nəticələr fayllara yazıldı:")
print("- log_analysis.txt")
print("- log_analysis.csv")
print("- failed_logins.json")
print("- threat_ips.json")
print("- combined_security_data.json")

