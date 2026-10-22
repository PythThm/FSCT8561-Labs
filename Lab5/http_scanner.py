import csv
import requests

BASE_URL = "http://localhost:3000"
TIMEOUT = 5

# Define test cases: (endpoint, method, params/data)
test_cases = [
    {"endpoint": "/", "method": "GET", "payload": None},
    {"endpoint": "/rest/products/search", "method": "GET", "payload": {"q": "apple"}},
    {"endpoint": "/rest/products/search", "method": "GET", "payload": {"q": "banana"}},
    {"endpoint": "/rest/products/search", "method": "POST", "payload": {"q": "apple"}} # Unsupported method test
]

results = []

print("[*] Starting HTTP Scanner on", BASE_URL)

for test in test_cases:
    url = BASE_URL + test["endpoint"]
    try:
        if test["method"] == "GET":
            response = requests.get(url, params=test["payload"], timeout=TIMEOUT)
        elif test["method"] == "POST":
            response = requests.post(url, data=test["payload"], timeout=TIMEOUT)
        else:
            continue

        # Collect observations
        record = {
            "endpoint": test["endpoint"],
            "method": test["method"],
            "input_payload": str(test["payload"]),
            "status_code": response.status_code,
            "response_length": len(response.content),
            "content_type": response.headers.get("Content-Type", "N/A"),
            "server": response.headers.get("Server", "N/A")
        }
        results.append(record)
        
        print(f"[{record['method']}] {record['endpoint']} | Payload: {record['input_payload']} | Status: {record['status_code']} | Length: {record['response_length']} bytes")

    except requests.RequestException as error:
        print(f"[!] Connection error for {test['endpoint']}: {error}")
        results.append({
            "endpoint": test["endpoint"],
            "method": test["method"],
            "input_payload": str(test["payload"]),
            "status_code": "ERROR",
            "response_length": 0,
            "content_type": "N/A",
            "server": "N/A"
        })

# Save results to CSV
csv_filename = "http_scan_results.csv"
fieldnames = ["endpoint", "method", "input_payload", "status_code", "response_length", "content_type", "server"]

with open(csv_filename, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

print(f"[*] Scan complete. Results saved to {csv_filename}")