import requests

base_url = "http://localhost:3000"
response = requests.get(base_url, timeout=5)

print("HTTP status:", response.status_code)
print("Response length:", len(response.content), "bytes")

# print("Content type:", response.headers.get("Content-Type"))
# print("First 100 characters:", response.text[:100])

search_url = base_url + "/rest/products/search"
r = requests.get(search_url, params={"q": "apple"}, timeout=5)

# print("Requested URL:", r.url)
# print("Status:", r.status_code)
# print("Content type:", r.headers.get("Content-Type"))
# print("First 150 characters:", r.text[:150])

# post_response = requests.post(
#     search_url,
#     data={"q": "apple"},
#     timeout=5
# )
# print("POST status:", post_response.status_code)
# print("POST response length:", len(post_response.content))


# search_terms = ["apple", "banana", "orange"]

# for term in search_terms:
#     print("Search term:", term)

# observation = {
#     "method": "GET",
#     "endpoint": "/rest/products/search",
#     "status_code": r.status_code,
#     "response_length": len(r.content),
#     "content_type": r.headers.get("Content-Type")
# }

# print(observation)
# print("Status:", observation["status_code"])

# records = []

# for term in ["apple", "banana"]:
#     result = requests.get(search_url, params={"q": term}, timeout=5)
#     records.append({"input": term, "status_code": result.status_code, "resposne_length": len(response.content)})

# print(records)

# def get_status(search_word):
#     result = requests.get(search_url, params={"q": search_word}, timeout=5)
#     return result.status_code

# print(get_status("banana"))

# try:
#     test_response = requests.get(base_url, timeout=5)
#     print("Connected. Status:", test_response.status_code)
# except requests.RequestException as error:
#     print("Could not connect:", error)

# marker = "fsct8561-marker-123"
# marker = "<u>fsct8561-test</u>"
# marker_response = requests.get(search_url, params={"q": marker}, timeout=5)

# if marker in marker_response.text:
#     print("Marker appears in the response — investigate its context")
# else:
#     print("Marker was not found in this response")

# normal_input = "apple"
# probe_input = "'"

# normal = requests.get(search_url, params={"q": normal_input}, timeout=5)
# probe = requests.get(search_url, params={"q": probe_input}, timeout=5)

# print("Normal input status:", normal.status_code)
# print("Probe input status:", probe.status_code)

# error_phrase = "SQLITE_ERROR"

# if error_phrase.lower() in probe.text.lower():
#     print("Database-related error text found; manual review required")
# else:
#     print("No matching database error text in this response")

# headers_to_check = ["Content-Security-Policy", "X-Content-Type-Options"]

# for name in headers_to_check:
#     if name in response.headers:
#         print(name, "is present")
#     else:
#         print(name, "is not present; investigate its relevance")

# alerts = []
# seen = set()

# for message in ["Missing CSP", "Missing CSP", "Missing X-Content-Type-Options"]:
#     if message not in seen:
#         seen.add(message)
#         alerts.append(message)

# print(alerts)

import csv

practice_records = [
    {"endpoint": "/", "status": 200},
    {"endpoint": "/example", "status": 404}
]

with open("practice_records.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=["endpoint", "status"])
    writer.writeheader()
    writer.writerows(practice_records)

print("Saved practice_records.csv")