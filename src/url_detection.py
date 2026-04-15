import pandas as pd

def detect_phishing():
    data = pd.read_csv("data/logs.csv")

    suspicious_keywords = ["phishing", "malicious", "fake", "attack"]

    results = []

    for url in data["url_accessed"]:
        if any(word in url for word in suspicious_keywords):
            results.append("PHISHING ⚠️")
        else:
            results.append("SAFE")

    data["URL_Status"] = results

    print("\nURL Analysis:\n")
    print(data[["url_accessed", "URL_Status"]])

    return data