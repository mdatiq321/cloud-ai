import pandas as pd
from risk_scoring import calculate_risk
from url_detection import detect_phishing

def generate_report():
    # Get results
    risk_data = calculate_risk()
    url_data = detect_phishing()

    # Merge both results
    final_data = risk_data.copy()
    final_data["URL_Status"] = url_data["URL_Status"]

    # Save to CSV
    final_data.to_csv("outputs/final_report.csv", index=False)

    print("\n✅ Final Report Generated: outputs/final_report.csv")

    return final_data