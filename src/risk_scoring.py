import pandas as pd
from sklearn.ensemble import IsolationForest
from data_preprocessing import preprocess

def calculate_risk():
    raw_data = pd.read_csv("data/logs.csv")
    processed_data = preprocess()

    model = IsolationForest(contamination=0.4)
    model.fit(processed_data)

    predictions = model.predict(processed_data)

    results = []

    for i in range(len(predictions)):
        score = 0

        if raw_data["failed_attempts"][i] >= 5:
            score += 2

        if raw_data["login_time"][i].startswith(("01", "02", "03")):
            score += 2

        if predictions[i] == -1:
            score += 3

        if score >= 5:
            risk = "CRITICAL"
        elif score >= 3:
            risk = "HIGH"
        elif score >= 2:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        results.append(risk)

    raw_data["Risk_Level"] = results

    print("\nFinal Risk Analysis:\n")
    print(raw_data)

    return raw_data