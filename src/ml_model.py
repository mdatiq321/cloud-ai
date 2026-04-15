import pandas as pd
from sklearn.ensemble import IsolationForest

# ---------------- TRAIN MODEL ----------------
def train_model():
    # sample training data (normal behavior)
    data = {
        "event_length": [5, 6, 7, 5, 6, 7, 6, 5],
        "hour": [10, 11, 12, 13, 14, 15, 16, 17]
    }

    df = pd.DataFrame(data)

    model = IsolationForest(contamination=0.2)
    model.fit(df)

    return model

# ---------------- PREDICT ----------------
def predict_risk(event_name, time_str):
    model = train_model()

    # extract features
    event_length = len(event_name)

    hour = int(time_str.split(" ")[1].split(":")[0]) if " " in time_str else 12

    test = pd.DataFrame([[event_length, hour]], columns=["event_length", "hour"])

    prediction = model.predict(test)

    # -1 = anomaly
    if prediction[0] == -1:
        return "CRITICAL"
    else:
        return "LOW"