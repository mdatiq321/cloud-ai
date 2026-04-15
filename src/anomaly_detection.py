from sklearn.ensemble import IsolationForest
from data_preprocessing import preprocess

def detect_anomalies():
    data = preprocess()

    model = IsolationForest(contamination=0.4)
    model.fit(data)

    predictions = model.predict(data)

    print("\nPredictions (1 = Normal, -1 = Suspicious):\n")
    print(predictions)

    return predictions