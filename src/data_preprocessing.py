import pandas as pd

def preprocess():
    data = pd.read_csv("data/logs.csv")

    # ✅ Fix column names (remove spaces)
    data.columns = data.columns.str.strip()

    # ✅ Print BEFORE using
    print("\nColumns in CSV:\n", data.columns)

    # Convert login_time → hour
    data["login_hour"] = data["login_time"].apply(lambda x: int(x.split(":")[0]))

    # Encode location
    data["location"] = data["location"].astype("category").cat.codes

    # Select features
    features = data[["login_hour", "failed_attempts", "location"]]

    print("\nProcessed Data:\n")
    print(features)

    return features