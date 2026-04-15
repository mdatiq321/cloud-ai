import random
import time
import pandas as pd

def generate_log():
    users = [101,102,103,104,105]
    locations = ["India", "Russia", "China", "Unknown"]

    log = {
        "user_id": random.choice(users),
        "login_time": f"{random.randint(0,23):02d}:{random.randint(0,59):02d}",
        "failed_attempts": random.randint(0,10),
        "location": random.choice(locations),
        "url_accessed": random.choice(["google.com","phishing.com","github.com"])
    }

    return log


if __name__ == "__main__":
    while True:
        log = generate_log()
        print(log)
        time.sleep(2)