import sqlite3

def create_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()

create_db()