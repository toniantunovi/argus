"""Database models."""
import sqlite3

def create_user(name, email, role="user"):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO users (name, email, role) VALUES ('{name}', '{email}', '{role}')")
    conn.commit()
    conn.close()

def update_balance(user_id, amount):
    """Financial: no validation on negative amounts."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"UPDATE accounts SET balance = balance + {amount} WHERE user_id = {user_id}")
    conn.commit()
    conn.close()

def transfer(from_id, to_id, amount):
    """Financial: no transaction isolation, race condition possible."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT balance FROM accounts WHERE user_id = {from_id}")
    balance = cursor.fetchone()[0]
    if balance >= amount:
        cursor.execute(f"UPDATE accounts SET balance = balance - {amount} WHERE user_id = {from_id}")
        cursor.execute(f"UPDATE accounts SET balance = balance + {amount} WHERE user_id = {to_id}")
    conn.commit()
    conn.close()
