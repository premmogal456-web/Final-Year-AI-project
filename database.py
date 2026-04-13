import mysql.connector


# ---------- DATABASE CONNECTION ----------
def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="threat_detector"
    )


# ---------- INSERT LOG (Used by threat_detector.py) ----------
def insert_log(ip, log, threat):
    conn = get_connection()
    cursor = conn.cursor()

    query = "INSERT INTO logs (ip, log, threat) VALUES (%s, %s, %s)"
    cursor.execute(query, (ip, log, threat))

    conn.commit()
    cursor.close()
    conn.close()


# ---------- REGISTER USER ----------
def register_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()

    query = "INSERT INTO users (username, password) VALUES (%s, %s)"
    cursor.execute(query, (username, password))

    conn.commit()
    cursor.close()
    conn.close()


# ---------- GET USER ----------
def get_user(username):
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username=%s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()
    return user


# ---------- UPDATE PASSWORD ----------
def update_password(username, new_password):
    conn = get_connection()
    cursor = conn.cursor()

    query = "UPDATE users SET password=%s WHERE username=%s"
    cursor.execute(query, (new_password, username))

    conn.commit()
    cursor.close()
    conn.close()


# ---------- DELETE USER ----------
def delete_user(username):
    conn = get_connection()
    cursor = conn.cursor()

    query = "DELETE FROM users WHERE username=%s"
    cursor.execute(query, (username,))

    conn.commit()
    cursor.close()
    conn.close()