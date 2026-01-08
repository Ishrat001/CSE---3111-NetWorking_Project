import os
import socket
import threading
import sqlite3
import hashlib
db_lock = threading.Lock()

# ================== PATH SETUP ==================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

DB_PATH = os.path.join(STORAGE_DIR, "users.db")

HOST = "0.0.0.0"
PORT = 5000

# ================== GLOBAL STATE ==================

online_users = {}        # username -> socket
online_users_lock = threading.Lock()

# ================== DATABASE ==================

def get_db():
    return sqlite3.connect(DB_PATH, check_same_thread=False,  timeout=10)

def init_db():
    db = get_db()

    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_name TEXT UNIQUE NOT NULL,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER,
        username TEXT,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS group_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        sender TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """ )

    db.execute("""
    CREATE TABLE IF NOT EXISTS group_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        sender TEXT,
        file_name TEXT,
        file_path TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS single_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS single_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        file_name TEXT,
        file_path TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db.commit()
    db.close()

# ================== UTIL ==================

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ================== AUTH LOGIC ==================

def handle_signup(db, parts):
    if len(parts) != 4:
        return "ERR|Invalid SIGNUP format"

    _, full_name, username, password = parts
    password_hash = hash_password(password)

    try:
        db.execute(
            "INSERT INTO users (full_name, username, password_hash) VALUES (?, ?, ?)",
            (full_name, username, password_hash)
        )
        db.commit()
        return "OK|Signup successful"
    except sqlite3.IntegrityError:
        return "ERR|Username already exists"

def handle_login(db, parts, conn):
    if len(parts) != 3:
        return "ERR|Invalid LOGIN format"

    _, username, password = parts
    password_hash = hash_password(password)

    cur = db.execute(
        "SELECT id FROM users WHERE username=? AND password_hash=?",
        (username, password_hash)
    )
    row = cur.fetchone()

    if row:
        with online_users_lock:
            online_users[username] = conn
        return "OK|Login successful"
    else:
        return "ERR|Invalid username or password"

# ================== CLIENT THREAD ==================

def client_thread(conn, addr):
    print(f"[+] Connected: {addr}")

    db = get_db()
    logged_in_user = None

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            message = data.decode().strip()
            print(f"[{addr}] {message}")

            parts = message.split("|")
            cmd = parts[0]

            if cmd == "SIGNUP":
                response = handle_signup(db, parts)

            elif cmd == "LOGIN":
                response = handle_login(db, parts, conn)
                if response.startswith("OK"):
                    logged_in_user = parts[1]
                   # online_users[logged_in_user] = conn

            elif cmd == "LIST_ONLINE_USERS":
                with online_users_lock:
                    users = list(online_users.keys())
                response = "OK|" + ",".join(users)


            # ---------- Future commands ----------
            # elif cmd == "MSG_P2P":
            # elif cmd == "GROUP_CREATE":
            # elif cmd == "GROUP_MESSAGE":
            # elif cmd == "FILE_UPLOAD":

            elif cmd == "LIST_GROUPS":
                cur = db.execute("SELECT id, group_name FROM groups")
                groups = [f"{row[0]}:{row[1]}" for row in cur.fetchall()]
                response = "OK|" + ",".join(groups)

            elif cmd == "GROUP_CREATE":
                if not logged_in_user:
                    response = "ERR|Not logged in"

                elif len(parts) != 3:
                    response = "ERR|Invalid GROUP_CREATE format"

                else:
                    group_name = parts[1]
                    members = parts[2].split(",")

                    # creator নিজেও member
                    members.append(logged_in_user)
                    members = sorted(set(members))  # important

                    # -------- duplicate group check --------
                    cur = db.execute("""
                        SELECT g.id, g.group_name
                        FROM groups g
                        JOIN group_members gm ON g.id = gm.group_id
                        GROUP BY g.id
                        HAVING GROUP_CONCAT(gm.username, ',') = ?
                    """, (",".join(members),))

                    existing = cur.fetchone()

                    if existing:
                        response = f"ERR|Group already exists with name {existing[1]}"
                    else:
                        try:
                            cur = db.execute(
                                "INSERT INTO groups (group_name, created_by) VALUES (?, ?)",
                                (group_name, logged_in_user)
                            )
                            group_id = cur.lastrowid

                            for m in members:
                                db.execute(
                                    "INSERT INTO group_members (group_id, username) VALUES (?, ?)",
                                    (group_id, m)
                                )

                            db.commit()
                            response = "OK|Group created"

                        except sqlite3.IntegrityError:
                            response = "ERR|Group name already exists"
            
            elif cmd == "LOAD_GROUP_MESSAGES":
                group_id = parts[1]

                cur = db.execute("""
                    SELECT 'MSG' AS type, sender, message, timestamp, NULL AS file_id
                    FROM group_messages
                    WHERE group_id = ?

                    UNION ALL

                    SELECT 'FILE' AS type, sender, file_name, timestamp, id
                    FROM group_files
                    WHERE group_id = ?

                    ORDER BY timestamp
                """, (group_id, group_id))

                msgs = []
                for msg_type, sender, content, ts, file_id in cur.fetchall():
                    if msg_type == "MSG":
                        msgs.append(f"[{ts}] {sender}: {content}")
                    else:
                        msgs.append(f"[{ts}] {sender} sent file: {content}|{file_id}")

                response = "OK|" + "||".join(msgs)


            elif cmd == "SEND_GROUP_MESSAGE":
                group_id = parts[1]
                message = parts[2]

                with db_lock:
                    db.execute(
                        "INSERT INTO group_messages (group_id, sender, message) VALUES (?, ?, ?)",
                        (group_id, logged_in_user, message)
                    )
                db.commit()

                response = "OK"

            elif cmd == "SEND_SINGLE_MESSAGE":
                receiver = parts[1]
                msg = parts[2]
                with db_lock:
                    db.execute(
                        "INSERT INTO single_messages (sender, receiver, message) VALUES (?, ?, ?)",
                        (logged_in_user, receiver, msg)
                    )
                db.commit()
                response = "OK"

            elif cmd == "LOAD_SINGLE_MESSAGES":
                other = parts[1]
                cur = db.execute(
                    "SELECT sender, message, timestamp FROM single_messages "
                    "WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) "
                    "ORDER BY timestamp",
                    (logged_in_user, other, other, logged_in_user)
                )
                msgs = [f"[{ts}] {s}: {m}" for s, m, ts in cur.fetchall()]
                response = "OK|" + "||".join(msgs)

            else:
                response = "ERR|Unknown command"

            conn.sendall((response + "\n").encode())

    except Exception as e:
        print(f"[!] Error with {addr}: {e}")

    finally:
        # remove user from online_users
        for user, c in list(online_users.items()):
            if c == conn:
                del online_users[user]
        conn.close()
        print(f"[-] Disconnected: {addr}")

# ================== SERVER MAIN ==================

def main():
    init_db()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    print(f" Server running on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        t = threading.Thread(
            target=client_thread,
            args=(conn, addr),
            daemon=True
        )
        t.start()

if __name__ == "__main__":
    main()
