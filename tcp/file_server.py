import socket, os, sqlite3, threading

HOST = "0.0.0.0"
PORT = 5001
BASE = "storage/files"
os.makedirs(BASE, exist_ok=True)

DB_PATH = "storage/users.db"

def recv_line(conn):
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(1024)
        if not chunk:
            raise ConnectionError("Disconnected")
        data += chunk
    line, rest = data.split(b"\n", 1)
    return line.decode().strip(), rest

def handle_client(conn):
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        header, _ = recv_line(conn)
        parts = header.split("|")
        cmd = parts[0]

        if cmd == "FILE_UPLOAD":
            gid, sender, filename, filesize = parts[1:]
            filesize = int(filesize)
            path = os.path.join(BASE, filename)

            with open(path, "wb") as f:
                    if _: # যদি হেডার পড়ার সময় কিছু ডাটা চলে আসে
                        f.write(_)
                        rec = len(_)
                    else:
                        rec = 0

                    while rec < filesize:
                        chunk = conn.recv(min(4096, filesize - rec))
                        if not chunk:
                            raise ConnectionError("Client disconnected")
                        f.write(chunk)
                        rec += len(chunk)

            db.execute(
                "INSERT INTO group_files (group_id,sender,file_name,file_path) VALUES (?,?,?,?)",
                (gid, sender, filename, path)
            )
            db.commit()

        elif cmd == "DOWNLOAD_GROUP_FILE":
            fid = parts[1]
            cur = db.execute(
                "SELECT file_path,file_name FROM group_files WHERE id=?", (fid,)
            )
            row = cur.fetchone()
            if not row:
                conn.sendall(b"ERR\n")
                return

            path, name = row
            size = os.path.getsize(path)
            conn.sendall(f"OK|{size}|{name}\n".encode())

            with open(path, "rb") as f:
                while chunk := f.read(4096):
                    conn.sendall(chunk)

        elif cmd == "FILE_UPLOAD_SINGLE":
            sender, receiver, filename, filesize = parts[1:]
            filesize = int(filesize)
            path = os.path.join(BASE, filename)

            try:
                with open(path, "wb") as f:
                    received = 0
                    if _: 
                        f.write(_)
                        received = len(_)

                    while received < filesize:
                        chunk = conn.recv(min(4096, filesize - received))
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)
                db.execute(
                    "INSERT INTO single_files (sender, receiver, file_name, file_path) VALUES (?,?,?,?)",
                    (sender, receiver, filename, path)
                )
                db.commit()
                print(f"File {filename} saved successfully.")

            except Exception as e:
                print(f"Error saving file: {e}")

        elif cmd == "DOWNLOAD_SINGLE_FILE":
            fid = parts[1]
            cur = db.execute(
                "SELECT file_path, file_name FROM single_files WHERE id=?", (fid,)
            )
            row = cur.fetchone()
            if not row:
                conn.sendall(b"ERR\n")
                return

            path, name = row
            size = os.path.getsize(path)
            conn.sendall(f"OK|{size}|{name}\n".encode())

            with open(path, "rb") as f:
                while chunk := f.read(4096):
                    conn.sendall(chunk)


    finally:
        conn.close()

def main():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen()
    print("File server on 5001")

    while True:
        c, _ = s.accept()
        threading.Thread(target=handle_client, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
