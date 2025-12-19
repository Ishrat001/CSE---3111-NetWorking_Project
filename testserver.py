import socket
import threading
import os
import time

# Handle a single client
def handle_client(client_socket, clients, client_names):
    client_name = client_socket.recv(1024).decode('utf-8')
    client_names[client_socket] = client_name
    print(f"{client_name} joined the chat")
    broadcast_message(f"{client_name} joined the chat", client_socket, clients, client_names, is_system=True)
    
    while True:
        try:
            header = client_socket.recv(1024).decode('utf-8')
            if not header:
                remove_client(client_socket, clients, client_names)
                break

            # Handle text messages
            if header.startswith("TEXT:"):
                message = header[5:]  # get text after 'TEXT:'
                sender_name = client_names[client_socket]
                print(f"{sender_name}: {message}")
                broadcast_message(f"{sender_name}: {message}", client_socket, clients, client_names)

            # Handle file transfer
            elif header.startswith("FILE:"):
                file_info = header.split(":")
                file_name = file_info[1]
                file_size = int(file_info[2])
                sender_name = client_names[client_socket]

                print(f"Receiving file: {file_name} from {sender_name}")
                broadcast_message(f"{sender_name} is sending a file: {file_name}", None, clients, client_names, is_system=True)

                if not os.path.exists("server_files"):
                    os.makedirs("server_files")

                timestamp = int(time.time())
                safe_sender_name = "".join(c for c in sender_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
                unique_file_name = f"{timestamp}_{safe_sender_name}_{file_name}"
                file_path = os.path.join("server_files", unique_file_name)

                with open(file_path, "wb") as f:
                    bytes_received = 0
                    while bytes_received < file_size:
                        chunk = client_socket.recv(4096)
                        if not chunk:
                            break
                        f.write(chunk)
                        bytes_received += len(chunk)

                print(f"File {file_name} received successfully from {sender_name}")
                broadcast_message(f"{sender_name} sent a file: {file_name}", None, clients, client_names, is_system=True)

                # Notify all clients about the new file
                for client in clients:
                    try:
                        notification = f"FILE_AVAILABLE:{file_name}:{unique_file_name}:{sender_name}"
                        client.send(notification.encode('utf-8'))
                    except:
                        remove_client(client, clients, client_names)

        except Exception as e:
            print(f"Error with client {client_names.get(client_socket, 'Unknown')}: {e}")
            remove_client(client_socket, clients, client_names)
            break


def broadcast_message(message, sender_socket, clients, client_names, is_system=False):
    formatted = f"[SYSTEM] {message}" if is_system else message
    for client in clients:
        if client != sender_socket:
            try:
                client.send(f"TEXT:{formatted}".encode('utf-8'))
            except:
                remove_client(client, clients, client_names)


def remove_client(client_socket, clients, client_names):
    if client_socket in clients:
        name = client_names.get(client_socket, "Unknown")
        clients.remove(client_socket)
        if client_socket in client_names:
            del client_names[client_socket]
        client_socket.close()
        print(f"{name} left the chat")
        broadcast_message(f"{name} left the chat", None, clients, client_names, is_system=True)


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(5)
    print("✅ Server started on port 5555. Waiting for connections...")

    clients = []
    client_names = {}

    while True:
        client_socket, client_address = server.accept()
        print(f"Connection established with {client_address}")
        clients.append(client_socket)
        threading.Thread(target=handle_client, args=(client_socket, clients, client_names), daemon=True).start()


if __name__ == "__main__":
    start_server()
