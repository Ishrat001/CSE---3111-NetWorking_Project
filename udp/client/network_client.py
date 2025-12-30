import socket
import json
import struct
import threading
from PyQt5.QtCore import QObject, pyqtSignal


class NetworkClient(QObject):
    signup_result = pyqtSignal(str, bool, str)
    login_result = pyqtSignal(str, bool, str)

    def __init__(self, server_ip="127.0.0.1", server_port=5000):
        super().__init__()
        self.server_addr = (server_ip, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.lock = threading.Lock()

    def send_signup_request(self, full_name, username, password):
        packet = {
            "type": "SIGNUP",
            "full_name": full_name,
            "username": username,
            "password": password
        }
        self._send(packet, "SIGNUP")

    def send_login_request(self, username, password):
        packet = {
            "type": "LOGIN",
            "username": username,
            "password": password
        }
        self._send(packet, "LOGIN")

    def _send(self, packet, req_type):
        def worker():
            try:
                data = json.dumps(packet).encode()
                header = struct.pack("!I", len(data))

                with self.lock:
                    self.sock.sendto(header + data, self.server_addr)
                    self.sock.settimeout(5)
                    resp, _ = self.sock.recvfrom(4096)

                size = struct.unpack("!I", resp[:4])[0]
                body = json.loads(resp[4:4 + size])

                success = body.get("success", False)
                message = body.get("message", "")

                if req_type == "SIGNUP":
                    self.signup_result.emit(req_type, success, message)
                else:
                    self.login_result.emit(req_type, success, message)

            except socket.timeout:
                self._emit_error(req_type, "Server timeout")
            except Exception as e:
                self._emit_error(req_type, str(e))
            finally:
                self.sock.settimeout(None)

        threading.Thread(target=worker, daemon=True).start()

    def _emit_error(self, req_type, msg):
        if req_type == "SIGNUP":
            self.signup_result.emit(req_type, False, msg)
        else:
            self.login_result.emit(req_type, False, msg)


network_client = NetworkClient()
