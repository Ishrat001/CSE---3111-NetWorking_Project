import os, socket
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit,
    QPushButton, QFileDialog, QMessageBox, QHBoxLayout, QTextBrowser
)
from PyQt5.QtCore import QTimer, QUrl, QThread, pyqtSignal


class SingleChatWindow(QWidget):
    def __init__(self, chat_sock, username, peer):
        super().__init__()

        self.chat_sock = chat_sock
        self.username = username
        self.peer = peer

        self.setWindowTitle(f"Chat with {peer}")

        layout = QVBoxLayout()

        self.chat_area = QTextBrowser()
        self.chat_area.setOpenExternalLinks(False)
        self.chat_area.anchorClicked.connect(self.download_file)

        self.message_box = QTextEdit()
        self.message_box.setFixedHeight(80)

        btns = QHBoxLayout()
        self.send_btn = QPushButton("Send")
        self.file_btn = QPushButton("Send File")
        btns.addWidget(self.send_btn)
        btns.addWidget(self.file_btn)

        layout.addWidget(self.chat_area)
        layout.addWidget(self.message_box)
        layout.addLayout(btns)
        self.setLayout(layout)

        self.send_btn.clicked.connect(self.send_message)
        self.file_btn.clicked.connect(self.send_file)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.load_messages)
        self.timer.start(1000)

        self.load_messages()

    def load_messages(self):
        self.chat_sock.sendall(
            f"LOAD_SINGLE_MESSAGES|{self.peer}\n".encode()
        )
        from network_utils import recv_line
        resp = recv_line(self.chat_sock)

        if not resp.startswith("OK|"):
            return

        self.chat_area.clear()
        parts = resp.split("|", 1)
        if len(parts) < 2: return

        msgs = parts[1].split("||")
        for m in msgs:
            if "sent file:" in m and "|" in m:
                try:
                    text, fid = m.rsplit("|", 1)
                    self.chat_area.append(
                        f'{text} <a href="download:{fid.strip()}">(Download)</a>'
                    )
                except ValueError:
                    # যদি কোনো কারণে split করতে না পারে তবে সাধারণ টেক্সট হিসেবে দেখাবে
                    self.chat_area.append(f"{m} <a href='download:{m}'>(Download)</a>")
            else:
                self.chat_area.append(m)

    def send_message(self):
        text = self.message_box.toPlainText().strip()
        if not text:
            return
        self.chat_sock.sendall(
            f"SEND_SINGLE_MESSAGE|{self.peer}|{text}\n".encode()
        )
        self.message_box.clear()

    def send_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self)
        if not file_path: return

        # peer=self.peer যোগ করা হয়েছে
        self.worker = FileWorker(
            host="localhost",
            port=5001,
            task="upload",
            username=self.username,
            peer=self.peer, 
            args=file_path
        )

        def on_success(msg):
            # ১. ফাইল আপলোড সফল হলে চ্যাট সার্ভারকে টেক্সট মেসেজ পাঠানো
            filename = os.path.basename(file_path)
            # চ্যাট সার্ভারকে এই ফরম্যাটে ডাটা পাঠান যেন সে এটাকে ফাইল হিসেবে চিনে
            file_info = f"SEND_SINGLE_MESSAGE|{self.peer}|sent file: {filename}\n"
            self.chat_sock.sendall(file_info.encode())
            
            self._ui_info(msg) # সাকসেস মেসেজ দেখানো

        self.worker.finished.connect(on_success)
        self.worker.error.connect(self._ui_error)
        self.worker.start()

    def download_file(self, url: QUrl):
        file_id = url.toString().split(":")[1]
        save_path, _ = QFileDialog.getSaveFileName(self, "Save file as")
        if not save_path: return

        self.worker = FileWorker(
            host="localhost",
            port=5001,
            task="download",
            args=(file_id, save_path)
        )
        self.worker.finished.connect(self._ui_info)
        self.worker.error.connect(self._ui_error)
        self.worker.start()
    
    # ইউজারকে সাধারণ তথ্য বা সাকসেস মেসেজ দেখানোর জন্য
    def _ui_info(self, msg):
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(self, "Success", msg)

    # ইউজারকে কোনো এরর বা ভুলের মেসেজ দেখানোর জন্য
    def _ui_error(self, msg):
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.warning(self, "Error", msg)


from PyQt5.QtCore import QThread, pyqtSignal
import socket, os

class FileWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, host, port, task, username=None, peer=None, args=None):
        super().__init__()
        self.host = host
        self.port = port
        self.task = task
        self.username = username
        self.peer = peer  # Single chat এর জন্য peer লাগে
        self.args = args 

    def run(self):
        try:
            sock = socket.socket()
            sock.connect((self.host, self.port))
            self.sock = sock

            if self.task == "upload":
                self.upload_single_logic()
            elif self.task == "download":
                self.download_single_logic()

            sock.close()
        except Exception as e:
            self.error.emit(str(e))

    def upload_single_logic(self):
        file_path = self.args
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)

        # কমান্ডটি অবশ্যই FILE_UPLOAD_SINGLE হতে হবে
        header = f"FILE_UPLOAD_SINGLE|{self.username}|{self.peer}|{filename}|{filesize}\n"
        self.sock.sendall(header.encode())

        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                self.sock.sendall(chunk)
        self.finished.emit(f"Successfully uploaded: {filename}")

    def download_single_logic(self):
        file_id, save_path = self.args 
        # কমান্ডটি DOWNLOAD_SINGLE_FILE হতে হবে
        self.sock.sendall(f"DOWNLOAD_SINGLE_FILE|{file_id}\n".encode())

        resp = b""
        while b"\n" not in resp:
            chunk = self.sock.recv(1024)
            if not chunk: break
            resp += chunk
        
        if not resp.startswith(b"OK|"):
            raise Exception("File not found on server")

        line, extra = resp.split(b"\n", 1)
        _, filesize, filename = line.decode().split("|")
        filesize = int(filesize)

        received = 0
        with open(save_path, "wb") as f:
            if extra: 
                f.write(extra)
                received = len(extra)
            
            while received < filesize:
                chunk = self.sock.recv(min(4096, filesize - received))
                if not chunk: break
                f.write(chunk)
                received += len(chunk)
        
        self.finished.emit(f"Downloaded: {filename}")