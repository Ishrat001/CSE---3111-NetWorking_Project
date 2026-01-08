import os
import socket
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit,
    QPushButton, QFileDialog, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import QTimer, QUrl
from PyQt5.QtWidgets import QTextBrowser, QTextEdit


class GroupChatWindow(QWidget):
    def __init__(self, chat_sock, file_sock, username, group_id, group_name):
        super().__init__()

        self.chat_sock = chat_sock     # text only
        self.file_sock = file_sock 
        self.username = username
        self.group_id = group_id
        self.group_name = group_name
        self.is_downloading = False

        self.setWindowTitle(f"Group: {group_name}")

        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        self.chat_area = QTextBrowser()
        self.chat_area.setOpenExternalLinks(False)
        self.chat_area.anchorClicked.connect(self.download_file)


        self.message_box = QTextEdit()
        self.message_box.setFixedHeight(80)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        self.send_btn = QPushButton("Send Message")
        self.file_btn = QPushButton("Send File")

        self.send_btn.setFixedHeight(36)
        self.file_btn.setFixedHeight(36)

        btn_layout.addWidget(self.send_btn)
        btn_layout.addWidget(self.file_btn)

        layout.addWidget(self.chat_area)
        layout.addWidget(self.message_box)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

        self.setStyleSheet("""
            QWidget {
                background-color: #f4f6f8;
                font-family: Segoe UI;
                font-size: 14px;
            }

            QTextBrowser {
                background-color: white;
                border: 1px solid #cfd4da;
                border-radius: 6px;
                padding: 8px;
            }

            QTextEdit {
                background-color: white;
                border: 1px solid #cfd4da;
                border-radius: 6px;
                padding: 8px;
            }

            QTextEdit:focus, QTextBrowser:focus {
                border: 1px solid #4a90e2;
            }

            QPushButton {
                background-color: #4a90e2;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px;
            }

            QPushButton:hover {
                background-color: #357abd;
            }

            QPushButton:pressed {
                background-color: #2d6da3;
            }
        """)

        self.send_btn.clicked.connect(self.send_message)
        self.file_btn.clicked.connect(self.send_file)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.load_messages)
        self.timer.start(1000)  # 1 second
        #self.chat_area.setOpenExternalLinks(False)
        #self.chat_area.anchorClicked.connect(self.download_file)
        self.load_messages()

       

    
    def load_messages(self):
        if self.is_downloading:
            return 
        self.chat_sock.sendall(f"LOAD_GROUP_MESSAGES|{self.group_id}\n".encode())
        #resp = self.sock.recv(8192).decode()
        from network_utils import recv_line
        resp = recv_line(self.chat_sock)

        if not resp.startswith("OK|"):
            return

        if resp.startswith("OK|"):
            msgs = resp.split("|", 1)[1].split("||")
            self.chat_area.clear()
            for m in msgs:
                if "sent file:" in m:
                    # example: [time] user sent file: cat.jpeg|5
                    text, file_id = m.rsplit("|", 1)

                    html = f"""
                    <span>{text}</span>
                    <a href="download:{file_id}"> (Download)</a>
                    """
                    self.chat_area.append(html)
                else:
                    self.chat_area.append(m)

    def send_message(self):
        text = self.message_box.toPlainText().strip()
        if not text:
            return

        msg = f"SEND_GROUP_MESSAGE|{self.group_id}|{text}\n"
        self.chat_sock.sendall(msg.encode())
        self.message_box.clear()
        #self.load_messages()

    def _ui_info(self, msg):
        QMessageBox.information(self, "Info", msg)

    def _ui_error(self, msg):
        QMessageBox.warning(self, "Error", msg)

    def send_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self)
        if not file_path:
            return

        # FileWorker কে host + port + file_path + username + group_id পাঠাও
        self.worker = FileWorker(
            host="localhost",
            port=5001,
            task="upload",
            username=self.username,
            group_id=self.group_id,
            args=file_path
        )

        self.worker.finished.connect(self._ui_info)
        self.worker.error.connect(self._ui_error)
        self.worker.start()
    

    def download_file(self, url: QUrl):
        if not url.toString().startswith("download:"):
            return

        file_id = url.toString().split(":")[1]
        save_path, _ = QFileDialog.getSaveFileName(self, "Save file as")
        if not save_path:
            return

        self.worker = FileWorker(
            host="localhost",   # file server host
            port=5001,          # file server port
            task="download",
            args=(file_id, save_path)       # file_id pass
        )

        self.worker.finished.connect(self._ui_info)
        self.worker.error.connect(self._ui_error)
        self.worker.start()


from PyQt5.QtCore import QThread, pyqtSignal
import socket, os
from PyQt5.QtWidgets import QFileDialog

class FileWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, host, port, task, username=None, group_id=None, args=None):
        super().__init__()
        self.host = host
        self.port = port
        self.task = task
        self.args = args 
        self.username = username
        self.group_id = group_id

    def run(self):
        try:
            sock = socket.socket()
            sock.connect((self.host, self.port))
            self.sock = sock

            if self.task == "upload":
                self.upload_logic()
            elif self.task == "download":
                self.download_logic()

            sock.close()
        except Exception as e:
            self.error.emit(str(e))

    def upload_logic(self):
        file_path = self.args
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)

        header = f"FILE_UPLOAD|{self.group_id}|{self.username}|{filename}|{filesize}\n"
        self.sock.sendall(header.encode())

        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                self.sock.sendall(chunk)
        self.finished.emit(f"Successfully uploaded: {filename}")

    def download_logic(self):
        file_id, save_path = self.args # আর্গুমেন্ট আনপ্যাক করা
        self.sock.sendall(f"DOWNLOAD_GROUP_FILE|{file_id}\n".encode())

        # রেসপন্স লাইন পড়া
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
            if extra: # যদি হেডারের সাথে কিছু ডাটা চলে আসে
                f.write(extra)
                received = len(extra)
            
            while received < filesize:
                chunk = self.sock.recv(min(4096, filesize - received))
                if not chunk: break
                f.write(chunk)
                received += len(chunk)
        
        self.finished.emit(f"Downloaded: {filename}")