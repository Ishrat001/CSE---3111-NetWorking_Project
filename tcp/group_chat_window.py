from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit,
    QPushButton, QFileDialog, QMessageBox, QHBoxLayout
)

class GroupChatWindow(QWidget):
    def __init__(self, sock, group_id, group_name):
        super().__init__()

        self.sock = sock
        self.group_id = group_id
        self.group_name = group_name

        self.setWindowTitle(f"Group: {group_name}")

        layout = QVBoxLayout()

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        self.message_box = QTextEdit()
        self.message_box.setFixedHeight(80)

        btn_layout = QHBoxLayout()
        self.send_btn = QPushButton("Send Message")
        self.file_btn = QPushButton("Send File")

        btn_layout.addWidget(self.send_btn)
        btn_layout.addWidget(self.file_btn)

        layout.addWidget(self.chat_area)
        layout.addWidget(self.message_box)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

        self.send_btn.clicked.connect(self.send_message)
        self.file_btn.clicked.connect(self.send_file)

    
    def load_messages(self):
        self.sock.sendall(f"LOAD_GROUP_MESSAGES|{self.group_id}\n".encode())
        resp = self.sock.recv(8192).decode()

        if resp.startswith("OK|"):
            msgs = resp.split("|", 1)[1].split("||")
            self.chat_area.clear()
            for m in msgs:
                self.chat_area.append(m)

    def send_message(self):
        text = self.message_box.toPlainText().strip()
        if not text:
            return

        msg = f"SEND_GROUP_MESSAGE|{self.group_id}|{text}\n"
        self.sock.sendall(msg.encode())
        self.message_box.clear()
        self.load_messages()

    def send_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self)
        if not file_path:
            return

        filename = file_path.split("/")[-1]
        msg = f"SEND_GROUP_FILE|{self.group_id}|{filename}\n"
        self.sock.sendall(msg.encode())

        QMessageBox.information(self, "Sent", "File sent (metadata)")

