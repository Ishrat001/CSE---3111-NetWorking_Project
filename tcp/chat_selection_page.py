from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt5.QtCore import Qt
from single_chat_select import SingleChatSelectPage
from group_chat_select import GroupChatSelectPage


class DashboardPage(QWidget):
    def __init__(self, sock, username, parent=None):
        super().__init__(parent)
        self.sock = sock
        self.username = username

        layout = QVBoxLayout()
        layout.setSpacing(20)

        title = QLabel(f"Welcome {username}, Choose Chat Mode")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size:18px; font-weight:bold;")

        self.single_btn = QPushButton("Single Chat")
        self.group_btn = QPushButton("Group Chat")

        self.single_btn.setFixedHeight(40)
        self.group_btn.setFixedHeight(40)

        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(self.single_btn)
        layout.addWidget(self.group_btn)
        layout.addStretch()

        self.setLayout(layout)

        self.single_btn.clicked.connect(self.open_single_chat_select)
        self.group_btn.clicked.connect(self.open_group_chat_select)


    def open_single_chat_select(self):
        self.single_page = SingleChatSelectPage()
        self.single_page.show()

        # server থেকে online users আনো
        self.sock.sendall(b"LIST_ONLINE_USERS\n")
        resp = self.sock.recv(4096).decode().strip()

        if resp.startswith("OK|"):
            users = resp.split("|", 1)[1].split(",")
            users = [u for u in users if u != self.username]  # নিজেকে বাদ
            self.single_page.load_users(users)

    def open_group_chat_select(self):
        self.group_page = GroupChatSelectPage(self.sock, self.username)
        self.group_page.show()

        # server থেকে group list আনো
        self.sock.sendall(b"LIST_GROUPS\n")
        resp = self.sock.recv(4096).decode().strip()

        if resp.startswith("OK|"):
            self.group_page.group_map = {}
            groups = resp.split("|", 1)[1]

            if groups:
                for g in groups.split(","):
                    gid, name = g.split(":")
                    self.group_page.group_map[name] = int(gid)
                    self.group_page.group_list.addItem(name)