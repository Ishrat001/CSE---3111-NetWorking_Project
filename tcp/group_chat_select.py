from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton
from create_group_page import CreateGroupPage
from group_chat_window import GroupChatWindow


class GroupChatSelectPage(QWidget):
    def __init__(self, chat_sock, file_sock, username):
        super().__init__()

        self.chat_sock = chat_sock
        self.file_sock = file_sock
        self.username = username

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Select a Group"))

        self.group_list = QListWidget()
        self.group_list.setSelectionMode(QListWidget.SingleSelection)

        self.join_btn = QPushButton("Join Group")
        self.create_btn = QPushButton("Create New Group")

        layout.addWidget(self.group_list)
        layout.addWidget(self.join_btn)
        layout.addWidget(self.create_btn)

        self.setLayout(layout)

        self.create_btn.clicked.connect(self.open_create_group)
        self.join_btn.clicked.connect(self.join_group)


    def open_create_group(self):
        self.create_page = CreateGroupPage()
        self.create_page.show()

        # server থেকে online users আনো
        self.chat_sock.sendall(b"LIST_ONLINE_USERS\n")
        resp = self.chat_sock.recv(4096).decode().strip()

        if resp.startswith("OK|"):
            users = resp.split("|", 1)[1].split(",")
            users = [u for u in users if u != self.username]
            self.create_page.user_list.addItems(users)

        # create button handle
        self.create_page.create_btn.clicked.connect(self.create_group_submit)

    def join_group(self):
        item = self.group_list.currentItem()
        if not item:
            return

        group_name = item.text()
        group_id = self.group_map[group_name]

        self.chat = GroupChatWindow(self.chat_sock, self.file_sock, self.username, group_id, group_name)
        self.chat.show()
        self.chat.load_messages()


    def create_group_submit(self):
        name = self.create_page.group_name.text().strip()
        items = self.create_page.user_list.selectedItems()

        if not name or not items:
            QMessageBox.warning(self.create_page, "Error", "Name & members required")
            return

        members = ",".join([i.text() for i in items])

        msg = f"GROUP_CREATE|{name}|{members}\n"
        self.chat_sock.sendall(msg.encode())

        resp = self.chat_sock.recv(4096).decode().strip()

        if resp.startswith("ERR|"):
            QMessageBox.warning(self.create_page, "Error", resp)
        else:
            # assume server sends: OK|group_id
            group_id = resp.split("|")[1]

            self.create_page.close()

            self.chat = GroupChatWindow(self, self.chat_sock, self.file_sock, self.username, group_id, name)
            self.chat.show()
            self.chat.load_messages()

