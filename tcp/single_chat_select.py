from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton

class SingleChatSelectPage(QWidget):
    def __init__(self, chat_sock, username):
        super().__init__()
        self.chat_sock = chat_sock
        self.username = username

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Select an Online User"))

        self.user_list = QListWidget()
        self.user_list.setSelectionMode(QListWidget.SingleSelection)

        self.continue_btn = QPushButton("Continue")

        layout.addWidget(self.user_list)
        layout.addWidget(self.continue_btn)
        self.setLayout(layout)

        self.continue_btn.clicked.connect(self.continue_clicked)

    def load_users(self, users):
        self.user_list.clear()
        for u in users:
            self.user_list.addItem(u)
    
    def continue_clicked(self):
        item = self.user_list.currentItem()
        if not item:
            return

        peer = item.text()

        from single_chat_window import SingleChatWindow
        self.chat_window = SingleChatWindow(self.chat_sock, self.username, peer)
        self.chat_window.show()
