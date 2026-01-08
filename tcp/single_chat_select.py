from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton
from PyQt5.QtCore import Qt


class SingleChatSelectPage(QWidget):
    def __init__(self, chat_sock, username):
        super().__init__()
        self.chat_sock = chat_sock
        self.username = username

        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(40, 40, 40, 40)

        title = QLabel("Select an Online User")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #333333;
        """)

        self.user_list = QListWidget()
        self.user_list.setSelectionMode(QListWidget.SingleSelection)

        self.continue_btn = QPushButton("Continue")
        self.continue_btn.setFixedHeight(36)

        layout.addWidget(title)
        layout.addWidget(self.user_list)
        layout.addWidget(self.continue_btn)
        self.setLayout(layout)

        # 🎨 SAME STYLE AS LOGIN / DASHBOARD / CHAT
        self.setStyleSheet("""
            QWidget {
                background-color: #f4f6f8;
                font-family: Segoe UI;
                font-size: 14px;
            }

            QListWidget {
                background-color: white;
                border: 1px solid #cfd4da;
                border-radius: 6px;
                padding: 4px;
            }

            QListWidget::item {
                padding: 8px;
            }

            QListWidget::item:selected {
                background-color: #4a90e2;
                color: white;
                border-radius: 4px;
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
