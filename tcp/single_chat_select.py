from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton

class SingleChatSelectPage(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Select an Online User"))

        self.user_list = QListWidget()
        self.user_list.setSelectionMode(QListWidget.SingleSelection)

        self.continue_btn = QPushButton("Continue")

        layout.addWidget(self.user_list)
        layout.addWidget(self.continue_btn)

        self.setLayout(layout)

    def load_users(self, users):
        self.user_list.clear()
        for u in users:
            self.user_list.addItem(u)
