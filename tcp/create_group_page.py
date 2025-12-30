from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit,
    QListWidget, QPushButton
)

class CreateGroupPage(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        self.group_name = QLineEdit()
        self.group_name.setPlaceholderText("Group Name")

        self.user_list = QListWidget()
        self.user_list.setSelectionMode(QListWidget.MultiSelection)

        self.create_btn = QPushButton("Create & Continue")

        layout.addWidget(QLabel("Create New Group"))
        layout.addWidget(self.group_name)
        layout.addWidget(QLabel("Select Members"))
        layout.addWidget(self.user_list)
        layout.addWidget(self.create_btn)

        self.setLayout(layout)

