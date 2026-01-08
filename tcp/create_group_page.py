from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit,
    QListWidget, QPushButton
)
from PyQt5.QtCore import Qt


class CreateGroupPage(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(40, 40, 40, 40)

        title = QLabel("Create New Group")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #333333;
        """)

        self.group_name = QLineEdit()
        self.group_name.setPlaceholderText("Group Name")

        self.user_list = QListWidget()
        self.user_list.setSelectionMode(QListWidget.MultiSelection)

        self.create_btn = QPushButton("Create & Continue")
        self.create_btn.setFixedHeight(36)

        layout.addWidget(title)
        layout.addWidget(self.group_name)
        layout.addWidget(QLabel("Select Members"))
        layout.addWidget(self.user_list)
        layout.addWidget(self.create_btn)

        self.setLayout(layout)

        # 🎨 SAME GLOBAL STYLE (LOGIN / DASHBOARD / CHAT)
        self.setStyleSheet("""
            QWidget {
                background-color: #f4f6f8;
                font-family: Segoe UI;
                font-size: 14px;
            }

            QLineEdit {
                background-color: white;
                border: 1px solid #cfd4da;
                border-radius: 6px;
                padding: 8px;
            }

            QLineEdit:focus {
                border: 1px solid #4a90e2;
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
