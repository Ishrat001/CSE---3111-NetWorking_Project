"""
PyQt5 Welcome UI for your TCP chat client project.

Features implemented here (welcome UI only, as requested):
- Initial welcome screen with app title and "Connect" button
- When "Connect" clicked, shows username and IP input fields + "OK" button
- Basic input validation (non-empty username, simple IP format check)
- A placeholder "Connected" message is shown after pressing OK (no network actions)

How to run:
1. Install PyQt5: pip install PyQt5
2. Run: python PyQt5_chat_welcome_ui.py

This file is intended as the starting point — later we can add the real TCP connect logic
and the subsequent chat UIs (group/p2p, send/share/download, client list, etc.).
"""

import sys
import re
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QLabel,
    QPushButton,
    QLineEdit,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QSizePolicy,
)
from PyQt5.QtCore import Qt

class WelcomeWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        # Main vertical layout
        v = QVBoxLayout()
        v.setSpacing(18)
        v.setContentsMargins(40, 40, 40, 40)

        # Welcome label
        self.title = QLabel("Welcome to PyChat")
        self.title.setAlignment(Qt.AlignCenter)
        font = self.title.font()
        font.setPointSize(20)
        font.setBold(True)
        self.title.setFont(font)
        v.addWidget(self.title)

        # Subtitle
        subtitle = QLabel("A simple TCP chat client (UI prototype)")
        subtitle.setAlignment(Qt.AlignCenter)
        v.addWidget(subtitle)

        # Spacer
        v.addStretch(1)

        # Connect button
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setFixedHeight(40)
        self.connect_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.connect_btn.clicked.connect(self.on_connect_clicked)
        v.addWidget(self.connect_btn)

        # Container for the connection form (hidden initially)
        self.form = QWidget()
        form_layout = QVBoxLayout()
        form_layout.setSpacing(10)

        # Username
        un_layout = QHBoxLayout()
        un_label = QLabel("User name:")
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Enter your display name")
        un_layout.addWidget(un_label)
        un_layout.addWidget(self.username_edit)
        form_layout.addLayout(un_layout)

        # IP
        ip_layout = QHBoxLayout()
        ip_label = QLabel("Server IP:")
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("e.g. 192.168.1.10 or localhost")
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_edit)
        form_layout.addLayout(ip_layout)

        # OK button
        ok_btn = QPushButton("OK, connect")
        ok_btn.setFixedHeight(36)
        ok_btn.clicked.connect(self.on_ok_clicked)
        form_layout.addWidget(ok_btn)

        self.form.setLayout(form_layout)
        self.form.setVisible(False)
        v.addWidget(self.form)

        # Spacer bottom
        v.addStretch(2)

        self.setLayout(v)

    def on_connect_clicked(self):
        # Reveal the form fields when user clicks Connect
        self.form.setVisible(True)
        self.username_edit.setFocus()

    def on_ok_clicked(self):
        username = self.username_edit.text().strip()
        ip = self.ip_edit.text().strip()

        if not username:
            QMessageBox.warning(self, "Validation error", "Please enter a user name.")
            self.username_edit.setFocus()
            return

        if not ip:
            QMessageBox.warning(self, "Validation error", "Please enter server IP or hostname.")
            self.ip_edit.setFocus()
            return

        if not self._is_valid_ip_or_host(ip):
            QMessageBox.warning(self, "Validation error", "Please enter a valid IP or hostname (e.g. 192.168.1.10 or localhost).")
            self.ip_edit.setFocus()
            return

        # ---- NEW CODE: Launch Main UI ----
        from cChatMainUi import MainChatWindow

        self.main_window = MainChatWindow()
        self.main_window.start_with_connection(username, ip, 5000)
        self.main_window.show()

    def _is_valid_ip_or_host(self, value: str) -> bool:
        # Simple checks: allow 'localhost', hostname-ish strings, or IPv4
        if value.lower() == "localhost":
            return True
        # IPv4 basic pattern
        ipv4_re = r"^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$"
        if re.match(ipv4_re, value):
            return True
        # hostname: letters, digits, dash, dot
        host_re = r"^[a-zA-Z0-9\-\.]{1,253}$"
        return bool(re.match(host_re, value))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyChat - Client")
        self.resize(520, 360)
        self.welcome = WelcomeWidget()
        self.setCentralWidget(self.welcome)


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
