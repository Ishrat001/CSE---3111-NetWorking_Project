import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QLineEdit, QVBoxLayout, QHBoxLayout, QMessageBox, QSizePolicy
)
from PyQt5.QtCore import Qt
import socket


class WelcomeWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.apply_styles()

    def init_ui(self):
        v = QVBoxLayout()
        v.setSpacing(16)
        v.setContentsMargins(40, 40, 40, 40)

        # Title
        title = QLabel("Welcome to PyChat")
        title.setAlignment(Qt.AlignCenter)
        f = title.font()
        f.setPointSize(20)
        f.setBold(True)
        title.setFont(f)
        v.addWidget(title)

        subtitle = QLabel("Sign in or create a new account")
        subtitle.setAlignment(Qt.AlignCenter)
        v.addWidget(subtitle)

        v.addStretch(1)

        # ---------- Mode buttons ----------
        mode_row = QHBoxLayout()
        self.btn_signin = QPushButton("Sign In")
        self.btn_signup = QPushButton("Sign Up")

        self.btn_signin.clicked.connect(self.show_signin)
        self.btn_signup.clicked.connect(self.show_signup)

        mode_row.addWidget(self.btn_signin)
        mode_row.addWidget(self.btn_signup)
        v.addLayout(mode_row)

        # ---------- Forms container ----------
        self.form = QWidget()
        self.form_layout = QVBoxLayout()
        self.form_layout.setSpacing(10)

        # Name (Sign up only)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Full name")

        # Username
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Username")

        # Password
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Password")
        self.password_edit.setEchoMode(QLineEdit.Password)

        # Confirm password (Sign up only)
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setPlaceholderText("Confirm password")
        self.confirm_edit.setEchoMode(QLineEdit.Password)

        # OK button
        self.ok_btn = QPushButton("OK")
        self.ok_btn.setFixedHeight(36)
        self.ok_btn.clicked.connect(self.on_ok_clicked)

        self.form.setLayout(self.form_layout)
        self.form.setVisible(False)
        v.addWidget(self.form)

        v.addStretch(2)
        self.setLayout(v)

    def apply_styles(self):
            self.setStyleSheet("""
                QWidget {
                    background-color: #f4f6f8;
                    font-family: Segoe UI;
                    font-size: 14px;
                }

                QLabel {
                    color: #333333;
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


    # ---------- UI switching ----------
    def clear_form(self):
        while self.form_layout.count():
            self.form_layout.takeAt(0).widget().setParent(None)

    def show_signin(self):
        self.clear_form()
        self.form_layout.addWidget(QLabel("Sign In"))
        self.form_layout.addWidget(self.username_edit)
        self.form_layout.addWidget(self.password_edit)
        self.form_layout.addWidget(self.ok_btn)
        self.form.setVisible(True)
        self.mode = "signin"

    def show_signup(self):
        self.clear_form()
        self.form_layout.addWidget(QLabel("Sign Up"))
        self.form_layout.addWidget(self.name_edit)
        self.form_layout.addWidget(self.username_edit)
        self.form_layout.addWidget(self.password_edit)
        self.form_layout.addWidget(self.confirm_edit)
        self.form_layout.addWidget(self.ok_btn)
        self.form.setVisible(True)
        self.mode = "signup"

    # ---------- OK button logic ----------
    def on_ok_clicked(self):
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password required")
            return

        if self.mode == "signup":
            name = self.name_edit.text().strip()
            confirm = self.confirm_edit.text().strip()

            if not name:
                QMessageBox.warning(self, "Error", "Name required")
                return

            if password != confirm:
                QMessageBox.warning(self, "Error", "Passwords do not match")
                return

            resp = server_signup(name, username, password)

            if resp.startswith("OK"):
                QMessageBox.information(self, "Signup", "Signup successful")
            else:
                QMessageBox.warning(self, "Signup Failed", resp)


        elif self.mode == "signin":
            username = self.username_edit.text().strip()
            password = self.password_edit.text().strip()
            
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password required")
                return
            
            resp, s = server_login(username, password)
            
            if resp.startswith("OK") and s:  
                from chat_selection_page import DashboardPage
                self.dashboard = DashboardPage(s, username)
                self.dashboard.show()
                self.parent().hide()

            else:
                QMessageBox.warning(self, "Login Failed", str(resp))


def server_signup(full_name, username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", 5000))
    s.sendall(f"SIGNUP|{full_name}|{username}|{password}\n".encode())
    resp = s.recv(1024).decode()
   # s.close()
    return resp


def server_login(username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", 5000))
    s.sendall(f"LOGIN|{username}|{password}\n".encode())
    resp = s.recv(1024).decode()
    # Jodi success hoy, socket return koro
    if resp.startswith("OK"):
        return resp, s
    else:
       # s.close()
        return resp, None



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyChat - Client")
        self.resize(520, 380)
        self.setCentralWidget(WelcomeWidget())


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()