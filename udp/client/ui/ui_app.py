import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QLineEdit, QVBoxLayout, QHBoxLayout, QMessageBox, QSizePolicy
)
from PyQt5.QtCore import Qt

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.network_client import network_client


class WelcomeWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.mode = None
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
        password = self.password_edit.text()

        if self.mode == "signup":
            name = self.name_edit.text().strip()
            confirm = self.confirm_edit.text()

            if not name:
                QMessageBox.warning(self, "Error", "Name required")
                return

            if password != confirm:
                QMessageBox.warning(self, "Error", "Passwords do not match")
                return

            if len(password) < 8:
                QMessageBox.warning(self, "Error", "Password must be at least 8 characters")
                return

            # ✅ ACTUAL SIGNUP CALL
            network_client.send_signup_request(
                name, username, password,
                callback=self.handle_signup_response
            )
            QMessageBox.information(self, "Signup", "Processing registration...")

        elif self.mode == "signin":
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password required")
                return

            # ✅ ACTUAL LOGIN CALL
            network_client.send_login_request(
                username, password,
                callback=self.handle_login_response
            )
            QMessageBox.information(self, "Login", "Authenticating...")
        else:
            QMessageBox.warning(self, "Error", "Please select Sign In or Sign Up")

    def handle_signup_response(self, req_type: str, success: bool, message: str):
        """Called when server responds to signup"""
        if success:
            QMessageBox.information(self, "Signup Success", message)
            # Clear fields
            self.clear_signup_fields()
            # Switch to signin mode
            self.show_signin()
        else:
            QMessageBox.warning(self, "Signup Failed", message)

    def handle_login_response(self, req_type: str, success: bool, message: str):
        """Called when server responds to login"""
        if success:
            QMessageBox.information(self, "Login Success", message)
            # Open main chat window
            self.open_main_window()
        else:
            QMessageBox.warning(self, "Login Failed", message)

    def clear_signup_fields(self):
        """Clear signup form"""
        self.name_edit.clear()
        self.username_edit.clear()
        self.password_edit.clear()
        self.confirm_edit.clear()

    def open_main_window(self):
        """Open the main chat application window"""
        try:
            # Try to import MainWindow
            from client.main_window import MainWindow
            self.main_window = MainWindow()
            self.main_window.show()
            self.window().close()  # Close current window
        except ImportError:
            QMessageBox.warning(self, "Error", 
                              "Main chat window not found.\nCreate client/main_window.py")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Cannot open chat: {str(e)}")


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