# client/main_window.py (temporary placeholder)
from PyQt5.QtWidgets import QMainWindow, QLabel

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Chat Window")
        self.setGeometry(100, 100, 800, 600)
        label = QLabel("Welcome to Chat! (Placeholder)", self)
        label.move(50, 50)