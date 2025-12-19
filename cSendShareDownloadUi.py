# =====================
# UI 2: Send/Share/Download Action UI
# =====================


from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QFileDialog, QPushButton, QTextEdit,
)
from PyQt5.QtCore import Qt


class ChatActionUI(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        v = QVBoxLayout()

        title = QLabel("Chat Action Panel")
        title.setAlignment(Qt.AlignCenter)
        f = title.font()
        f.setPointSize(16)
        f.setBold(True)
        title.setFont(f)
        v.addWidget(title)

        # Buttons
        self.btn_send_msg = QPushButton("Send Message")
        self.btn_share_file = QPushButton("Share File")
        self.btn_download_file = QPushButton("Download File")

        v.addWidget(self.btn_send_msg)
        v.addWidget(self.btn_share_file)
        v.addWidget(self.btn_download_file)

        # Text box for send message UI
        self.msg_box = QTextEdit()
        self.msg_box.setPlaceholderText("Type your message here...")
        self.msg_box.setVisible(False)
        v.addWidget(self.msg_box)

        # Action buttons
        self.btn_send_now = QPushButton("Send Now")
        self.btn_send_now.setVisible(False)
        v.addWidget(self.btn_send_now)

        self.setLayout(v)

        # Button Logic
        self.btn_send_msg.clicked.connect(self.show_msg_box)
        self.btn_share_file.clicked.connect(self.pick_share_file)

    def show_msg_box(self):
        self.msg_box.setVisible(True)
        self.btn_send_now.setVisible(True)

    def pick_share_file(self):
        QFileDialog.getOpenFileName(self, "Select File To Share")

if __name__ == "__main__":
    import sys
    from PyQt5.QtWidgets import QApplication

    app = QApplication(sys.argv)

    win = ChatActionUI()
    win.resize(500, 500)
    win.show()
    sys.exit(app.exec_())