# =====================
# UI 1: Message Viewer UI
# "button 3 or 4 e click korle group or p2p er sob msg dekhbe"
# =====================

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton, QTextEdit,
    QHBoxLayout
)
from PyQt5.QtCore import Qt

class MessageViewerUI(QWidget):
    def __init__(self, title_text="Message Viewer", parent=None):
        super().__init__(parent)
        self.init_ui(title_text)

    def init_ui(self, title_text):
        v = QVBoxLayout()

        title = QLabel(title_text)
        title.setAlignment(Qt.AlignCenter)
        f = title.font()
        f.setPointSize(16)
        f.setBold(True)
        title.setFont(f)
        v.addWidget(title)

        # List of messages (scrollable)
        self.msg_list = QListWidget()
        v.addWidget(self.msg_list)

        # Message reply box (optional)
        reply_label = QLabel("Reply Message:")
        self.reply_box = QTextEdit()
        self.reply_box.setFixedHeight(80)

        v.addWidget(reply_label)
        v.addWidget(self.reply_box)

        # Buttons row
        h = QHBoxLayout()
        self.btn_send_reply = QPushButton("Send Reply")
        self.btn_clear = QPushButton("Clear View")

        h.addWidget(self.btn_send_reply)
        h.addWidget(self.btn_clear)

        v.addLayout(h)
        self.setLayout(v)


if __name__ == "__main__":
    import sys
    from PyQt5.QtWidgets import QApplication

    app = QApplication(sys.argv)

    win = MessageViewerUI("Test Message Viewer")
    win.resize(500, 500)
    win.show()

    sys.exit(app.exec_())
