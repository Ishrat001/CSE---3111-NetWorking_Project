#!/usr/bin/env python3
"""
PyQt5 Main Chat UI for the TCP chat client project.

This file implements the second screen you asked for (separate from the welcome UI):
- Buttons: Group Chat, P-to-P Chat, See All Group Msg, See All P2P Msg
- Bottom area: list of currently connected clients (QListWidget)
- Simple dialogs to pick chat partners (using the connected clients list)
- Clear placeholders where to plug in the actual TCP/network code:
    * `connect_to_server(username, host, port)` should perform the real socket connect
    * call `on_connected()` after connection succeeds to populate the clients list
    * call `update_client_list(list_of_usernames)` whenever server sends updated client list

How to use with the welcome UI:
- After the welcome UI collects username and server IP, call `MainChatWindow.start_with_connection(username, host, port)`
  (this will attempt a placeholder connect and open the main UI on success)
- Replace the placeholder `connect_to_server` with your real TCP client logic and make it call
  `window.on_connected()` and `window.update_client_list(...)` on events from server.

Run (for UI testing without network):
- `python PyQt5_chat_main_ui.py` will launch the main UI and prefill a fake client list for demo.

"""

import sys
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QInputDialog,
)
from PyQt5.QtCore import Qt


class MainChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyChat - Main")
        self.resize(700, 450)

        self.username = None
        self.server_host = None
        self.server_port = None
        self.child_windows = []

        self.init_ui()

    def init_ui(self):
        central = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(12)

        # Top label
        self.info_label = QLabel("Not connected")
        self.info_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.info_label)

        # Buttons row
        btn_row = QHBoxLayout()
        self.btn_group = QPushButton("Group Chat")
        self.btn_p2p = QPushButton("P to P Chat")
        self.btn_see_group = QPushButton("See All Group Msg")
        self.btn_see_p2p = QPushButton("See All P2P Msg")

        for b in (self.btn_group, self.btn_p2p, self.btn_see_group, self.btn_see_p2p):
            b.setFixedHeight(40)
            btn_row.addWidget(b)

        main_layout.addLayout(btn_row)

        # Middle area: instructions + selected partners
        self.selection_label = QLabel("Selected partners: (none)")
        main_layout.addWidget(self.selection_label)

        # Connected clients list at the bottom
        bottom_row = QHBoxLayout()
        clients_layout = QVBoxLayout()
        clients_layout.addWidget(QLabel("Connected clients:"))
        self.clients_list = QListWidget()
        self.clients_list.setSelectionMode(QListWidget.MultiSelection)
        clients_layout.addWidget(self.clients_list)

        # Right-side quick actions
        actions_layout = QVBoxLayout()
        actions_layout.addWidget(QLabel("Actions"))
        self.btn_refresh = QPushButton("Refresh list")
        self.btn_refresh.setFixedHeight(36)
        actions_layout.addWidget(self.btn_refresh)
        actions_layout.addStretch(1)

        bottom_row.addLayout(clients_layout, 3)
        bottom_row.addLayout(actions_layout, 1)

        main_layout.addLayout(bottom_row)

        central.setLayout(main_layout)
        self.setCentralWidget(central)

        # Hook up signals
        self.btn_group.clicked.connect(self.on_group_chat)
        self.btn_p2p.clicked.connect(self.on_p2p_chat)
        self.btn_see_group.clicked.connect(self.on_see_group_msgs)
        self.btn_see_p2p.clicked.connect(self.on_see_p2p_msgs)
        self.btn_refresh.clicked.connect(self.on_refresh_clients)

    # ------------------ Public API to integrate network code ------------------
    def start_with_connection(self, username: str, host: str, port: int = 5000):
        """Call this after welcome UI collects username and host.

        Replace the internals with real connect logic. Right now it's a placeholder
        that pretends to connect and populates a fake client list for demo.
        """
        self.username = username
        self.server_host = host
        self.server_port = port
        self.info_label.setText(f"Connecting as '{username}' to {host}:{port}...")

        # TODO: replace the following placeholder with your actual connect code.
        success = self.connect_to_server(username, host, port)
        if success:
            self.on_connected()
        else:
            QMessageBox.critical(self, "Connection failed", "Could not connect to server (placeholder).")

    def connect_to_server(self, username: str, host: str, port: int) -> bool:
        """
        Placeholder function for connecting to the TCP server.

        Replace this with your socket creation / thread / asyncio logic. Return True if
        connection succeeds (then call on_connected()); otherwise return False.
        """
        # Example: start socket, authenticate with username, request client list...
        # For now, simulate success.
        return True

    def on_connected(self):
        """Call this when the real network layer confirms connection to server."""
        self.info_label.setText(f"Connected as '{self.username}' to {self.server_host}:{self.server_port}")
        # For demo, populate a fake client list. The real server would push this list.
        demo_clients = ["alice", "bob", "charlie", "david"]
        if self.username and self.username in demo_clients:
            demo_clients.remove(self.username)
        self.update_client_list(demo_clients)

    def update_client_list(self, client_names):
        """Call this whenever the server sends the current list of connected clients."""
        self.clients_list.clear()
        for name in client_names:
            item = QListWidgetItem(name)
            self.clients_list.addItem(item)

    # ------------------ UI actions (hook into actual logic later) ------------------
    def _get_selected_clients(self):
        return [it.text() for it in self.clients_list.selectedItems()]

    def on_group_chat(self):
        partners = self._get_selected_clients()
        if not partners:
            QMessageBox.information(self, "No partners selected", "Please select at least one client from the bottom list to create a group.")
            return
        self.selection_label.setText(f"Selected partners: {', '.join(partners)}")

        from cSendShareDownloadUi import ChatActionUI
        win = ChatActionUI()
        self.child_windows.append(win)
        win.resize(500, 500)
        win.show()


    def on_p2p_chat(self):
        partners = self._get_selected_clients()
        if len(partners) != 1:
            QMessageBox.information(self, "Select one partner", "Please select exactly one client for p-to-p chat.")
            return
        partner = partners[0]
        self.selection_label.setText(f"Selected partners: {partner}")

        from cSendShareDownloadUi import ChatActionUI
        win = ChatActionUI()
        self.child_windows.append(win)
        win.resize(500, 500)
        win.show()



    def on_see_group_msgs(self):
        from cMessageViewUi import MessageViewerUI
        win = MessageViewerUI("All Group Messages")
        self.child_windows.append(win)
        win.resize(500, 600)
        win.show()


    def on_see_p2p_msgs(self):
        from cMessageViewUi import MessageViewerUI
        win = MessageViewerUI("All P2P Messages")
        self.child_windows.append(win)
        win.resize(500, 600)
        win.show()

        
    def on_refresh_clients(self):
        # Request an updated list from server; placeholder here just shows a message.
        QMessageBox.information(self, "Refresh", "(Placeholder) Would request client list update from server.")


# ------------ Quick demo runner ------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainChatWindow()
    # For demo, open the window and pretend we connected as 'me' to localhost
    w.start_with_connection(username="me", host="localhost", port=5000)
    w.show()
    sys.exit(app.exec_())
