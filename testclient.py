import socket
import threading
import os
import queue
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from playsound import playsound

# ---------- Config ----------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
BUFFER_SIZE = 4096

# notification sound files - place these in same folder or change paths
MSG_SOUND = "ding.mp3"
FILE_SOUND = "ping.mp3"
# ----------------------------

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat & File Share (with Progress & Sound)")
        self.root.geometry("720x600")

        # Networking
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = ""
        self.connected = False

        # Thread-safe queue for UI updates from network threads
        self.ui_queue = queue.Queue()

        # Download state
        self.downloading = False
        self.download_expected = None  # dict: { 'unique':..., 'save_path':..., 'size':..., 'received':...}

        # Available files mapping for listbox
        self.available_files = {}  # display_name -> (unique_name, sender_name)

        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # start the UI queue processor
        self.root.after(100, self.process_ui_queue)

        # Start connection flow
        self.ask_and_connect()

    def build_ui(self):
        # Top frame: connection info & status
        top = tk.Frame(self.root)
        top.pack(fill='x', padx=10, pady=6)

        tk.Label(top, text="Server IP:").grid(row=0, column=0, sticky='w')
        self.server_ip_entry = tk.Entry(top, width=15)
        self.server_ip_entry.insert(0, SERVER_HOST)
        self.server_ip_entry.grid(row=0, column=1, padx=(2,10))

        tk.Label(top, text="Port:").grid(row=0, column=2, sticky='w')
        self.port_entry = tk.Entry(top, width=6)
        self.port_entry.insert(0, str(SERVER_PORT))
        self.port_entry.grid(row=0, column=3, padx=(2,10))

        tk.Label(top, text="Name:").grid(row=0, column=4, sticky='w')
        self.name_entry = tk.Entry(top, width=15)
        self.name_entry.grid(row=0, column=5, padx=(2,10))

        self.connect_btn = tk.Button(top, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=6, padx=5)

        # Main frames: chat and files
        main = tk.Frame(self.root)
        main.pack(fill='both', expand=True, padx=10, pady=6)

        # Chat frame
        chat_frame = tk.LabelFrame(main, text="Chat")
        chat_frame.pack(side='left', fill='both', expand=True, padx=(0,8))

        self.chat_display = tk.Text(chat_frame, state='disabled', wrap='word', width=60, height=20)
        self.chat_display.pack(fill='both', expand=True, padx=6, pady=6)

        entry_frame = tk.Frame(chat_frame)
        entry_frame.pack(fill='x', padx=6, pady=(0,6))
        self.msg_entry = tk.Entry(entry_frame)
        self.msg_entry.pack(side='left', fill='x', expand=True, padx=(0,6))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        tk.Button(entry_frame, text="Send", width=10, command=self.send_message).pack(side='left')
        tk.Button(entry_frame, text="Upload File", width=12, command=self.send_file).pack(side='left', padx=(6,0))

        # Files frame
        files_frame = tk.LabelFrame(main, text="Available Files", width=260)
        files_frame.pack(side='right', fill='y')
        files_frame.pack_propagate(False)

        self.files_listbox = tk.Listbox(files_frame, width=40, height=12)
        self.files_listbox.pack(padx=6, pady=6)

        btn_frame = tk.Frame(files_frame)
        btn_frame.pack(fill='x', padx=6, pady=(0,6))
        tk.Button(btn_frame, text="Download", command=self.download_file).pack(side='left', fill='x', expand=True)
        tk.Button(btn_frame, text="Refresh List", command=self.request_file_list).pack(side='left', fill='x', expand=True, padx=(6,0))

        # Progress and status bar
        bottom = tk.Frame(self.root)
        bottom.pack(fill='x', padx=10, pady=(0,8))

        self.progress = ttk.Progressbar(bottom, orient='horizontal', length=400, mode='determinate')
        self.progress.pack(side='left', padx=(0,8), pady=4)

        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = tk.Label(bottom, textvariable=self.status_var, anchor='w')
        self.status_label.pack(side='left', fill='x', expand=True)

    # ----------------- Connection -----------------
    def ask_and_connect(self):
        # initial prompt: user may fill entries or use default then click Connect
        pass  # do nothing; user can press Connect

    def toggle_connection(self):
        if not self.connected:
            self.connect()
        else:
            self.disconnect()

    def connect(self):
        host = self.server_ip_entry.get().strip() or SERVER_HOST
        try:
            port = int(self.port_entry.get().strip())
        except:
            messagebox.showerror("Error", "Invalid port")
            return
        name = self.name_entry.get().strip()
        if not name:
            messagebox.showerror("Error", "Enter your name")
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.sock.send(name.encode('utf-8'))
            self.connected = True
            self.name = name
            self.connect_btn.config(text="Disconnect")
            self.status_var.set(f"Connected as {name}")
            # start receiving thread
            threading.Thread(target=self.receive_loop, daemon=True).start()
            self.display_system("[SYSTEM] Connected to server.")
            # request file list initially
            self.request_file_list()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect: {e}")
            self.connected = False

    def disconnect(self):
        try:
            self.connected = False
            self.sock.close()
        except:
            pass
        self.connect_btn.config(text="Connect")
        self.status_var.set("Disconnected")
        self.display_system("[SYSTEM] Disconnected from server.")

    # ----------------- UI helpers -----------------
    def display(self, text):
        self.chat_display.config(state='normal')
        self.chat_display.insert('end', text + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see('end')

    def display_system(self, text):
        self.display(f"[SYSTEM] {text}")

    def play_sound(self, path):
        # play sound in a background thread to avoid blocking
        def _p():
            try:
                if os.path.exists(path):
                    playsound(path)
            except:
                pass
        threading.Thread(target=_p, daemon=True).start()

    # ----------------- Sending -----------------
    def send_message(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        try:
            self.sock.send(f"TEXT:{msg}".encode('utf-8'))
            self.display(f"You: {msg}")
            self.msg_entry.delete(0, 'end')
        except Exception as e:
            self.display_system(f"Failed to send message: {e}")

    def send_file(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)

        # send header
        try:
            self.progress['value'] = 0
            self.progress['maximum'] = filesize
            self.status_var.set(f"Uploading '{filename}' (0%)")
            self.sock.send(f"FILE:{filename}:{filesize}".encode('utf-8'))

            # send file in a background thread so UI doesn't freeze
            def _upload():
                sent = 0
                try:
                    with open(file_path, 'rb') as f:
                        while True:
                            chunk = f.read(BUFFER_SIZE)
                            if not chunk:
                                break
                            self.sock.send(chunk)
                            sent += len(chunk)
                            # update progress via ui_queue
                            self.ui_queue.put(('upload_progress', sent, filesize, filename))
                    # finished
                    self.ui_queue.put(('upload_done', filename))
                    # request file list refresh
                    time.sleep(0.2)
                    self.request_file_list()
                except Exception as e:
                    self.ui_queue.put(('upload_error', str(e)))
            threading.Thread(target=_upload, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send file: {e}")

    def request_file_list(self):
        # We don't have separate protocol in server for requesting the list in earlier server version.
        # But our server broadcasts FILE_LIST when files change. To force a refresh we can send a TEXT ping.
        # Alternatively if server implements FILE_LIST request you can add DOWNLOAD_LIST request.
        try:
            self.sock.send("TEXT:__REQUEST_FILE_LIST__".encode('utf-8'))
        except:
            pass

    # ----------------- Download -----------------
    def download_file(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return
        sel = self.files_listbox.curselection()
        if not sel:
            messagebox.showwarning("Warning", "Select a file first")
            return
        display_name = self.files_listbox.get(sel[0])
        unique_name, sender_name = self.available_files[display_name]

        save_path = filedialog.asksaveasfilename(title="Save file as", initialfile=display_name.split(' (from')[0])
        if not save_path:
            return

        # Set download expected state; receive thread will handle incoming FILE_DATA for us.
        self.downloading = True
        self.download_expected = {
            'unique': unique_name,
            'save_path': save_path,
            'size': 0,
            'received': 0,
            'filename': display_name.split(' (from')[0]
        }
        self.progress['value'] = 0
        self.status_var.set(f"Downloading '{self.download_expected['filename']}' (0%)")

        try:
            self.sock.send(f"DOWNLOAD:{unique_name}".encode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to request download: {e}")
            self.downloading = False
            self.download_expected = None

    # ----------------- Receiving thread -----------------
    def receive_loop(self):
        while self.connected:
            try:
                data = self.sock.recv(BUFFER_SIZE)
                if not data:
                    break

                # We may receive either UTF-8 header messages or binary file chunks.
                # Try decode first; if decode fails, treat as binary chunk (part of file transfer).
                try:
                    text = data.decode('utf-8')
                except UnicodeDecodeError:
                    text = None

                if text is not None:
                    # Handle various textual protocols
                    if text.startswith("TEXT:"):
                        payload = text[5:]
                        # If special internal request response, server might send file list as TEXT or FILE_LIST
                        if payload.startswith("[SYSTEM]") and "__REQUEST_FILE_LIST__" in payload:
                            # ignore
                            pass
                        else:
                            # normal chat message
                            self.ui_queue.put(('display', payload))
                            # play message sound
                            self.ui_queue.put(('play_sound', MSG_SOUND))
                    elif text.startswith("FILE_LIST:"):
                        # Server sends file list in format: FILE_LIST:unique:orig:sender|unique2:orig2:sender2...
                        file_data = text[10:]
                        self.ui_queue.put(('file_list', file_data))
                    elif text.startswith("FILE_DATA:"):
                        # server will send header "FILE_DATA:filename:size" and then binary chunks follow
                        parts = text.split(":")
                        if len(parts) >= 3:
                            file_name = parts[1]
                            try:
                                file_size = int(parts[2])
                            except:
                                file_size = 0
                        else:
                            file_name = "unknown"
                            file_size = 0

                        # If this client previously requested download, proceed to receive binary chunks
                        if self.downloading and self.download_expected:
                            # update expected size
                            self.download_expected['size'] = file_size
                            # start writing file and read chunks until done
                            save_path = self.download_expected['save_path']
                            received = 0
                            try:
                                with open(save_path, 'wb') as f:
                                    while received < file_size:
                                        chunk = self.sock.recv(BUFFER_SIZE)
                                        if not chunk:
                                            break
                                        f.write(chunk)
                                        received += len(chunk)
                                        # update progress via ui_queue
                                        self.ui_queue.put(('download_progress', received, file_size, file_name))
                                # download complete
                                self.ui_queue.put(('download_done', save_path, file_name))
                            except Exception as e:
                                self.ui_queue.put(('download_error', str(e)))
                            finally:
                                self.downloading = False
                                self.download_expected = None
                        else:
                            # If we did not request but server sent FILE_DATA to us, consume it safely
                            # read and discard file_size bytes (best-effort)
                            try:
                                file_size = int(parts[2])
                            except:
                                file_size = 0
                            received = 0
                            while received < file_size:
                                chunk = self.sock.recv(BUFFER_SIZE)
                                if not chunk:
                                    break
                                received += len(chunk)
                    else:
                        # unknown text message - treat as display
                        self.ui_queue.put(('display', text))
                else:
                    # Binary data outside of FILE_DATA header context - ignore or log
                    # For safety, we put as raw message
                    pass

            except Exception as e:
                # socket issues
                self.ui_queue.put(('display', f"[SYSTEM] Connection lost: {e}"))
                self.connected = False
                break

        # cleanup on exit
        self.ui_queue.put(('display', "[SYSTEM] Disconnected from server"))
        self.connected = False

    # ----------------- UI queue processor -----------------
    def process_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                tag = item[0]
                if tag == 'display':
                    self.display(item[1])
                elif tag == 'file_list':
                    self.update_file_list(item[1])
                elif tag == 'play_sound':
                    self.play_sound(item[1])
                elif tag == 'upload_progress':
                    sent, total, filename = item[1], item[2], item[3]
                    self.progress['maximum'] = total
                    self.progress['value'] = sent
                    pct = int((sent/total)*100) if total else 0
                    self.status_var.set(f"Uploading '{filename}' ({pct}%)")
                elif tag == 'upload_done':
                    filename = item[1]
                    self.progress['value'] = 0
                    self.status_var.set(f"Uploaded '{filename}'")
                    self.display_system(f"You uploaded '{filename}'")
                    self.play_sound(FILE_SOUND)
                elif tag == 'upload_error':
                    err = item[1]
                    self.status_var.set("Upload failed")
                    messagebox.showerror("Upload Error", err)
                elif tag == 'download_progress':
                    rec, total, fname = item[1], item[2], item[3]
                    self.progress['maximum'] = total
                    self.progress['value'] = rec
                    pct = int((rec/total)*100) if total else 0
                    self.status_var.set(f"Downloading '{fname}' ({pct}%)")
                elif tag == 'download_done':
                    path, fname = item[1], item[2]
                    self.progress['value'] = 0
                    self.status_var.set(f"Downloaded '{fname}'")
                    self.display_system(f"Downloaded '{fname}' → {path}")
                    self.play_sound(FILE_SOUND)
                elif tag == 'download_error':
                    err = item[1]
                    self.status_var.set("Download failed")
                    messagebox.showerror("Download Error", err)
                else:
                    # unknown tag
                    pass
        except queue.Empty:
            pass
        # schedule next poll
        self.root.after(100, self.process_ui_queue)

    # ----------------- File list update -----------------
    def update_file_list(self, data):
        # data format: unique:orig:sender|unique2:orig2:sender2...
        self.files_listbox.delete(0, 'end')
        self.available_files.clear()
        if not data:
            return
        parts = data.split("|")
        for entry in parts:
            if not entry:
                continue
            try:
                unique, orig, sender = entry.split(":")
            except ValueError:
                # fallback if server used different format
                continue
            display = f"{orig} (from {sender})"
            self.available_files[display] = (unique, sender)
            self.files_listbox.insert('end', display)

    def on_close(self):
        try:
            self.connected = False
            self.sock.close()
        except:
            pass
        self.root.destroy()


if __name__ == "__main__":
    # Ensure notification sound files exist, otherwise app still runs but no sound
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
