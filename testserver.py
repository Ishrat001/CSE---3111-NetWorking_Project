"""""
import socket
import threading
import os
import time

# Handle a single client
def handle_client(client_socket, clients, client_names):
    client_name = client_socket.recv(1024).decode('utf-8')
    client_names[client_socket] = client_name
    print(f"{client_name} joined the chat")
    broadcast_message(f"{client_name} joined the chat", client_socket, clients, client_names, is_system=True)
    
    while True:
        try:
            header = client_socket.recv(1024).decode('utf-8')
            if not header:
                remove_client(client_socket, clients, client_names)
                break

            # Handle text messages
            if header.startswith("TEXT:"):
                message = header[5:]  # get text after 'TEXT:'
                sender_name = client_names[client_socket]
                print(f"{sender_name}: {message}")
                broadcast_message(f"{sender_name}: {message}", client_socket, clients, client_names)

            # Handle file transfer
            elif header.startswith("FILE:"):
                file_info = header.split(":")
                file_name = file_info[1]
                file_size = int(file_info[2])
                sender_name = client_names[client_socket]

                print(f"Receiving file: {file_name} from {sender_name}")
                broadcast_message(f"{sender_name} is sending a file: {file_name}", None, clients, client_names, is_system=True)

                if not os.path.exists("server_files"):
                    os.makedirs("server_files")

                timestamp = int(time.time())
                safe_sender_name = "".join(c for c in sender_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
                unique_file_name = f"{timestamp}_{safe_sender_name}_{file_name}"
                file_path = os.path.join("server_files", unique_file_name)

                with open(file_path, "wb") as f:
                    bytes_received = 0
                    while bytes_received < file_size:
                        chunk = client_socket.recv(4096)
                        if not chunk:
                            break
                        f.write(chunk)
                        bytes_received += len(chunk)

                print(f"File {file_name} received successfully from {sender_name}")
                broadcast_message(f"{sender_name} sent a file: {file_name}", None, clients, client_names, is_system=True)

                # Notify all clients about the new file
                for client in clients:
                    try:
                        notification = f"FILE_AVAILABLE:{file_name}:{unique_file_name}:{sender_name}"
                        client.send(notification.encode('utf-8'))
                    except:
                        remove_client(client, clients, client_names)

        except Exception as e:
            print(f"Error with client {client_names.get(client_socket, 'Unknown')}: {e}")
            remove_client(client_socket, clients, client_names)
            break


def broadcast_message(message, sender_socket, clients, client_names, is_system=False):
    formatted = f"[SYSTEM] {message}" if is_system else message
    for client in clients:
        if client != sender_socket:
            try:
                client.send(f"TEXT:{formatted}".encode('utf-8'))
            except:
                remove_client(client, clients, client_names)


def remove_client(client_socket, clients, client_names):
    if client_socket in clients:
        name = client_names.get(client_socket, "Unknown")
        clients.remove(client_socket)
        if client_socket in client_names:
            del client_names[client_socket]
        client_socket.close()
        print(f"{name} left the chat")
        broadcast_message(f"{name} left the chat", None, clients, client_names, is_system=True)


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(5)
    print("✅ Server started on port 5555. Waiting for connections...")

    clients = []
    client_names = {}

    while True:
        client_socket, client_address = server.accept()
        print(f"Connection established with {client_address}")
        clients.append(client_socket)
        threading.Thread(target=handle_client, args=(client_socket, clients, client_names), daemon=True).start()


if __name__ == "__main__":
    start_server()
    """""
import socket
import threading
import json
import time
import traceback
import struct
from collections import defaultdict, deque

# ---------- Configuration ----------
HOST = '0.0.0.0'
PORT = 5000
MSS = 1024                     # application payload per application-packet (bytes)
INITIAL_SSTHRESH = 64         # in packets
INITIAL_CWND = 1              # in packets
RTO_INITIAL = 1.0             # seconds (initial retransmission timeout)
KEEPALIVE_INTERVAL = 10       # seconds to check client liveness
MAX_INFLIGHT = 1024
UDP_BUFFER_SIZE = 65507       # Max UDP packet size

# ---------- Data structures ----------
class ClientInfo:
    def __init__(self, username, addr):
        self.username = username
        self.addr = addr  # (ip, port)
        self.lock = threading.Lock()
        self.last_seen = time.time()
        self.rwnd = 64 * MSS  # advertised receiver window (bytes) - clients can override
        self.udp_socket = None  # UDP socket to send to this client

# Packet wrapper
class AppPacket:
    """
    Represent an application-level DATA packet for forwarding:
    header (dict) and payload (bytes).
    """
    def __init__(self, header: dict, payload: bytes):
        self.header = header
        self.payload = payload
        # Mandatory fields for DATA:
        # header['seq'] (int), header['msg_id'] (str), header['payload_len'] (int)

# ---------- Global registries ----------
clients = {}         # username -> ClientInfo
clients_lock = threading.Lock()
groups = defaultdict(set)  # group_name -> set(usernames)
# Each recipient has a Sender object to manage cwnd/acks when server sends to them
senders = {}         # (sender_username, recipient_username, msg_id) -> Sender
senders_lock = threading.Lock()

# Global UDP server socket
udp_socket = None

# ---------- UDP Utility functions ----------
def send_json_over_udp(sock: socket.socket, addr: tuple, header: dict, payload: bytes = None):
    """
    Send JSON header + payload over UDP to specific address.
    We need to add a length prefix to know how much to receive.
    """
    header_bytes = json.dumps(header).encode('utf-8')
    
    # Create packet: [4-byte header length][header][payload]
    if payload is None:
        payload = b''
    
    # Calculate sizes
    header_len = len(header_bytes)
    total_payload_len = len(payload)
    
    # Create the complete packet
    packet = struct.pack('!II', header_len, total_payload_len) + header_bytes + payload
    
    try:
        sock.sendto(packet, addr)
    except Exception as e:
        print(f"Error sending UDP to {addr}: {e}")

def recv_json_from_udp(sock: socket.socket):
    """
    Receive a complete UDP packet and parse header + payload.
    Returns (header, payload, addr)
    """
    try:
        data, addr = sock.recvfrom(UDP_BUFFER_SIZE)
        if len(data) < 8:  # Need at least 8 bytes for the two lengths
            return None, None, addr
        
        # Parse lengths
        header_len, payload_len = struct.unpack('!II', data[:8])
        
        # Extract header and payload
        if len(data) < 8 + header_len + payload_len:
            print(f"Packet too short: expected {8 + header_len + payload_len}, got {len(data)}")
            return None, None, addr
        
        header_bytes = data[8:8 + header_len]
        payload_bytes = data[8 + header_len:8 + header_len + payload_len]
        
        try:
            header = json.loads(header_bytes.decode('utf-8'))
            return header, payload_bytes, addr
        except Exception as e:
            print(f"Failed to parse header: {e}")
            return None, None, addr
    except socket.error as e:
        print(f"Socket error in recv_json_from_udp: {e}")
        return None, None, None

# ---------- Sender (application-level Reno over UDP) ----------
class Sender:
    """
    Manage a send queue and an application-layer TCP-Reno for sending packets
    to a single recipient over UDP.
    """

    def __init__(self, server_sock, recipient_username, recipient_info: ClientInfo):
        """
        server_sock: UDP socket to send packets
        recipient_username: name
        recipient_info: ClientInfo for recipient (addr)
        """
        self.recipient = recipient_username
        self.recipient_info = recipient_info
        self.addr = recipient_info.addr
        self.server_sock = server_sock

        # Reno state
        self.cwnd = INITIAL_CWND
        self.ssthresh = INITIAL_SSTHRESH
        self.MSS = MSS
        self.send_base = None   # lowest unacked seq (int)
        self.next_seq = None    # next seq to send (int)
        self.inflight = {}      # seq -> (AppPacket, send_time, retrans_count)
        self.lock = threading.Lock()

        # ACK tracking
        self.dup_ack_count = 0
        self.last_ack = None

        # Timer
        self.rto = RTO_INITIAL
        self.timer = None
        self.timer_lock = threading.Lock()

        # queue for new packets to send
        self.queue = deque()
        self.queue_cond = threading.Condition()

        # running flag
        self.running = True

        # Start sender thread
        self.worker_thread = threading.Thread(target=self._run_sender_loop, daemon=True)
        self.worker_thread.start()

    def stop(self):
        self.running = False
        with self.queue_cond:
            self.queue_cond.notify_all()
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=1)

    def enqueue_packet(self, app_packet: AppPacket):
        """
        Add an AppPacket to send queue. Packets must have header['seq'] defined.
        """
        with self.queue_cond:
            self.queue.append(app_packet)
            self.queue_cond.notify()

    def _start_timer(self):
        with self.timer_lock:
            if self.timer and self.timer.is_alive():
                return
            self.timer = threading.Timer(self.rto, self._on_timeout)
            self.timer.daemon = True
            self.timer.start()

    def _stop_timer(self):
        with self.timer_lock:
            if self.timer:
                try:
                    self.timer.cancel()
                except:
                    pass
                self.timer = None

    def _on_timeout(self):
        """
        Timeout: treat as packet loss -> perform Reno timeout behavior
        Retransmit send_base packet.
        """
        with self.lock:
            if self.send_base is None:
                return
            print(f"[Sender-> {self.recipient}] TIMEOUT for seq {self.send_base}. cwnd={self.cwnd}, ssthresh={self.ssthresh}")
            # update ssthresh
            self.ssthresh = max(self.cwnd // 2, 2)
            self.cwnd = 1  # enter slow start
            # retransmit send_base
            pkt_info = self.inflight.get(self.send_base)
            if pkt_info:
                packet, _, rcount = pkt_info
                # increase retrans count
                self.inflight[self.send_base] = (packet, time.time(), rcount + 1)
                try:
                    send_json_over_udp(self.server_sock, self.addr, packet.header, packet.payload)
                except Exception as e:
                    print("Error retransmitting:", e)
            # restart timer
            self._start_timer()

    def on_ack_received(self, ack_num: int):
        """
        Called when an ACK is received (ack is cumulative next_expected_seq).
        Implement Reno reactions here.
        """
        with self.lock:
            # if no inflight / send_base not set, ignore
            if self.send_base is None:
                return

            if ack_num > self.send_base:
                # New ACK: advance send_base and remove inflight entries <= ack_num-1
                removed = []
                seqs_to_remove = [s for s in self.inflight.keys() if s < ack_num]
                for s in seqs_to_remove:
                    removed.append(s)
                    self.inflight.pop(s, None)
                old_send_base = self.send_base
                self.send_base = ack_num
                self.dup_ack_count = 0
                self.last_ack = ack_num
                # adjust cwnd
                if self.cwnd < self.ssthresh:
                    # slow start
                    self.cwnd += 1  # increase by 1 packet per ACK (approx)
                else:
                    # congestion avoidance: additive increase roughly 1 packet per RTT
                    # Implemented as increase by 1/cwnd per ACK approximated by incrementing after cwnd ACKs.
                    # For simplicity, increase by 1 when cwnd ACKs accumulate — but here increment by float trick:
                    self.cwnd += 1.0 / max(1, int(self.cwnd))
                    # keep cwnd at least 1
                    if self.cwnd < 1:
                        self.cwnd = 1
                # reset timer if still inflight
                if self.inflight:
                    self._stop_timer()
                    self._start_timer()
                else:
                    self._stop_timer()
                return
            elif ack_num == self.send_base:
                # duplicate ACK
                self.dup_ack_count += 1
                print(f"[Sender-> {self.recipient}] DupACK #{self.dup_ack_count} for {ack_num}")
                if self.dup_ack_count == 3:
                    # fast retransmit
                    print(f"[Sender-> {self.recipient}] 3 DupACKs -> fast retransmit seq {self.send_base}")
                    self.ssthresh = max(int(self.cwnd // 2), 2)
                    self.cwnd = self.ssthresh + 3
                    # retransmit send_base
                    pkt_info = self.inflight.get(self.send_base)
                    if pkt_info:
                        packet, _, rcount = pkt_info
                        self.inflight[self.send_base] = (packet, time.time(), rcount + 1)
                        try:
                            send_json_over_udp(self.server_sock, self.addr, packet.header, packet.payload)
                        except Exception as e:
                            print("Fast retransmit error:", e)
                    # restart timer
                    self._stop_timer()
                    self._start_timer()
                return
            else:
                # ack < send_base; old ack; ignore
                return

    def _run_sender_loop(self):
        """
        Main loop: keep sending new packets from queue while respecting cwnd (packets).
        cwnd measured in packets (not bytes) for simplicity.
        """
        while self.running:
            with self.queue_cond:
                while not self.queue and self.running:
                    self.queue_cond.wait(timeout=0.5)
                if not self.running:
                    break
                # copy available queued packets to a temp list to process
                pending = []
                while self.queue:
                    pending.append(self.queue.popleft())

            # initialize send_base/next_seq if needed
            with self.lock:
                if pending:
                    if self.send_base is None:
                        # first packet's seq
                        self.send_base = pending[0].header['seq']
                        self.next_seq = self.send_base

            # send loop: try to push as many packets as cwnd allows
            # (cwnd may be float due to congestion avoidance; send floor(cwnd))
            while pending:
                with self.lock:
                    allowed = int(max(1, int(self.cwnd))) - len(self.inflight)
                if allowed <= 0:
                    # wait for ACKs
                    time.sleep(0.05)
                    # while waiting, process new ACKs via on_ack_received called from client handler
                    continue

                # send up to `allowed` packets from pending
                to_send = min(allowed, len(pending))
                for _ in range(to_send):
                    pkt = pending.pop(0)
                    seq = pkt.header['seq']
                    try:
                        send_json_over_udp(self.server_sock, self.addr, pkt.header, pkt.payload)
                    except Exception as e:
                        print("Error sending to recipient", self.recipient, e)
                        # Put back packet and break
                        pending.insert(0, pkt)
                        break
                    # record inflight
                    with self.lock:
                        self.inflight[seq] = (pkt, time.time(), 0)
                        # start timer if not running
                        if self.timer is None:
                            self._start_timer()

                # small sleep to yield
                time.sleep(0.001)

            # no more pending from this round; wait a bit
            time.sleep(0.02)

# ---------- Server logic ----------
def client_handler(addr):
    """
    Per-client handler: read UDP packets and perform routing.
    """
    username = None
    try:
        # First expect HELLO to register username
        header, payload, _ = recv_json_from_udp(udp_socket)
        if header is None:
            print("Connection closed before HELLO from", addr)
            return
        
        if header.get('type') != 'HELLO' or not header.get('username'):
            print("First message not HELLO from", addr, "-> closing")
            return
        
        username = header['username']
        with clients_lock:
            if username in clients:
                # username already connected: reject
                print("Username already connected:", username)
                send_json_over_udp(udp_socket, addr, {"type":"ERROR","msg":"username already connected"})
                return
            clients[username] = ClientInfo(username, addr)
        print(f"[{username}] connected from {addr}")

        # Acknowledge
        send_json_over_udp(udp_socket, addr, {"type":"WELCOME","msg":"registered","username":username})

        # main loop
        while True:
            header, payload, client_addr = recv_json_from_udp(udp_socket)
            
            # Check if this packet is from our client
            if client_addr != addr:
                # Wrong client, ignore or handle differently
                continue
                
            if header is None:
                print(f"[{username}] disconnected")
                break
            
            # update last_seen
            with clients_lock:
                if username in clients:
                    clients[username].last_seen = time.time()
            
            htype = header.get('type')
            if htype == 'KEEPALIVE':
                # ignore
                continue
            elif htype == 'MSG':
                # simple small text msg; forward immediately
                mode = header.get('mode','p2p')
                to_list = header.get('to', [])
                # forward to recipients
                for r in to_list:
                    forward_simple_msg(username, r, payload, addr)
            elif htype == 'FILE_START':
                # file transfer initiation: header contains filename, size, msg_id and to list
                to_list = header.get('to', [])
                filename = header.get('filename')
                total_size = header.get('size', 0)
                msg_id = header.get('msg_id')
                print(f"[{username}] FILE_START {msg_id} -> {to_list} filename={filename} size={total_size}")
                # notify recipients optionally
                for r in to_list:
                    notify_file_start(username, r, header, addr)
                # After FILE_START, expect FILE_DATA chunks
                while True:
                    subh, subpayload, _ = recv_json_from_udp(udp_socket)
                    if subh is None:
                        break
                    if subh.get('type') == 'FILE_DATA':
                        # build AppPacket and forward using Sender (app-level Reno)
                        app_packet = AppPacket(subh, subpayload)
                        forward_app_packet_to_recipient(app_packet, subh.get('to', []), username)
                    elif subh.get('type') == 'FILE_END':
                        # forward FILE_END to recipients
                        for r in to_list:
                            forward_simple_header(r, subh, addr)
                        break
                    else:
                        # ignore or handle other types inside file session
                        pass

            elif htype == 'ACK':
                # application-level ACK from this client: likely for server->recipient flows
                ack = header.get('ack')
                msg_id = header.get('msg_id')
                origin = header.get('origin')  # who was original sender? optional
                # dispatch ack to appropriate Sender(s)
                dispatch_ack_to_senders(username, ack, msg_id)
            elif htype == 'JOIN_GROUP':
                group = header.get('group')
                with clients_lock:
                    groups[group].add(username)
                send_json_over_udp(udp_socket, addr, {"type":"JOIN_OK","group":group})
            elif htype == 'LEAVE_GROUP':
                group = header.get('group')
                with clients_lock:
                    groups[group].discard(username)
                send_json_over_udp(udp_socket, addr, {"type":"LEAVE_OK","group":group})
            else:
                print(f"[{username}] Unknown header type: {htype} -> {header}")
    except Exception as e:
        print("Exception in client handler:", e)
        traceback.print_exc()
    finally:
        # clean up
        with clients_lock:
            if username and username in clients:
                del clients[username]
        print(f"[{username}] cleaned up")

# ---------- Forwarding helpers ----------
def forward_simple_msg(from_user, to_user, payload_bytes, from_addr):
    """
    Forward a small message to a single recipient immediately over UDP.
    """
    with clients_lock:
        recipient_info = clients.get(to_user)
    if not recipient_info:
        print("Recipient not connected:", to_user)
        return
    header = {"type":"MSG","from":from_user,"payload_len":len(payload_bytes)}
    try:
        send_json_over_udp(udp_socket, recipient_info.addr, header, payload_bytes)
    except Exception as e:
        print("Error forwarding small MSG:", e)

def forward_simple_header(to_user, header, from_addr):
    """
    Send a header-only control message to recipient over UDP.
    """
    with clients_lock:
        recipient_info = clients.get(to_user)
    if not recipient_info:
        return
    try:
        send_json_over_udp(udp_socket, recipient_info.addr, header)
    except Exception as e:
        print("Error forwarding header:", e)

def notify_file_start(from_user, to_user, header, from_addr):
    """
    Inform recipient of an incoming file — header contains filename, size, msg_id.
    """
    with clients_lock:
        recipient_info = clients.get(to_user)
    if not recipient_info:
        print("notify_file_start: recipient offline", to_user)
        return
    notify_h = {"type":"FILE_START","from":from_user,"msg_id":header.get('msg_id'),
                "filename":header.get('filename'), "size": header.get('size')}
    try:
        send_json_over_udp(udp_socket, recipient_info.addr, notify_h)
    except Exception as e:
        print("notify_file_start error:", e)

def forward_app_packet_to_recipient(app_packet: AppPacket, to_list, origin_username):
    """
    Forward an AppPacket to each recipient using a Sender object (application-level Reno).
    app_packet.header must include 'seq' and 'msg_id'.
    """
    for r in to_list:
        with clients_lock:
            recipient_info = clients.get(r)
        if not recipient_info:
            print("Recipient not connected:", r)
            continue
        # create/get a Sender for (origin, recipient, msg_id)
        key = (origin_username, r, app_packet.header.get('msg_id'))
        with senders_lock:
            s = senders.get(key)
            if s is None:
                s = Sender(udp_socket, r, recipient_info)
                senders[key] = s
        # enqueue the app_packet into s
        s.enqueue_packet(app_packet)

def dispatch_ack_to_senders(from_username, ack_num, msg_id):
    """
    When this client (from_username) sends an ACK (ack_num) for msg_id,
    find all Sender objects that are sending to this client for that msg_id
    and notify them.
    """
    to_notify = []
    with senders_lock:
        for key, s in list(senders.items()):
            # key = (origin, recipient, msg_id)
            origin, recipient, mid = key
            if recipient == from_username and (msg_id is None or mid == msg_id):
                to_notify.append(s)
    for s in to_notify:
        s.on_ack_received(ack_num)

# ---------- Main server receiver ----------
def udp_server_receiver():
    """
    Main UDP receiver thread that listens for incoming packets
    and dispatches them to appropriate client handlers.
    """
    global udp_socket
    
    # Create UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind((HOST, PORT))
    
    print(f"UDP Server listening on {HOST}:{PORT}")
    
    # Client address to username mapping for routing
    addr_to_username = {}
    
    while True:
        try:
            header, payload, addr = recv_json_from_udp(udp_socket)
            if header is None:
                continue
            
            htype = header.get('type')
            
            if htype == 'HELLO':
                # New connection
                username = header.get('username')
                addr_to_username[addr] = username
                # Start client handler in new thread
                t = threading.Thread(target=client_handler, args=(addr,), daemon=True)
                t.start()
            else:
                # Existing client
                username = addr_to_username.get(addr)
                if username:
                    # Update client's last seen
                    with clients_lock:
                        if username in clients:
                            clients[username].last_seen = time.time()
                    
                    # Process the message
                    if htype == 'ACK':
                        ack = header.get('ack')
                        msg_id = header.get('msg_id')
                        dispatch_ack_to_senders(username, ack, msg_id)
                    # Other message types will be handled in client_handler
                    
        except Exception as e:
            print(f"Error in UDP receiver: {e}")
            traceback.print_exc()

# ---------- Maintenance thread ----------
def maintenance_loop():
    while True:
        now = time.time()
        remove_users = []
        with clients_lock:
            for u, cinfo in list(clients.items()):
                if now - cinfo.last_seen > (KEEPALIVE_INTERVAL * 4):
                    remove_users.append(u)
        for u in remove_users:
            print("Removing inactive user:", u)
            with clients_lock:
                info = clients.pop(u, None)
        time.sleep(KEEPALIVE_INTERVAL)

# ---------- Main ----------
def main():
    # Start maintenance thread
    m = threading.Thread(target=maintenance_loop, daemon=True)
    m.start()

    # Start UDP server receiver
    try:
        udp_server_receiver()
    except KeyboardInterrupt:
        print("Shutting down server")
    finally:
        if udp_socket:
            udp_socket.close()

if __name__ == "__main__":
    main()