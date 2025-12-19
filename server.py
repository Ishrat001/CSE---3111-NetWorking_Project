#!/usr/bin/env python3
"""
server.py

Multi-threaded TCP server that implements an application-layer TCP-Reno-style
congestion control for forwarding application DATA packets (used for file chunks
or message chunks). The server acts as a relay: when it receives DATA from a
sender for some recipient(s), it forwards the DATA to each recipient using a
per-recipient Sender object that enforces cwnd/ssthresh/dupACK/timeout logic.

Notes:
- This is an application-level reliability & congestion-control layer built ON TOP
  of OS TCP sockets (for simplicity of connection handling). Clients must speak
  the matching application protocol (send HELLO, send DATA with seq numbers, send
  ACKs back when they receive DATA).
- The in-line protocol uses newline-separated JSON headers followed by binary payload
  whose length is specified in the header field `payload_len`.
- The server keeps everything in memory (no persistent DB).
"""

import socket
import threading
import json
import time
import traceback
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

# ---------- Data structures ----------
class ClientInfo:
    def __init__(self, username, conn, addr):
        self.username = username
        self.conn = conn
        self.addr = addr
        self.lock = threading.Lock()
        self.last_seen = time.time()
        self.rwnd = 64 * MSS  # advertised receiver window (bytes) - clients can override

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
senders = {}         # (sender_username, recipient_username, msg_id) -> Sender  (or keyed by (recipient, msg_id) for server->recipient flows)
senders_lock = threading.Lock()

# ---------- Utility functions ----------
def send_json_over_socket(conn: socket.socket, header: dict, payload: bytes = None):
    """
    Writes a JSON header + newline, then payload bytes if present.
    The receiver reads a line and then reads payload_len bytes from socket.
    """
    header_bytes = json.dumps(header).encode('utf-8') + b'\n'
    with threading.Lock():
        conn.sendall(header_bytes)
        if payload:
            conn.sendall(payload)

def recv_json_header(conn: socket.socket):
    """
    Read one JSON header line (terminated by newline). Returns dict.
    If connection closed, return None.
    """
    # Read until newline
    data = b''
    while True:
        try:
            ch = conn.recv(1)
        except ConnectionResetError:
            return None
        if not ch:
            return None
        if ch == b'\n':
            break
        data += ch
        # protective bound
        if len(data) > 65536:
            raise RuntimeError("Header too large")
    try:
        header = json.loads(data.decode('utf-8'))
        return header
    except Exception as e:
        print("Failed parsing header:", e, data)
        return None

def recv_exact(conn: socket.socket, size: int):
    """
    Read exactly size bytes from socket (or return None if connection closed).
    """
    buf = b''
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

# ---------- Sender (application-level Reno) ----------
class Sender:
    """
    Manage a send queue and an application-layer TCP-Reno for sending packets
    to a single recipient over the recipient's TCP connection.

    This Sender is used when the server must forward application DATA packets
    (e.g., file chunks) to a target client. We generate per-packet sequence numbers
    (seq is part of header provided by origin) and manage retransmissions and cwnd.

    For simplicity, cwnd and ssthresh are measured in packets (not bytes).
    """

    def __init__(self, server_sock_conn, recipient_username, recipient_info: ClientInfo):
        """
        server_sock_conn: not used directly here (we use recipient_info.conn),
        recipient_username: name
        recipient_info: ClientInfo for recipient (conn, addr)
        """
        self.recipient = recipient_username
        self.recipient_info = recipient_info
        self.conn = recipient_info.conn

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
                    send_json_over_socket(self.conn, packet.header, packet.payload)
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
                            send_json_over_socket(self.conn, packet.header, packet.payload)
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
                        send_json_over_socket(self.conn, pkt.header, pkt.payload)
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
def client_handler(conn: socket.socket, addr):
    """
    Per-client thread: read headers, payloads, and perform routing.
    """
    username = None
    try:
        # First expect HELLO to register username
        header = recv_json_header(conn)
        if header is None:
            print("Connection closed before HELLO from", addr)
            conn.close()
            return
        if header.get('type') != 'HELLO' or not header.get('username'):
            print("First message not HELLO from", addr, "-> closing")
            conn.close()
            return
        username = header['username']
        with clients_lock:
            if username in clients:
                # username already connected: reject
                print("Username already connected:", username)
                send_json_over_socket(conn, {"type":"ERROR","msg":"username already connected"})
                conn.close()
                return
            clients[username] = ClientInfo(username, conn, addr)
        print(f"[{username}] connected from {addr}")

        # Acknowledge
        send_json_over_socket(conn, {"type":"WELCOME","msg":"registered","username":username})

        # main loop
        while True:
            header = recv_json_header(conn)
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
                text_len = header.get('payload_len', 0)
                payload = b''
                if text_len:
                    payload = recv_exact(conn, text_len)
                    if payload is None:
                        break
                # forward to recipients
                for r in to_list:
                    forward_simple_msg(username, r, payload)
            elif htype == 'FILE_START':
                # file transfer initiation: header contains filename, size, msg_id and to list
                to_list = header.get('to', [])
                filename = header.get('filename')
                total_size = header.get('size', 0)
                msg_id = header.get('msg_id')
                print(f"[{username}] FILE_START {msg_id} -> {to_list} filename={filename} size={total_size}")
                # notify recipients optionally
                for r in to_list:
                    notify_file_start(username, r, header)
                # After FILE_START, expect FILE_DATA chunks
                while True:
                    subh = recv_json_header(conn)
                    if subh is None:
                        break
                    if subh.get('type') == 'FILE_DATA':
                        payload_len = subh.get('payload_len', 0)
                        payload = recv_exact(conn, payload_len) if payload_len else b''
                        # build AppPacket and forward using Sender (app-level Reno)
                        app_packet = AppPacket(subh, payload)
                        forward_app_packet_to_recipient(app_packet, subh.get('to', []), username)
                    elif subh.get('type') == 'FILE_END':
                        # forward FILE_END to recipients
                        for r in to_list:
                            forward_simple_header(r, subh)
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
                # We'll locate senders keyed by (recipient= this client ?), but the sender objects expect on_ack_received calls
                # We call all senders where recipient matches this client and msg_id matches
                dispatch_ack_to_senders(username, ack, msg_id)
            elif htype == 'JOIN_GROUP':
                group = header.get('group')
                with clients_lock:
                    groups[group].add(username)
                send_json_over_socket(conn, {"type":"JOIN_OK","group":group})
            elif htype == 'LEAVE_GROUP':
                group = header.get('group')
                with clients_lock:
                    groups[group].discard(username)
                send_json_over_socket(conn, {"type":"LEAVE_OK","group":group})
            else:
                print(f"[{username}] Unknown header type: {htype} -> {header}")
    except Exception as e:
        print("Exception in client handler:", e)
        traceback.print_exc()
    finally:
        # clean up
        with clients_lock:
            if username and username in clients:
                try:
                    clients[username].conn.close()
                except:
                    pass
                del clients[username]
        print(f"[{username}] cleaned up")

# ---------- Forwarding helpers ----------
def forward_simple_msg(from_user, to_user, payload_bytes):
    """
    Forward a small message to a single recipient immediately (not using Sender/Reno).
    For small chat messages, we can avoid the complex Reno sender and just deliver
    immediately via TCP conn of recipient. However, to grade congestion control
    demonstration, you can also route small messages through the Sender mechanism.
    """
    with clients_lock:
        recipient_info = clients.get(to_user)
    if not recipient_info:
        print("Recipient not connected:", to_user)
        return
    header = {"type":"MSG","from":from_user,"payload_len":len(payload_bytes)}
    try:
        send_json_over_socket(recipient_info.conn, header, payload_bytes)
    except Exception as e:
        print("Error forwarding small MSG:", e)

def forward_simple_header(to_user, header):
    """
    Send a header-only control message to recipient.
    """
    with clients_lock:
        recipient_info = clients.get(to_user)
    if not recipient_info:
        return
    try:
        send_json_over_socket(recipient_info.conn, header)
    except Exception as e:
        print("Error forwarding header:", e)

def notify_file_start(from_user, to_user, header):
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
        send_json_over_socket(recipient_info.conn, notify_h)
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
                s = Sender(None, r, recipient_info)
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

# ---------- Server acceptor ----------
def acceptor(sock: socket.socket):
    print("Server acceptor running on", sock.getsockname())
    while True:
        conn, addr = sock.accept()
        print("New connection from", addr)
        t = threading.Thread(target=client_handler, args=(conn, addr), daemon=True)
        t.start()

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
                if info:
                    try:
                        info.conn.close()
                    except:
                        pass
        time.sleep(KEEPALIVE_INTERVAL)

# ---------- Main ----------
def main():
    # Start listening
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(100)
    print(f"Server listening on {HOST}:{PORT}")

    # Start maintenance thread
    m = threading.Thread(target=maintenance_loop, daemon=True)
    m.start()

    # Accept loop
    try:
        acceptor(srv)
    except KeyboardInterrupt:
        print("Shutting down server")
    finally:
        srv.close()

if __name__ == "__main__":
    main()
