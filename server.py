import socket
import threading
import json
import time
import traceback
import struct
from collections import defaultdict, deque
import queue

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
MAX_RECV_BUFFER_SIZE = 65536  # 64KB max receive buffer per client (in bytes)
MAX_SEND_BUFFER_SIZE = 131072 # 128KB max send buffer per sender (in bytes)

# ---------- Data structures ----------
class ClientInfo:
    def __init__(self, username, addr):
        self.username = username
        self.addr = addr  # (ip, port)
        self.lock = threading.Lock()
        self.last_seen = time.time()
        
        # Buffer management - RECEIVER side
        self.rwnd = MAX_RECV_BUFFER_SIZE  # Available receive buffer space (bytes)
        self.recv_buffer = queue.Queue(maxsize=MAX_RECV_BUFFER_SIZE // MSS)  # Queue of received packets
        self.last_acked_seq = 0  # Last sequence number acknowledged
        self.last_read_seq = 0   # Last sequence number read by application
        self.buffer_cond = threading.Condition()  # Condition variable for buffer operations
        
        # Stats
        self.total_received = 0
        self.total_dropped = 0
        self.buffer_high_water = 0
        
        # UDP socket to send to this client
        self.udp_socket = None

# Packet wrapper with buffer management info
class AppPacket:
    def __init__(self, header: dict, payload: bytes):
        self.header = header
        self.payload = payload
        self.seq = header.get('seq', 0)
        self.size = len(payload) + 100  # Approximate size including header overhead
        self.timestamp = time.time()

# ---------- Global registries ----------
clients = {}         # username -> ClientInfo
clients_lock = threading.Lock()
groups = defaultdict(set)  # group_name -> set(usernames)
senders = {}         # (sender_username, recipient_username, msg_id) -> Sender
senders_lock = threading.Lock()

# Global UDP server socket
udp_socket = None

# ---------- Buffer Management Classes ----------
class ReceiveBuffer:
    """Manages receive buffer for a client"""
    def __init__(self, max_size_bytes=MAX_RECV_BUFFER_SIZE):
        self.max_size_bytes = max_size_bytes
        self.buffer = {}  # seq -> AppPacket
        self.next_expected_seq = 0
        self.available_space = max_size_bytes
        self.lock = threading.Lock()
        self.data_available = threading.Condition(self.lock)
        
    def add_packet(self, packet: AppPacket):
        """Add a packet to receive buffer if space available"""
        with self.lock:
            # Check if we have space
            if packet.size > self.available_space:
                return False  # No space
            
            # Check if packet is duplicate
            if packet.seq in self.buffer:
                return True  # Already have it
            
            # Add to buffer
            self.buffer[packet.seq] = packet
            self.available_space -= packet.size
            
            # Update high water mark
            used = self.max_size_bytes - self.available_space
            if used > self.max_size_bytes * 0.8:  # 80% full
                # Could trigger backpressure here
                pass
            
            # Notify that data is available
            self.data_available.notify()
            return True
    
    def get_next_packet(self, timeout=1.0):
        """Get the next in-order packet from buffer"""
        with self.data_available:
            # Wait for next expected packet
            start_time = time.time()
            while self.next_expected_seq not in self.buffer:
                if time.time() - start_time > timeout:
                    return None
                self.data_available.wait(timeout=0.1)
            
            # Retrieve the packet
            packet = self.buffer.pop(self.next_expected_seq)
            self.available_space += packet.size
            self.next_expected_seq += 1
            
            return packet
    
    def get_available_space(self):
        """Get available buffer space in bytes"""
        with self.lock:
            return self.available_space
    
    def cleanup_old_packets(self, max_age_seconds=30):
        """Clean up old packets from buffer"""
        with self.lock:
            current_time = time.time()
            to_remove = []
            for seq, packet in self.buffer.items():
                if current_time - packet.timestamp > max_age_seconds:
                    to_remove.append(seq)
            
            for seq in to_remove:
                packet = self.buffer.pop(seq, None)
                if packet:
                    self.available_space += packet.size
            return len(to_remove)

class SendBuffer:
    """Manages send buffer for a Sender"""
    def __init__(self, max_size_bytes=MAX_SEND_BUFFER_SIZE):
        self.max_size_bytes = max_size_bytes
        self.buffer = {}  # seq -> AppPacket
        self.sent_packets = {}  # seq -> (packet, send_time)
        self.next_seq_to_send = 0
        self.next_new_seq = 0
        self.available_space = max_size_bytes
        self.lock = threading.Lock()
        
    def add_packet(self, packet: AppPacket):
        """Add a packet to send buffer"""
        with self.lock:
            if packet.size > self.available_space:
                return False  # Buffer full
            
            seq = self.next_new_seq
            packet.header['seq'] = seq  # Ensure seq is set
            packet.seq = seq
            
            self.buffer[seq] = packet
            self.available_space -= packet.size
            self.next_new_seq += 1
            return True
    
    def get_packet_to_send(self, window_size):
        """Get next packet to send within window"""
        with self.lock:
            if self.next_seq_to_send not in self.buffer:
                return None
            
            packet = self.buffer[self.next_seq_to_send]
            
            # Mark as sent but keep in buffer for retransmission
            self.sent_packets[self.next_seq_to_send] = (packet, time.time())
            self.next_seq_to_send += 1
            
            return packet
    
    def ack_packet(self, seq):
        """Acknowledge a packet, freeing buffer space"""
        with self.lock:
            # Remove from buffer if present
            if seq in self.buffer:
                packet = self.buffer.pop(seq)
                self.available_space += packet.size
            
            # Remove from sent packets
            if seq in self.sent_packets:
                del self.sent_packets[seq]
            
            # If this ACK allows us to advance next_seq_to_send
            while self.next_seq_to_send not in self.buffer and self.next_seq_to_send < self.next_new_seq:
                self.next_seq_to_send += 1
    
    def get_retransmit_packet(self, seq):
        """Get packet for retransmission"""
        with self.lock:
            if seq in self.buffer:
                packet = self.buffer[seq]
                # Update sent time
                self.sent_packets[seq] = (packet, time.time())
                return packet
            return None
    
    def get_available_space(self):
        """Get available buffer space"""
        with self.lock:
            return self.available_space
    
    def get_packets_in_flight(self):
        """Get number of packets in flight (sent but not ACKed)"""
        with self.lock:
            return len(self.sent_packets)

# ---------- UDP Utility functions ----------
def send_json_over_udp(sock: socket.socket, addr: tuple, header: dict, payload: bytes = None):
    header_bytes = json.dumps(header).encode('utf-8')
    if payload is None:
        payload = b''
    
    header_len = len(header_bytes)
    total_payload_len = len(payload)
    
    packet = struct.pack('!II', header_len, total_payload_len) + header_bytes + payload
    
    try:
        bytes_sent = sock.sendto(packet, addr)
        return bytes_sent
    except Exception as e:
        print(f"Error sending UDP to {addr}: {e}")
        return 0

def recv_json_from_udp(sock: socket.socket):
    try:
        data, addr = sock.recvfrom(UDP_BUFFER_SIZE)
        if len(data) < 8:
            return None, None, addr
        
        header_len, payload_len = struct.unpack('!II', data[:8])
        
        if len(data) < 8 + header_len + payload_len:
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

# ---------- Enhanced Sender with Buffer Management ----------
class Sender:
    def __init__(self, server_sock, recipient_username, recipient_info: ClientInfo):
        self.recipient = recipient_username
        self.recipient_info = recipient_info
        self.addr = recipient_info.addr
        self.server_sock = server_sock

        # Reno state
        self.cwnd = INITIAL_CWND
        self.ssthresh = INITIAL_SSTHRESH
        self.MSS = MSS
        
        # Buffer management
        self.send_buffer = SendBuffer()
        self.inflight = {}  # seq -> (AppPacket, send_time, retrans_count)
        self.send_base = None
        self.next_seq = 0
        
        # Window management
        self.advertised_window = MAX_RECV_BUFFER_SIZE  # Start with max
        self.effective_window = 1  # Start with 1 packet
        
        # ACK tracking
        self.dup_ack_count = 0
        self.last_ack = None
        self.rtt_samples = []
        self.rtt_estimate = RTO_INITIAL
        self.rtt_variance = 0

        # Timer
        self.rto = RTO_INITIAL
        self.timer = None
        self.timer_lock = threading.Lock()

        # Queue for new packets
        self.queue = deque()
        self.queue_cond = threading.Condition()

        # Running flag
        self.running = True

        # Stats
        self.total_sent = 0
        self.total_retrans = 0
        self.buffer_full_drops = 0

        # Start threads
        self.worker_thread = threading.Thread(target=self._run_sender_loop, daemon=True)
        self.window_update_thread = threading.Thread(target=self._window_update_loop, daemon=True)
        self.worker_thread.start()
        self.window_update_thread.start()

    def stop(self):
        self.running = False
        with self.queue_cond:
            self.queue_cond.notify_all()
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=1)
        if self.window_update_thread.is_alive():
            self.window_update_thread.join(timeout=1)

    def enqueue_packet(self, app_packet: AppPacket):
        """Add packet to send queue with buffer checking"""
        with self.queue_cond:
            # Check if we have buffer space
            available = self.send_buffer.get_available_space()
            if app_packet.size > available:
                self.buffer_full_drops += 1
                print(f"[Sender->{self.recipient}] Buffer full, dropping packet")
                return False
            
            self.queue.append(app_packet)
            self.queue_cond.notify()
            return True

    def _update_effective_window(self):
        """Update effective window based on cwnd and advertised window"""
        # Calculate window in packets
        cwnd_packets = int(self.cwnd)
        adv_window_packets = max(1, self.advertised_window // self.MSS)
        
        # Effective window is min(cwnd, advertised window)
        self.effective_window = min(cwnd_packets, adv_window_packets)
        
        # Also consider buffer space
        buffer_space_packets = self.send_buffer.get_available_space() // self.MSS
        self.effective_window = min(self.effective_window, max(1, buffer_space_packets))

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

    def _update_rtt(self, sample):
        """Update RTT estimate using Jacobson/Karels algorithm"""
        if sample <= 0:
            return
        
        alpha = 0.125  # smoothing factor
        beta = 0.25    # variance factor
        
        if not self.rtt_samples:
            self.rtt_estimate = sample
            self.rtt_variance = sample / 2
        else:
            error = sample - self.rtt_estimate
            self.rtt_estimate += alpha * error
            self.rtt_variance += beta * (abs(error) - self.rtt_variance)
        
        self.rto = self.rtt_estimate + 4 * self.rtt_variance
        self.rto = max(0.1, min(self.rto, 60.0))  # Clamp between 100ms and 60s

    def _on_timeout(self):
        """Timeout handler with buffer awareness"""
        with self.lock:
            if self.send_base is None:
                return
            
            print(f"[Sender->{self.recipient}] TIMEOUT seq {self.send_base}. "
                  f"cwnd={self.cwnd:.2f}, ssthresh={self.ssthresh}, "
                  f"inflight={len(self.inflight)}, buffer={self.send_buffer.get_available_space()}")
            
            # Reno timeout: reduce ssthresh, set cwnd=1
            self.ssthresh = max(int(self.cwnd // 2), 2)
            self.cwnd = 1
            self._update_effective_window()
            
            # Retransmit oldest unacked packet
            if self.send_base in self.inflight:
                self.total_retrans += 1
                pkt_info = self.inflight[self.send_base]
                packet, _, rcount = pkt_info
                self.inflight[self.send_base] = (packet, time.time(), rcount + 1)
                
                # Also mark in send_buffer
                retrans_packet = self.send_buffer.get_retransmit_packet(self.send_base)
                if retrans_packet:
                    try:
                        send_json_over_udp(self.server_sock, self.addr, 
                                         retrans_packet.header, retrans_packet.payload)
                    except Exception as e:
                        print(f"Timeout retransmit error: {e}")
            
            # Restart timer
            self._start_timer()

    def on_ack_received(self, ack_num: int, advertised_window: int = None):
        """Handle ACK with window advertisement"""
        if advertised_window is not None:
            self.advertised_window = advertised_window
        
        with self.lock:
            if self.send_base is None:
                return

            # Update RTT if we have timing info
            if ack_num in self.inflight:
                _, send_time, _ = self.inflight[ack_num]
                rtt_sample = time.time() - send_time
                self._update_rtt(rtt_sample)

            if ack_num > self.send_base:
                # New ACK received
                old_send_base = self.send_base
                
                # Remove acked packets from inflight and buffer
                for seq in range(self.send_base, ack_num):
                    if seq in self.inflight:
                        del self.inflight[seq]
                    self.send_buffer.ack_packet(seq)
                
                self.send_base = ack_num
                self.dup_ack_count = 0
                
                # Update congestion window (Reno)
                if self.cwnd < self.ssthresh:
                    # Slow start: exponential increase
                    self.cwnd += 1
                else:
                    # Congestion avoidance: additive increase
                    self.cwnd += 1.0 / max(1, int(self.cwnd))
                
                self._update_effective_window()
                
                # Restart timer if packets still inflight
                if self.inflight:
                    self._stop_timer()
                    self._start_timer()
                else:
                    self._stop_timer()
                    
                print(f"[Sender->{self.recipient}] New ACK {ack_num}. "
                      f"cwnd={self.cwnd:.2f}, adv_win={self.advertised_window}, "
                      f"eff_win={self.effective_window}")
                
            elif ack_num == self.send_base:
                # Duplicate ACK
                self.dup_ack_count += 1
                
                if self.dup_ack_count == 3:
                    # Fast retransmit
                    print(f"[Sender->{self.recipient}] Fast retransmit seq {self.send_base}")
                    self.ssthresh = max(int(self.cwnd // 2), 2)
                    self.cwnd = self.ssthresh + 3
                    self._update_effective_window()
                    
                    # Retransmit
                    if self.send_base in self.inflight:
                        self.total_retrans += 1
                        pkt_info = self.inflight[self.send_base]
                        packet, _, rcount = pkt_info
                        self.inflight[self.send_base] = (packet, time.time(), rcount + 1)
                        
                        retrans_packet = self.send_buffer.get_retransmit_packet(self.send_base)
                        if retrans_packet:
                            try:
                                send_json_over_udp(self.server_sock, self.addr,
                                                 retrans_packet.header, retrans_packet.payload)
                            except Exception as e:
                                print(f"Fast retransmit error: {e}")
                    
                    self._stop_timer()
                    self._start_timer()

    def _window_update_loop(self):
        """Periodically update window based on receiver buffer space"""
        while self.running:
            time.sleep(0.5)  # Update every 500ms
            
            # Could request window update from receiver here
            # For now, we'll just recalculate effective window
            self._update_effective_window()
            
            # Clean old inflight packets (safety)
            current_time = time.time()
            to_remove = []
            for seq, (packet, send_time, _) in self.inflight.items():
                if current_time - send_time > 60:  # 60 second timeout
                    to_remove.append(seq)
            
            for seq in to_remove:
                del self.inflight[seq]

    def _run_sender_loop(self):
        """Main sending loop with buffer and window management"""
        while self.running:
            # Get packets from queue
            with self.queue_cond:
                while not self.queue and self.running:
                    self.queue_cond.wait(timeout=0.5)
                if not self.running:
                    break
                
                pending = []
                while self.queue:
                    pending.append(self.queue.popleft())

            # Add packets to send buffer
            for packet in pending:
                if not self.send_buffer.add_packet(packet):
                    # Buffer full - wait for space
                    time.sleep(0.1)
                    # Put back and retry
                    self.queue.appendleft(packet)
                    break

            # Send packets according to window
            while self.running:
                # Calculate how many packets we can send
                inflight_count = self.send_buffer.get_packets_in_flight()
                available_window = max(0, self.effective_window - inflight_count)
                
                if available_window <= 0 or self.send_base is None:
                    # Window exhausted or no base seq
                    time.sleep(0.01)
                    continue
                
                # Get next packet to send
                packet = self.send_buffer.get_packet_to_send(available_window)
                if not packet:
                    # No more packets ready to send
                    break
                
                # Send packet
                try:
                    send_json_over_udp(self.server_sock, self.addr, 
                                     packet.header, packet.payload)
                    self.total_sent += 1
                    
                    # Track inflight
                    self.inflight[packet.seq] = (packet, time.time(), 0)
                    
                    # Start timer if needed
                    if self.timer is None:
                        self._start_timer()
                        
                except Exception as e:
                    print(f"Error sending packet {packet.seq}: {e}")
                
                # Small delay between packets
                time.sleep(0.001)
            
            # Brief sleep to prevent busy waiting
            time.sleep(0.01)

#...........server logic.........
def forward_simple_msg(from_user, to_user, payload_bytes, from_addr):
    """
    Forward P2P message to a single recipient
    """
    with clients_lock:
        recipient_info = clients.get(to_user)
    
    if not recipient_info:
        print(f"[P2P] Recipient {to_user} not found")
        return
    
    # Create message header
    header = {
        "type": "MSG",
        "from": from_user,
        "mode": "p2p",
        "to": [to_user],
        "payload_len": len(payload_bytes)
    }
    
    try:
        send_json_over_udp(udp_socket, recipient_info.addr, header, payload_bytes)
        print(f"[P2P] {from_user} -> {to_user}: {len(payload_bytes)} bytes")
    except Exception as e:
        print(f"[P2P] Error forwarding to {to_user}: {e}")


def forward_to_group(from_user, group_name, header, payload_bytes=None):
    """
    Broadcast message to all group members except sender
    Returns number of recipients
    """
    with clients_lock:
        if group_name not in groups:
            print(f"[Group] {group_name} doesn't exist")
            return 0
        
        sent_count = 0
        members = list(groups[group_name])
        
        for member in members:
            if member == from_user:
                continue  # Skip sender
            
            recipient_info = clients.get(member)
            if not recipient_info:
                print(f"[Group] Member {member} offline")
                continue
            
            # Update header for recipient
            recipient_header = header.copy()
            recipient_header['from'] = from_user
            recipient_header['group'] = group_name
            recipient_header['to'] = [member]  # Single recipient
            
            try:
                send_json_over_udp(udp_socket, recipient_info.addr, 
                                 recipient_header, payload_bytes)
                sent_count += 1
            except Exception as e:
                print(f"[Group] Error sending to {member}: {e}")
    
    print(f"[Group] {from_user} -> {group_name}: {sent_count}/{len(members)-1} members")
    return sent_count


def notify_file_start(from_user, to_user, header, from_addr):
    """
    Notify recipient about incoming file transfer
    """
    with clients_lock:
        recipient_info = clients.get(to_user)
    
    if not recipient_info:
        print(f"[File] Cannot notify {to_user}: offline")
        return
    
    # Extract file info
    file_info = {
        "type": "FILE_NOTIFY",
        "from": from_user,
        "msg_id": header.get('msg_id'),
        "filename": header.get('filename'),
        "size": header.get('size'),
        "timestamp": time.time()
    }
    
    try:
        send_json_over_udp(udp_socket, recipient_info.addr, file_info)
        print(f"[File] Notified {to_user} about file from {from_user}")
    except Exception as e:
        print(f"[File] Notification error to {to_user}: {e}")


def forward_app_packet_to_recipient(app_packet: AppPacket, to_list, origin_username):
    """
    Forward AppPacket using TCP Reno Sender for reliability
    """
    for recipient in to_list:
        with clients_lock:
            recipient_info = clients.get(recipient)
        
        if not recipient_info:
            print(f"[Reno] Recipient {recipient} offline, dropping packet")
            continue
        
        # Create/get Sender for this (origin, recipient, msg_id) flow
        msg_id = app_packet.header.get('msg_id', 'default')
        key = (origin_username, recipient, msg_id)
        
        with senders_lock:
            sender = senders.get(key)
            if sender is None:
                sender = Sender(udp_socket, recipient, recipient_info)
                senders[key] = sender
        
        # Enqueue packet for reliable delivery
        success = sender.enqueue_packet(app_packet)
        if not success:
            print(f"[Reno] Buffer full for {recipient}, packet dropped")


def dispatch_ack_to_senders(from_username, ack_num, msg_id, advertised_window=None):
    """
    Dispatch ACK to appropriate Sender objects
    Already exists but needs to use senders_lock
    """
    to_notify = []
    
    with senders_lock:
        for key, sender in list(senders.items()):
            origin, recipient, mid = key
            if recipient == from_username and (msg_id is None or mid == msg_id):
                to_notify.append((sender, advertised_window))
    
    for sender, adv_win in to_notify:
        sender.on_ack_received(ack_num, adv_win)
    
    # Clean up finished senders
    cleanup_finished_senders()


def cleanup_finished_senders():
    """
    Remove Sender objects that have completed their transfers
    """
    with senders_lock:
        to_remove = []
        for key, sender in senders.items():
            if not sender.running or (sender.send_base is not None and len(sender.inflight) == 0 and len(sender.queue) == 0):
                to_remove.append(key)
                sender.stop()
        
        for key in to_remove:
            del senders[key]
        
        if to_remove:
            print(f"[Cleanup] Removed {len(to_remove)} finished senders")


def maintenance_loop():
    """
    Background maintenance: clean inactive users, update windows
    """
    while True:
        time.sleep(KEEPALIVE_INTERVAL)
        
        current_time = time.time()
        inactive_users = []
        
        # Find inactive users
        with clients_lock:
            for username, client in list(clients.items()):
                if current_time - client.last_seen > KEEPALIVE_INTERVAL * 3:
                    inactive_users.append(username)
        
        # Remove inactive users
        for username in inactive_users:
            with clients_lock:
                if username in clients:
                    # Remove from groups
                    for group_name in list(groups.keys()):
                        groups[group_name].discard(username)
                    
                    # Remove client
                    del clients[username]
                    print(f"[Maintenance] Removed inactive user: {username}")
        
        # Clean old senders
        cleanup_finished_senders()
        
        # Print server status (optional)
        with clients_lock:
            print(f"[Status] Online: {len(clients)}, Groups: {len(groups)}, Senders: {len(senders)}")


# Buffer-aware Client Handler
def client_handler(addr):
    """Handle client with buffer management"""
    username = None
    receive_buffer = None
    
    try:
        # First expect HELLO
        header, payload, _ = recv_json_from_udp(udp_socket)
        if header is None:
            print("Connection closed before HELLO from", addr)
            return
        
        if header.get('type') != 'HELLO' or not header.get('username'):
            print("First message not HELLO from", addr)
            return
        
        username = header['username']
        
        with clients_lock:
            if username in clients:
                print("Username already connected:", username)
                send_json_over_udp(udp_socket, addr, 
                                 {"type":"ERROR", "msg":"username already connected"})
                return
            
            # Create client with buffer
            client = ClientInfo(username, addr)
            receive_buffer = ReceiveBuffer()
            clients[username] = client
        
        print(f"[{username}] connected from {addr}")

        # Send welcome with buffer info
        send_json_over_udp(udp_socket, addr, 
                         {"type":"WELCOME", "msg":"registered", 
                          "username":username, "buffer_size":MAX_RECV_BUFFER_SIZE})

        # Main receive loop
        while True:
            header, payload, client_addr = recv_json_from_udp(udp_socket)
            
            if client_addr != addr:
                continue
                
            if header is None:
                print(f"[{username}] disconnected")
                break
            
            # Update last seen
            with clients_lock:
                if username in clients:
                    clients[username].last_seen = time.time()
            
            htype = header.get('type')
            
            if htype == 'WINDOW_UPDATE':
                # Client advertising its window size
                advertised_window = header.get('rwnd', MAX_RECV_BUFFER_SIZE)
                with clients_lock:
                    if username in clients:
                        clients[username].rwnd = advertised_window
                continue
                
            elif htype == 'ACK':
                # ACK with possible window advertisement
                ack = header.get('ack')
                msg_id = header.get('msg_id')
                adv_win = header.get('rwnd', None)
                
                # Dispatch to senders
                dispatch_ack_to_senders(username, ack, msg_id, adv_win)
                continue
                
            # ✅ FIXED: Handle MSG with group broadcast
            elif htype == 'MSG':
                mode = header.get('mode', 'p2p')
                to_list = header.get('to', [])
                group_name = header.get('group')  # Get group name if present
                
                # 🔥 FIX: UDP te already payload ase, recv_exact lagbe na!
                # payload variable already defined from recv_json_from_udp
                message_payload = payload  # Rename to avoid confusion
                
                if mode == 'p2p':
                    # Existing P2P forwarding
                    for r in to_list:
                        forward_simple_msg(username, r, message_payload, addr)
                
                elif mode == 'group' and group_name:
                    # ✅ Group broadcast
                    forward_to_group(username, group_name, header, message_payload)
                
                elif mode == 'broadcast':
                    # Optional: Broadcast to all online users
                    with clients_lock:
                        for other_user, other_info in clients.items():
                            if other_user != username:  # Don't send to self
                                try:
                                    send_json_over_udp(udp_socket, other_info.addr, header, message_payload)
                                except Exception as e:
                                    print(f"Broadcast error to {other_user}: {e}")
                
            # ✅ ADD OTHER MESSAGE TYPES (FILE_START, JOIN_GROUP, etc.)
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
                
                # For UDP, FILE_DATA will come as separate packets
                # No while loop needed like TCP
            
            elif htype == 'FILE_DATA':
                # This comes as separate UDP packet
                app_packet = AppPacket(header, payload)
                to_list = header.get('to', [])
                forward_app_packet_to_recipient(app_packet, to_list, username)
            
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
            
            elif htype == 'GET_ONLINE_USERS':
                # Send online users list
                with clients_lock:
                    online_users = list(clients.keys())
                send_json_over_udp(udp_socket, addr, 
                                 {"type": "ONLINE_USERS", "users": online_users})
            
            else:
                print(f"[{username}] Unknown message type: {htype}")
            
    except Exception as e:
        print(f"Exception in client handler for {username}: {e}")
        traceback.print_exc()
    finally:
        # Cleanup
        with clients_lock:
            if username and username in clients:
                # Remove from all groups
                for group_name in list(groups.keys()):
                    groups[group_name].discard(username)
                del clients[username]
        print(f"[{username}] cleaned up")

# ---------- Main ----------
def main():
    global udp_socket
    
    # Create UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind((HOST, PORT))
    
    print(f"UDP Server with Buffer Management listening on {HOST}:{PORT}")
    print(f"Max receive buffer: {MAX_RECV_BUFFER_SIZE} bytes")
    print(f"Max send buffer: {MAX_SEND_BUFFER_SIZE} bytes")
    
    # Start maintenance thread
    m = threading.Thread(target=maintenance_loop, daemon=True)
    m.start()
    
    # Simple UDP receiver (would need enhancement for full routing)
    while True:
        try:
            header, payload, addr = recv_json_from_udp(udp_socket)
            if header and header.get('type') == 'HELLO':
                threading.Thread(target=client_handler, args=(addr,), daemon=True).start()
        except KeyboardInterrupt:
            print("Shutting down server")
            break
        except Exception as e:
            print(f"Server error: {e}")
    
    if udp_socket:
        udp_socket.close()

if __name__ == "__main__":
    main()