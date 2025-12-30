# server/main.py
import socket
from server.handlers.auth_handler import AuthHandler
from server.protocol.serializer import receive_packet_udp
import json
import struct

def main():
    # Create UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('0.0.0.0', 5000))
    
    # Create auth handler
    auth_handler = AuthHandler(udp_socket)
    
    print("Server started on port 5000...")
    
    while True:
        try:
            # Receive packet
            data, client_addr = udp_socket.recvfrom(4096)
            
            if len(data) >= 4:
                # Parse packet
                header_len = struct.unpack('!I', data[:4])[0]
                if len(data) >= 4 + header_len:
                    packet_json = data[4:4 + header_len].decode('utf-8')
                    packet = json.loads(packet_json)
                    
                    # Route to auth handler
                    packet_type = packet.get('type')
                    if packet_type == 'SIGNUP':
                        auth_handler.handle_signup(packet, client_addr)
                    elif packet_type == 'LOGIN':
                        auth_handler.handle_login(packet, client_addr)
                        
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Server error: {e}")
    
    udp_socket.close()

if __name__ == "__main__":
    main()