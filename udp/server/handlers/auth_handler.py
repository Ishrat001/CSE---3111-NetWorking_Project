# server/handlers/auth_handler.py
from server.db.user_db import user_db
from server.protocol.serializer import send_packet_udp
import socket

class AuthHandler:
    """Handles authentication requests from clients"""
    
    def __init__(self, udp_socket: socket.socket):
        self.udp_socket = udp_socket
    
    def handle_signup(self, packet_data: dict, client_addr: tuple):
        """Handle signup request from client"""
        full_name = packet_data.get('full_name', '').strip()
        username = packet_data.get('username', '').strip()
        password = packet_data.get('password', '').strip()
        
        # Call database
        success, message = user_db.register_user(full_name, username, password)
        
        # Send response to client
        response = {
            'type': 'SIGNUP_RESPONSE',
            'success': success,
            'message': message,
            'username': username if success else None
        }
        
        # Send back to client
        self._send_response(client_addr, response)
        
        print(f"[Signup] {username}: {message}")
    
    def handle_login(self, packet_data: dict, client_addr: tuple):
        """Handle login request from client"""
        username = packet_data.get('username', '').strip()
        password = packet_data.get('password', '').strip()
        
        # Call database
        success, message, user_data = user_db.login_user(username, password)
        
        # Prepare response
        response = {
            'type': 'LOGIN_RESPONSE',
            'success': success,
            'message': message
        }
        
        if success and user_data:
            response.update({
                'username': username,
                'full_name': user_data.get('full_name'),
                'user_id': user_data.get('id')
            })
        
        # Send back to client
        self._send_response(client_addr, response)
        
        print(f"[Login] {username}: {message}")
    
    def _send_response(self, client_addr: tuple, response: dict):
        """Send response packet to client"""
        try:
            # Convert to JSON
            import json
            import struct
            response_json = json.dumps(response).encode('utf-8')
            packet = struct.pack('!I', len(response_json)) + response_json
            self.udp_socket.sendto(packet, client_addr)
        except Exception as e:
            print(f"Error sending auth response: {e}")