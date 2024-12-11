import socket
import logging
from threading import Thread

# Configure logging
logging.basicConfig(
    filename='honeypot.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_connection(port, client_address, scan_type=None):
    """Logs the connection details."""
    if scan_type:
        logging.info(f"Scan detected on port {port} from {client_address} - Scan Type: {scan_type}")
    else:
        logging.info(f"Connection on port {port} from {client_address}")

def handle_client(client_socket, client_address, port):
    """Handles interaction with a client."""
    try:
        # Log the connection
        log_connection(port, client_address)

        # Simulate a response for the honeypot service
        response = f"You've reached a honeypot on port {port}!"
        client_socket.send(response.encode())

        # Log received data (if any)
        data = client_socket.recv(1024)
        if data:
            log_connection(port, client_address, scan_type="Data Received")
    except Exception as e:
        logging.error(f"Error handling client on port {port}: {e}")
    finally:
        client_socket.close()

def detect_scan_behavior(client_socket, port):
    """Detect potential scanning behavior."""
    try:
        # Wait for a short time to see if there are rapid successive connections
        client_socket.settimeout(2)
        data = client_socket.recv(1024)
        if not data:
            # Likely a port scan if no data is sent
            return "Port Scan"
    except socket.timeout:
        return "Timeout Scan (likely nmap or similar)"
    except Exception as e:
        logging.error(f"Error detecting scan on port {port}: {e}")
    return None

def start_honeypot(port):
    """Starts a honeypot on the specified port."""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        print(f"Honeypot listening on port {port}")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Connection on port {port} from {client_address}")
            
            # Detect scan behavior
            scan_type = detect_scan_behavior(client_socket, port)
            if scan_type:
                log_connection(port, client_address, scan_type=scan_type)
            else:
                Thread(target=handle_client, args=(client_socket, client_address, port)).start()
    except Exception as e:
        logging.error(f"Error starting honeypot on port {port}: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    # List of ports to listen on
    ports = [22, 80, 443]  # SSH, HTTP, HTTPS as examples

    # Start a thread for each port
    for port in ports:
        Thread(target=start_honeypot, args=(port,)).start()
