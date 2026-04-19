import socket
import threading

HOST = '127.0.0.1'
PORT = 9999

clients = []  # list of (conn, addr) tuples
lock = threading.Lock()


def broadcast(message: bytes, sender_conn=None):
    """Send a message to all connected clients except the sender."""
    with lock:
        for conn, addr in clients:
            if conn is not sender_conn:
                try:
                    conn.sendall(message)
                except OSError:
                    pass


def handle_client(conn: socket.socket, addr):
    print(f"[+] New connection from {addr}")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            message = f"[{addr[0]}:{addr[1]}] {data.decode()}"
            print(message)
            broadcast(message.encode(), sender_conn=conn)
    except (ConnectionResetError, OSError):
        pass
    finally:
        with lock:
            clients.remove((conn, addr))
        conn.close()
        print(f"[-] {addr} disconnected")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] Server listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            with lock:
                clients.append((conn, addr))
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
