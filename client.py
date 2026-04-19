import socket
import threading
import sys

HOST = '127.0.0.1'
PORT = 9999


def receive_messages(conn: socket.socket):
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                print("[*] Disconnected from server")
                break
            print(data.decode())
        except (ConnectionResetError, OSError):
            break


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((HOST, PORT))
    except ConnectionRefusedError:
        print(f"[!] Could not connect to {HOST}:{PORT}. Is the server running?")
        sys.exit(1)

    print(f"[*] Connected to {HOST}:{PORT}. Type messages and press Enter to send.")

    # Start background thread to receive messages
    recv_thread = threading.Thread(target=receive_messages, args=(client,), daemon=True)
    recv_thread.start()

    try:
        while True:
            message = input()
            if not message:
                continue
            client.sendall(message.encode())
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Disconnecting")
    finally:
        client.close()


if __name__ == "__main__":
    main()
