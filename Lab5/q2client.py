import socket
import hashlib


def compute_hash(data):
    hash_obj = hashlib.sha256()
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 22345))

    data = "This is some data to verify"
    print(f"Sending data: {data}")

    client_socket.send(data.encode('utf-8'))

    local_hash = compute_hash(data)
    print(f"Local computed hash: {local_hash}")

    server_hash = client_socket.recv(1024).decode('utf-8')
    print(f"Hash received from server: {server_hash}")

    if local_hash == server_hash:
        print("Data integrity verified: No tampering detected.")
    else:
        print("Warning: Data corruption or tampering detected!")

    client_socket.close()


if __name__ == "__main__":
    start_client()

