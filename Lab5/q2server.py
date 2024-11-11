import socket
import hashlib


def compute_hash(data):
    # Compute hash using a simple SHA256 algorithm
    hash_obj = hashlib.sha256()
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 22345))
    server_socket.listen(1)
    print('Server is listening on port 12345...')
    dataa = "This is some data to erify"
    while True:
        conn, addr = server_socket.accept()
        print(f"Connection established with {addr}")

        # Receive data from client
        data = conn.recv(1024).decode('utf-8')
        if not data:
            break
        print(f"Data received: {data}")

        # Compute the hash of the received data
        data_hash = compute_hash(dataa)
        print(f"Computed hash: {data_hash}")

        # Send the hash back to the client
        conn.send(data_hash.encode('utf-8'))
        print(f"Hash sent back to client\n")

        conn.close()


if __name__ == "__main__":
    start_server()

