import socket


def start_client():
    """Starts the client and communicates with the server"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    count = 1
    while True:
        if count % 2 == 1:
            # Client's turn to send data
            message = input("Enter a message (type 'stop' to end): ")
            client_socket.sendall(message.encode())
            if message == "stop":
                break
        else:
            # Client's turn to receive data
            data = client_socket.recv(1024).decode()
            print(f"Server: {data}")
            if data == "stop":
                break

        # Alternate the turn
        count += 1

    client_socket.close()


if __name__ == "__main__":
    start_client()
