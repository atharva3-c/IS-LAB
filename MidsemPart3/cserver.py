import socket

def start_server():
    """Starts the server to listen for client connections"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)

    print("Server is listening...")
    client_socket, addr = server_socket.accept()
    print(f"Connection established with {addr}")

    count = 1
    while True:
        if count % 2 == 0:
            # Server's turn to send data
            message = input("Enter a message for the client (type 'stop' to end): ")
            client_socket.sendall(message.encode())
            if message == "stop":
                break
        else:
            # Server's turn to receive data
            data = client_socket.recv(1024).decode()
            print(f"Client: {data}")
            if data == "stop":
                break

        # Alternate the turn
        count += 1

    client_socket.close()
    print("Connection closed with client.")

if __name__ == "__main__":
    start_server()
