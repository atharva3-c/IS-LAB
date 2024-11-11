import socket

def handle_client(client_socket):
    while True:
        # Receive data from client
        request = client_socket.recv(1024).decode()

        if request == "1":
            # If client sends option 1, print the message on the server side
            data = client_socket.recv(1024).decode()
            print(f"Data from client: {data}")
        elif request == "2":
            # If client sends option 2, print hello on the server side
            print("Client requested to print 'Hello' on server side.")
        elif request == "3":
            print("Client requested to exit.")
            client_socket.send("exit".encode())
            break
        else:
            print("Invalid option received.")

    client_socket.close()

def main():
    # Set up server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 9999))
    server.listen(1)
    print("Server listening on port 9999...")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")

        handle_client(client_socket)
        break  # Exit after handling the client

    server.close()

if __name__ == "__main__":
    main()
