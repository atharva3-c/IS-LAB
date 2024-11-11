import socket


def start_client():
    """Starts the client and communicates with the server"""
    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect(('localhost', 12345))

    # Ask the user to input two numbers
    a = int(input("Enter the first number: "))
    b = int(input("Enter the second number: "))

    # Send the two numbers to the server
    client_socket.sendall(f"{a} {b}".encode())

    # Close the connection
    client_socket.close()


if __name__ == "__main__":
    start_client()
