import socket

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 9999))  # Connect to the server

    while True:
        print("\n--- Client Menu ---")
        print("1) Enter Data")
        print("2) Print Hello")
        print("3) Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            client.send(choice.encode())  # Send the choice to server
            data = input("Enter data to send to the server: ")
            client.send(data.encode())  # Send data to server
        elif choice == "2":
            client.send(choice.encode())  # Send the choice to server
            print("Hello from the client side!")  # Print hello on client side
        elif choice == "3":
            client.send(choice.encode())  # Send the choice to server
            response = client.recv(1024).decode()
            if response == "exit":
                print("Exiting client...")
                break
        else:
            print("Invalid option. Please try again.")

    client.close()

if __name__ == "__main__":
    main()
