def print_hello():
    """Function to print 'Hello'"""
    print("Hello")

def menu():
    """Displays the menu options"""
    print("\nMenu:")
    print("1. Enter a document line")
    print("2. Call the print_hello function")
    print("3. Exit")

def main():
    documents = {}
    doc_count = 1  # Counter to keep track of the document number

    while True:
        menu()  # Display the menu
        choice = input("Enter your choice: ")

        if choice == "1":
            # Get user input and add it to the dictionary
            line = input(f"Enter line for doc{doc_count}: ")
            documents[f"doc{doc_count}"] = line
            doc_count += 1
            print(f"Document added: doc{doc_count-1} -> {line}")

        elif choice == "2":
            # Call the print_hello function
            print_hello()

        elif choice == "3":
            # Exit the program
            print("Exiting...")
            break

        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
