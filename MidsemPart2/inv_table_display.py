# A simple dataset with just 2 documents to start
documents = {
    "doc1": "the quick brown fox",
    "doc2": "the lazy dog"
}


# Function to create an inverted index
def create_inverted_index(documents):
    """Create a plaintext inverted index."""
    index = {}

    for doc_id, doc in documents.items():
        for word in doc.split():
            if word not in index:
                index[word] = []
            index[word].append(doc_id)

    return index


# Function to display the inverted index
def display_inverted_index(index):
    """Display the plaintext inverted index."""
    print("\n--- Plaintext Inverted Index ---")
    for word, doc_ids in index.items():
        print(f"Word '{word}' appears in documents: {doc_ids}")


# Function to add a new line (document) to the dataset
def add_new_document(documents):
    """Add a new document to the dataset."""
    new_doc_id = f"doc{len(documents) + 1}"
    new_doc_content = input(f"Enter the content for {new_doc_id}: ")
    documents[new_doc_id] = new_doc_content
    print(f"Document '{new_doc_id}' added successfully!")


# Main menu function
def menu():
    """Menu-driven program."""
    while True:
        print("\n--- Menu ---")
        print("1) Display inverted index")
        print("2) Add new line to dataset")
        print("3) Exit")

        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            inverted_index = create_inverted_index(documents)
            display_inverted_index(inverted_index)
        elif choice == '2':
            add_new_document(documents)
        elif choice == '3':
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice, please try again.")


# Run the menu
if __name__ == "__main__":
    menu()
