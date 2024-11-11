def hash_function(input_string):
    hash_value = 5381

    for char in input_string:
        hash_value = hash_value * 33 + ord(char)
        hash_value = hash_value ^ 0xABCDEFAB
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value


a = hash_function("atharva")
print(a)

