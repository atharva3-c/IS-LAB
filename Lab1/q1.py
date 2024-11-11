def gcd(num1, num2):
    if num1==num2:
        return num1
    if num1>num2:
        return gcd(num1-num2,num2)

    return gcd(num1,num2-num1)


a = input("enter a string\n")
key_m = int(input("enter mul key"))
key_add=int(input("enter addi key"))
if(gcd(key_m,26)!=1):
    print("not co prime!")
    exit();


b = ''.join(chr(((ord(ch) + key_add - ord('a')) % 26) + ord('a')) if ch != ' ' else ' ' for ch in a)

c = ''.join(chr((((ord(ch) - ord('a')) * key_m) % 26) + ord('a')) if ch != ' ' else ' ' for ch in a)

d = ''.join(chr(((((ord(ch) - ord('a')) * key_m)+key_add) % 26) + ord('a')) if ch != ' ' else ' ' for ch in a)
print(b)
print(c)
print(d)

print("encryption part")

key_inv=pow(key_m,-1,26)

e = ''.join(chr(((ord(ch) -key_add - ord('a')) % 26) + ord('a')) if ch != ' ' else ' ' for ch in b)

f = ''.join(chr((((ord(ch) - ord('a')) * key_inv) % 26) + ord('a')) if ch != ' ' else ' ' for ch in c)

g = ''.join(chr(((((ord(ch) - ord('a')) - key_add)*key_inv) % 26) + ord('a')) if ch != ' ' else ' ' for ch in d)
print(e)
print(f)
print(g)

