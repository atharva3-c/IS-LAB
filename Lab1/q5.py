a="yes"
b="ciw"

key=((ord(b[0])-ord(a[0]))%26)
print(key)

text= "XVIEWYW"

b=''.join(chr(((ord(ch)-key-ord('A'))%26)+ord('A'))for ch in text)

print(b)
