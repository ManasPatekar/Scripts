with open('whitepages.txt', 'rb') as f:
    data = f.read().replace(b'\xe2\x80\x83', b'0').replace(b' ', b'1')
binary = data.decode('ascii')
flag = ''.join([chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)])
print(flag)
