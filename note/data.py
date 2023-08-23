payload = 'd1b1c98dd7689fb8ec11d242b123dc9b'
payload_list = [r'\x' + str(payload[i:i+2]) for i in range(0, len(payload), 2)]
# payload_list = [hex(int(payload[i:i+2], 16)) for i in range(0, len(payload), 2)]
print(payload_list)
print(len(payload_list))