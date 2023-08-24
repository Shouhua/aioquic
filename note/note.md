## 2023-08-24
1. long header packet需要加密第一个自己的后4位，short header packet是第一个自己的后5位
```
Initial Packet {
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2) = 0,
     Reserved Bits (2),         # Protected
     Packet Number Length (2),  # Protected
     Version (32),
     DCID Len (8),
     Destination Connection ID (0..160),
     SCID Len (8),
     Source Connection ID (0..160),
     Token Length (i),
     Token (..),
     Length (i),
     Packet Number (8..32),     # Protected
     Protected Payload (0..24), # Skipped Part
     Protected Payload (128),   # Sampled Part
     Protected Payload (..)     # Remainder
}

   1-RTT Packet {
     Header Form (1) = 0,
     Fixed Bit (1) = 1,
     Spin Bit (1),
     Reserved Bits (2),         # Protected
     Key Phase (1),             # Protected
     Packet Number Length (2),  # Protected
     Destination Connection ID (0..160),
     Packet Number (8..32),     # Protected
     Protected Payload (0..24), # Skipped Part
     Protected Payload (128),   # Sampled Part
     Protected Payload (..),    # Remainder
}
```
2. 使用包加密后，再使用头部加密
3. 头部加密使用头保护密钥和packet payload中的密文采样。因为packet number length是不定的，最大4 bytes，采样的起始offset使用4减去实际的packet number length
4. aioquic中header_length是payload之前的内容长度, 截至packet number的尾部，例如，initial packet中长度是开始至packet number结尾; packet header中的rest length = packet nuber length + paylaod length + 16(AEAD tag)
5. short header packet首字节中第6位表示key phase，用于提醒对端需要更新密钥, 处理过程详见[此处](./src/aioquic/quic/crypto.py#L82)
6. TLS1.3中，使用密钥推导算法[HKDF](https://suntus.github.io/2019/05/09/HKDF%E7%AE%97%E6%B3%95/)计算密钥
```python
# protect client initial packet
initial_salt = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
initial_secret = hkdf_extract(initial_salt, cid)
client_initial_secret = hkdf_expand_label(initial_secret, "client in", "", 32)
algorithm = hashes.SHA256()
key = hkdf_expand_label(algorithm, client_initial_secret, "quic key", "", 16)
iv  = hkdf_expand_label(algorithm, client_initial_secret, "quic iv", "", 12)
hp  = hkdf_expand_label(algorithm, client_initial_secret, "quic hp", "", 16)
hp_cipher_name, payload_cipher_name = (b"aes-128-ecb", b"aes-128-gcm")
nonce = iv xor pn
protected_payload = AEAD("aes-128-gcm", key, nonce).update(plain_head).update(plain_payload) # 包括16 bytes tag
sample_offset = MAX_PN_SIZE - pn_size
sample = protected_payload[sample_offset : sample_offset+16]
mask = AEAD("aes-128-ecb", hp).update(sample) # 16 bytes mask
header[0] ^= mask[0] & 0x0f
header[pn_offset..pn_offset+pn_size] ^= mask[1..pn_size]
protected_content = header + protected_payload
```
**Server initial packet protection like client, 需要注意的是cid还是使用client initial packet中的source destination id**, 具体实现参考[代码](./protection.py)，或者[C实现](./protection.c)  

7. [aioquic中receiver支持decode packet number，但是sender固定packet number length 为2](https://github.com/aiortc/aioquic/issues/200)
8. python中需要注意的两种字节表示
```python
raw = b'1234' # 内存中表示为31323334
hex_str = b'\x01\x02\x03\04' # 内存中表示为01020304

binascii.hexlify(raw) # b'31323334'
binascii.unhexlify(raw) # b'\x124'
binascii.a2b_hex(hex_str) # 01020304

# 首先将raw转化为内存形式0x31323334，然后取2个字节3132转化为整数
struct.unpack('HH', raw) # (12849, 13363) -> (0x3231, 0x3433)
struct.unpack('HH', hex_str) # (513, 1027) -> (0x201, 0x403)
struct.unpack('>HH', hex_str) # (258, 1027) -> (0x102, 0x304)
```