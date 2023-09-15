## 2023-09-14
### [Sock5协议](https://datatracker.ietf.org/doc/html/rfc1928)
1. IPv6
目前环境不支持IPv6，无法测试
2. close_wait
```sudo lsof -i:1080```, 原因时被动关闭方(server)，发送完fin，应用程序没有正确检测socket关闭状态导致, 需要合适的时候关闭socket
3. 解析域名时，需要判断下客户端是否是域名，还是IPv4/IPv6，chrome中的某个插件直接将IPv4/6地址当作域名发送
4. wireshark会根据端口显示协议，比如使用1080端口，即使不是Socks5协议，也会显示该Socks协议

实现的[Socks5 server](./socks5_server.py), 监听1080, client使用chrome的某插件，配置服务的地址, 如果本地测试udp代理，使用如下文件和工具:  
- [client](./socks5_client.py), 监听1081
- [udp echo server](./udp_echo_server.py) 监听9000
- 启动nc模拟client发送消息到[Socks5 client](./socks5_client.py)   
```shell
nc -v -4 -t localhost 1081
# hello
# hello
```
发送消息后，能看到nc收到echo消息, **Scoks5 client代码里面写死了目的地**
## 2023-09-11
### Message Digest
1. Message digest also known as **cryptographic hashes**
2. avalanche(雪崩) effect: any change to the message, big or small, must result in an extensive change to the digest  
3. SHA-2 family, SHA256 is currently the default hash function that's used in the TLS protocol, as well as the default signing function for X.509 and SSH keys.  
### MAC and HMAC(Hash-based Message Authentication Code)
1. MAC_function(message, secret_key)  
2. 相比于Message Digest仅提供完整性(integrity), MAC还提供了不可伪造保护，因为需要密钥(authenticity). 相对于Digital Signature，数字签名还提供了不可否认性，因为使用私钥签名，私钥只在一个人手中  
### KDF(Key Derivation Function), 代表有PBKDF2, scrypt, HKDF(HMAC-based KDF)等
1. encryption key和password区别
Encryption key用于对称加密算法中，一般来说，需要固定长度位数，可读性差; password则相反
2. KDF takes the following parameters
IKM(Input Key Material), Salt, Info(Application-specific information), PRF(Pseudorandom Function), Function-specific params(interation count or others(scrypt使用参数)), OKM(Output Key Material) length
### Asymmetric Encryption and Decryption
1. a private key and a public key form a **keypair**
2. Man in the Middle attac(中间人攻击)，提起非对称加密就要提及中间人攻击，密钥运送问题
3. 非对称加密算法(asymmetric crypto algorithm)有RSA, DSA, ECDSA, DH, ECDH等算法
### Certificates and TLS
```shell
openssl genpkey -algorithm ED448 -out root_keypair.pem
openssl pkey -pubout -in root_keypair.pem -noout -text
openssl req -new -subj "/CN=Root CA" -addext "basicConstraints=critical,CA:TRUE" -key root_keypair.pem -out root_csr.pem
openssl x509 -req -in root_csr.pem -copy_extensions copyall -key root_keypair.pem -days 3650 -out root_cert.pem
openssl genpkey -algorithm ED448 -out intermediate_keypair.pem
openssl req -new -subj "/CN=Root CA" -addext "basicConstraints=critical,CA:TRUE" -key intermediate_keypair.pem -out intermediate_csr.pem
openssl x509 -req -in intermediate_csr.pem -copy_extensions copyall -CA root_cert.pem -CAkey root_keypair.pem -days 3650 -out intermediate_cert.pem
openssl verify -verbose -show_chain -trusted root_cert.pem intermediate_cert.pem
```
## 2023-09-04
```python
# bytes to int
version = b"\x03\x03"
int.from_bytes(version, "big")
# bytes to ascii
raw_data = b"hello"
plain_text = raw_data.decode()
assert plain_text.encode() == raw_data
```
## 2023-08-30
计算handshake相关密钥，使用的hash包括client hello, server hello, 不包括各自的recored header(5 bytes)
Tls1.3中计算application相关密钥时候，需要使用header hash，内容包括client hello, server hello, encrypted extension, Certificate, Certificate Verify, Finished, 假设没有CertificateRequest, 不包括各自的record header(5 bytes)
## 2023-08-29
1. Python和C互相调用, 场景虽然用到不多，但是考虑性能的代码却要使用，比如crypto相关的AEAD，head protection代码使用C代码重写  
**需要注意的是，windows和linux平台import时的模块后缀有不同，网上大多举例windows平台，在linux平台可能会报模块没找到问题**
```python
# 判断当前平台的支持导入后缀
import importlib
print(importlib.machinery.all_suffixes())
# window: ['.py', '.pyw', '.pyc', '.cp311-win_amd64.pyd', '.pyd']
# linux: ['.py', '.pyc', '.cpython-310-x86_64-linux-gnu.so', '.abi3.so', '.so']
# python导入的路径
import sys
print(sys.path)
```
## 2023-08-28
### python
1. ```bytes.fromhex("0003") -> b'\x00\x03'```
2. ```int.from_bytes(b"\x00\x03", byteorder="big") -> '0x3'```
3. [from contextlib import contextmanager](https://docs.python.org/3/library/contextlib.html)
代码中大量应用，比如在解析TLS协议时候，新申请空间，yeild，最后做些校验或者释放资源
```python
from contextlib import contextmanager

@contextmanager
def managed_resource(*args, **kwds):
    # Code to acquire resource, e.g.:
    resource = acquire_resource(*args, **kwds)
    try:
        yield resource
    finally:
        # Code to release resource, e.g.:
        release_resource(resource)

with managed_resource(timeout=3600) as resource:
    # Resource is released at the end of this block,
    # even if code in the block raises an exception
```
### [tls1.3](https://www.gabriel.urdhr.fr/2022/02/26/tls1.3-intro/)
- TLS1.3有三种握手类型
1. (EC)DHE
2. PSK-only
3. PSK with (EC)DHE
- 各个过程密钥生成过程  
**hello_hash是不含有record header的，即不包括记录的前5个字节**
```python
# early key生成过程
early_secret = HKDF_Extract(length=32, key=psk, salt=b"\x00")
binder_key = HKDF_Expand(length=32, label="tls13 res binder", hash=SHA256(b""), key=early_secret)
client_early_traffic_secret = HKDF_Expand(lenght=32, label="tls13 c e traffic", hash=client_hello_hash, key=early_secret)
early_exporter_master_secret = HKDF_Exapnd(length=32, label="tls13 e exp master", hash=client_hello_hash, key=early_secret)
# 握手密钥生成过程
shared_secret = X25519.exchange(peer_pub_key, local_private_key)
if resumption_keys:
     early_secret = resumption_keys.early_secret
else:
     early_secret = HKDF_Extract(length=32, key=b"\x00"*32, salt=b"\x00")
derived_secret = HKDF_Exapnd(length=32, label=b"tls13 derived", hash=SHA256(b""), key=early_secret)
handshake_secret = HKDF_Extract(length=32, key=shared_secret, salt=derived_secret)
client_handshake_traffic_secret = HKDF_Expand(length=32, label="tls13 c hs traffic", hash=hello_hash, key=handshake_secret)
server_handshake_traffic_secret = HKDF_Expand(length=32, label="tls13 s hs traffic", hash=hello_hash, key=handshake_secret)
client_handshake_key = HKDF_Expand(length=16, label="tls13 key", hash=b"", key=client_handshake_traffic_secret)
client_handshake_key = HKDF_Expand(length=12, label="tls13 iv", hash=b"", key=client_handshake_traffic_secret)
server_handshake_key = HKDF_Expand(length=16, label="tls13 key", hash=b"", key=server_handshake_traffic_secret)
server_handshake_key = HKDF_Expand(length=12, label="tls13 iv", hash=b"", key=server_handshake_traffic_secret)
# 应用密钥生成过程
derived_secret = HKDF_Expand(length=32, label="tls13 derived", hash=SHA256(b""), key=handshake_secret)
master_secret = HKDF_Extract(length=32, key=b"\x00"*32, salt=derived_secret)
client_application_traffic_secret = HKDF_Expand(length=32, label="tls13 c ap traffic", hash=handshake_hash, key=master_secret)
client_application_key = HKDF_Expand(length=16, label="tsl13 key", hash=b"", key=client_application_traffic_secret)
client_application_iv = HKDF_Expand(length=12, label="tsl13 iv", hash=b"", key=client_application_traffic_secret)
server_application_traffic_secret = HKDF_Expand(length=32, label="tls13 s ap traffic", hash=handshake_hash)
server_application_key = HKDF_Expand(length=16, label="tsl13 key", hash=b"", key=server_application_traffic_secret)
server_application_iv = HKDF_Expand(length=12, label="tsl13 iv", hash=b"", key=server_application_traffic_secret)
```
## 2023-08-25
### 阅读[Demystifying cryptography with OpenSSL 3.0](https://download.bibis.ir/Books/Security/IT-Security/Cryptography/2022/Demystifying-Cryptography-with-OpenSSL-3.0-Discover-the-best-techniques-to-enhance-your-network-security-with-OpenSSL-3.0-(Khlebnikov,-AlexeiAdolfsen,-Jarle)_bibis.ir.pdf)
1. an encryption key is not the same as a password, but an encryption key can be derived from a password
2. It is important to know that when a message is signed, usually, the digital signature algorithm is not applied to the message itself. Instead, the signature algorithm is applied to the message digest, which is produced by some cryptographic hash functions, such as SHA-256. 
3. asymmetric encryption每次最多加密自己的key长度的plain text，这就是为什么RSA要使用加密session key(symmetric encrpytion)的方式, 说白了，非对称加密是为了解决对称密钥传送的问题
4. DSA(Digital Signature Algorithm)使用非对加密的private key加密信息的**hash**，private_key_sign(sha(message))
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
8. **解密大致跟加密步骤差不多，有一点需要注意，short packet中有key phase(first_byte & 4)，key phase是变更时，header protection remove还是使用原先的密钥(hp)，payload解密使用新生成的密钥，原因是只有拿到里header才能确认key phase是否变更了:)**
9. Openssl command line encryption
```shell
# 使用HKDF算法获取client key
# key(cid): 8394c8f03e515708
# salt: 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
# label(encode('tls client in')): 00200f746c73313320636c69656e7420696e00
openssl kdf -keylen 32 -kdfopt digest:SHA2-256 -kdfopt hexkey:8394c8f03e515708 -kdfopt hexsalt:38762cf7f55934b34d179ae6a4c80cadccbb7f0a -kdfopt hexinfo:00200f746c73313320636c69656e7420696e00 HKDF
# 根据protected payload内容获取sample，然后使用AES-128-ECB算法获取mask
echo -e -n "\\xd1\\xb1\\xc9\\x8d\\xd7\\x68\\x9f\\xb8\\xec\\x11\\xd2\\x42\\xb1\\x23\\xdc\\x9b" > sample.txt
openssl enc -aes-128-ecb -v -p -e -nosalt -K 9f50449e04a0e810283a1e9933adedd2 -in sample.txt -out sample.aes
```