## 关于
这个文件夹内容主要是关于QUIC协议加解密算法在C和Python中的实践。QUIC-TLS细节主要参考[文档](https://datatracker.ietf.org/doc/html/rfc9001)和`aioquic`代码。主要涉及到的算法有：
1. Packet Protection: `AES-128-GCM` 或者 `CHACHA20_POLY1305`
2. Header Projection: `AES-128-ECM` 或者 `CHACHA20_POLY1305`

## 文件说明
`quic_protection.py` 主要根据`QUIC`协议`packet`信息进行上述加密测试, 主要使用`pyopenssl`。<br>
`protection.c` 			 使用AES算法测试对应`Python`文件内容<br>
`chacha20*`  			   文档主要验证`CHACHA20_POLY1305`算法在`C`和`Python`中的相关库支持情况

## C和Python中库CHACHA20和CHACHA20_POLY1305算法支持情况
### C
OpenSSL库全部支持
### Python
主要有两个库，[pycryptodom](https://www.pycryptodome.org/src/cipher/chacha20)和[pycryptography](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305)
#### pycryptodom
支持CHACHA20和CHACHA20_POLY1305, 但是不能自定义counter, 不过这种情况及其罕见; 
#### pycryptography
支持`CHACHA20_POLY1305`的[RFC 8439文档](https://datatracker.ietf.org/doc/html/rfc8439), **但是她的CHACHA20[不兼容](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20)RFC 8439**。