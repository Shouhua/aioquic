# pyCrypto不在维护，pyCryptodom的API兼容前者。作者推荐pyCryptography和pyCryptodom
# pyCryptodom库的ChaCha20和ChaCha20-Poly1305是遵循RFC 8439(https://datatracker.ietf.org/doc/html/rfc8439)
# 但是不能指定counter
# pyCryptography 不遵循RFC 8439

# python3 -m pip install pycryptodom

from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from binascii import hexlify

# https://www.pycryptodome.org/src/cipher/chacha20
# PyCryptodome ChaCha20
# 测试数据来源: https://datatracker.ietf.org/doc/html/rfc8439#section-2.4.2
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
nonce = bytes.fromhex("000000000000004a00000000")
cipher = ChaCha20.new(key=key, nonce=nonce)
plaintext = bytes.fromhex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
)

ciphertext = cipher.encrypt(plaintext)
print("ChaCha20 ciphertext: {hexlify(ciphertext)}")

# https://www.pycryptodome.org/src/cipher/chacha20_poly1305
# PyCryptodome ChaCha20-Poly1305
# 测试数据来源: https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
cp_key = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
)
cp_iv = bytes.fromhex("070000004041424344454647")
aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
cp = ChaCha20_Poly1305.new(key=cp_key, nonce=cp_iv)
cp.update(aad)
cp_ciphertext, cp_tag = cp.encrypt_and_digest(plaintext)
print(f"ChaCha20-Poly1305 ciphertext: {hexlify(cp_ciphertext)}")
print(f"ChaCha20-Poly1305 tag: {hexlify(cp_tag)}")
