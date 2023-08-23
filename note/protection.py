import struct
import binascii
from typing import Tuple

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends.openssl.backend import backend

# https://blog.unasuke.com/2021/read-quic-initial-packet-by-ruby/

initial_salt = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
cid = binascii.unhexlify("8394c8f03e515708")
hp_cipher_name, aead_cipher_name = (b"aes-128-ecb", b"aes-128-gcm")
PN_MAX_SIZE = 4

LONG_CLIENT_PACKET_NUMBER = 2
LONG_SERVER_PACKET_NUMBER = 1
LONG_CLIENT_PLAIN_HEADER = binascii.unhexlify(
    "c300000001088394c8f03e5157080000449e00000002"
)
LONG_CLIENT_PLAIN_PAYLOAD = binascii.unhexlify(
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
    "75300901100f088394c8f03e51570806048000ffff"
) + bytes(917)

# https://datatracker.ietf.org/doc/html/rfc9001#appendix-A.3
LONG_SERVER_PACKET_NUMBER = 1
LONG_SERVER_PLAIN_HEADER = binascii.unhexlify(
    "c1000000010008f067a5502a4262b50040750001"
)
LONG_SERVER_PLAIN_PAYLOAD = binascii.unhexlify(
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
    "020304"
)

def hkdf_label(label: bytes, hash_value: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    return (
        struct.pack("!HB", length, len(full_label))
        + full_label
        + struct.pack("!B", len(hash_value))
        + hash_value
    )

def hkdf_expand_label(
    algorithm: hashes.HashAlgorithm,
    secret: bytes,
    label: bytes,
    hash_value: bytes,
    length: int,
) -> bytes:
    return HKDFExpand(
        algorithm=algorithm,
        length=length,
        info=hkdf_label(label, hash_value, length),
    ).derive(secret)

def hkdf_extract(
    algorithm: hashes.HashAlgorithm, salt: bytes, key_material: bytes
) -> bytes:
    h = hmac.HMAC(salt, algorithm)
    h.update(key_material)
    return h.finalize()

def derive_key_iv_hp(algorithm: hashes.HashAlgorithm, secret: bytes) -> Tuple[bytes, bytes, bytes]:
    return (
        hkdf_expand_label(algorithm, secret, b"quic key", b"", 16),
        hkdf_expand_label(algorithm, secret, b"quic iv", b"", 12),
        hkdf_expand_label(algorithm, secret, b"quic hp", b"", 16)
    )

def generate_nonce(iv: bytes, pn: int) -> bytes:
    nonce = list(iv)
    # TODO 大端，小段问题
    padding_pn = pn.to_bytes(8, 'little')
    # TODO 为什么使用这种交叉xor的方式
    # nonce  xor pn
    #   4        7
    #   11       0   
    for i in range(8):
        nonce[11 - i] ^= padding_pn[i]
    return bytes(nonce)

def encrypt_packet(is_client: bool, algorithm: hashes.HashAlgorithm, salt: bytes, cid: bytes, pn: int, pn_size: int, plain_header: bytes, plain_payload: bytes) -> bytes:
    initial_secret = hkdf_extract(algorithm, salt, cid)
    # 客户端 用于发送数据使用的密钥
    app_initial_secret = hkdf_expand_label(algorithm, initial_secret, b"client in" if is_client else b"server in", b"", 32)
    key, iv, hp = derive_key_iv_hp(algorithm, app_initial_secret)

    nonce = generate_nonce(iv, pn)

    evp_cipher = backend._lib.EVP_get_cipherbyname(aead_cipher_name)    
    backend.openssl_assert(evp_cipher != backend._ffi.NULL)
    ctx = backend._lib.EVP_CIPHER_CTX_new()
    ctx = backend._ffi.gc(ctx, backend._lib.EVP_CIPHER_CTX_free)
    res = backend._lib.EVP_CipherInit_ex(
        ctx,
        evp_cipher,
        backend._ffi.NULL, # ENGINE *impl
        backend._ffi.from_buffer(key), # unsigned char *key
        backend._ffi.from_buffer(nonce), # unsigned char *iv
        1, # int enc
    )
    backend.openssl_assert(res != 0)

    outlen = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherUpdate(
        ctx,
        backend._ffi.NULL,
        outlen,
        backend._ffi.from_buffer(plain_header),
        len(plain_header)
    )
    backend.openssl_assert(res != 0)
    buf = backend._ffi.new("unsigned char[]", len(plain_payload))
    res = backend._lib.EVP_CipherUpdate(
        ctx, 
        buf, 
        outlen, 
        backend._ffi.from_buffer(plain_payload), 
        len(plain_payload)
    )
    backend.openssl_assert(res != 0)
    processed_data = backend._ffi.buffer(buf, outlen[0])[:]

    res = backend._lib.EVP_CipherFinal_ex(ctx, backend._ffi.NULL, outlen)
    backend.openssl_assert(res != 0)
    backend.openssl_assert(outlen[0] == 0)
    tag_buf = backend._ffi.new("unsigned char[]", 16)
    res = backend._lib.EVP_CIPHER_CTX_ctrl(
        ctx, backend._lib.EVP_CTRL_AEAD_GET_TAG, 16, tag_buf
    )
    backend.openssl_assert(res != 0)
    tag = backend._ffi.buffer(tag_buf, 16)[:]
    protected_payload = processed_data + tag

    # header加密
    header_evp_cipher = backend._lib.EVP_get_cipherbyname(hp_cipher_name)    
    ctx = backend._lib.EVP_CIPHER_CTX_new()
    backend.openssl_assert(evp_cipher != backend._ffi.NULL)
    ctx = backend._ffi.gc(ctx, backend._lib.EVP_CIPHER_CTX_free)
    res = backend._lib.EVP_CipherInit_ex(
        ctx,
        header_evp_cipher,
        backend._ffi.NULL, # ENGINE *impl
        backend._ffi.from_buffer(hp), # unsigned char *key
        backend._ffi.NULL, # unsigned char *iv
        1, # int enc
    )
    sample_offset = PN_MAX_SIZE - pn_size
    sample = protected_payload[sample_offset : sample_offset + 16]
    maskbuf = backend._ffi.new("unsigned char[]", 16)
    masklen = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherUpdate(
        ctx, 
        maskbuf,
        masklen, 
        backend._ffi.from_buffer(sample), len(sample))
    mask = backend._ffi.buffer(maskbuf, masklen[0])[:]
    header_list = list(plain_header)
    header_list[0] ^= mask[0] & 0x0f # mask packet number length
    pn_offset = len(plain_header) - pn_size
    for i in range(pn_size):
        header_list[pn_offset+i] ^= mask[i+1] # mask packet number
    protected_header = bytes([header_list[i] for i in range(len(header_list))])
    if is_client == False:
        print(f'key: {binascii.hexlify(key)}')
        print(f'iv: {binascii.hexlify(iv)}')
        print(f'hp: {binascii.hexlify(hp)}')
        print(f'nonce: {binascii.hexlify(nonce)}')
        print(f'protected header: {binascii.hexlify(protected_header)}')
        print(f'protected payload: {binascii.hexlify(protected_payload)}')
        print(f'sample: {binascii.hexlify(sample)}')
        print(f'mask: {binascii.hexlify(mask)}')
    return protected_header + protected_payload



def main():
    client_protected_packet = encrypt_packet(
        True, 
        hashes.SHA256(), 
        initial_salt,
        cid,
        LONG_CLIENT_PACKET_NUMBER, 
        4,
        LONG_CLIENT_PLAIN_HEADER,
        LONG_CLIENT_PLAIN_PAYLOAD)
    print(f'client protected initial packet: {binascii.hexlify(client_protected_packet)}')

    server_protected_packet = encrypt_packet(
        False,
        hashes.SHA256(),
        initial_salt,
        cid,
        LONG_SERVER_PACKET_NUMBER,
        2,
        LONG_SERVER_PLAIN_HEADER,
        LONG_SERVER_PLAIN_PAYLOAD
    )
    print(f'server protected initial packet: {binascii.hexlify(server_protected_packet)}')

if __name__ == '__main__':
    main()