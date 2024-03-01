#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

void print_hex(char *label, unsigned char *data, int len)
{
	fprintf(stdout, "%s(%d): ", label, len);
	for (int i = 0; i < len; i++)
	{
		fprintf(stdout, "%02x ", data[i]);
	}
	fprintf(stdout, "\n");
}

unsigned char *hexstr2buf(const char *str)
{
	size_t len = strlen(str);
	if (len % 2 != 0)
		return NULL;
	size_t res_len = len / 2 + 1;
	unsigned char *res = (unsigned char *)malloc(res_len);

	for (int i = 0; i < len; i += 2)
	{
		sscanf(str + i, "%2hhx", res + i / 2);
	}
	*(res + res_len - 1) = '\0';
	return res;
}

int main()
{
	int ok = 0;
	/* 测试数据来源: https://datatracker.ietf.org/doc/html/rfc8439#section-2.4.2 */
	char *key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	char *iv_hex = "01000000000000000000004a00000000"; // 4bytes(32bits)counter + 12bytes(96bits)nonce
	char *plaintext_hex = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
	unsigned char *key, *iv, *plaintext;
	unsigned char out[4096];
	int outlen = 0;

	/* 使用OPENSSL_hexstr2buf */
	// long key_len, iv_len, plaintext_len;
	// key = OPENSSL_hexstr2buf(key_hex, &key_len);
	// iv = OPENSSL_hexstr2buf(iv_hex, &iv_len);
	// plaintext = OPENSSL_hexstr2buf(plaintext_hex, &plaintext_len);

	// printf("%lu, %lu, %lu\n", key_len, iv_len, plaintext_len);

	key = hexstr2buf(key_hex);
	iv = hexstr2buf(iv_hex);
	plaintext = hexstr2buf(plaintext_hex);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	ok = EVP_CipherInit_ex(ctx, EVP_chacha20(), NULL, key, iv, 1);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 16, NULL);

	ok = EVP_CipherUpdate(ctx, out, &outlen, plaintext, strlen(plaintext));

	print_hex("out", out, outlen);

	outlen = 0;
	EVP_EncryptFinal_ex(ctx, out, &outlen);
	print_hex("out", out, outlen);

	/* OPENSSL_free 可以判断NULL */
	OPENSSL_free(NULL);

	OPENSSL_free(key);
	OPENSSL_free(iv);
	OPENSSL_free(plaintext);
	EVP_CIPHER_CTX_free(ctx);

	return 0;
}