#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>

#define IV_LEN 12
#define TAG_LEN 16

/* 测试数据来源 : https: // datatracker.ietf.org/doc/html/rfc8439#section-2.8.2 */
// uint8_t data[] = {
// 	0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
// 	0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
// 	0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
// 	0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
// 	0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
// 	0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
// 	0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
// 	0x74, 0x2e};

// uint8_t aad[] = {
// 	0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};

// uint8_t key[] = {
// 	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
// 	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};

// uint8_t nonce[] = {
// 	0x07, 0x00, 0x00, 0x00,
// 	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};

// uint8_t tag[] = {
// 	0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91};

/* 测试数据来源 : https: // datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
gcc -g -Wall -Wextra -pedantic chacha20_poly1305.c -o chacha20_poly1305 -lcrypto && \
	./chacha20_poly1305 \
		808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f \
		070000004041424344454647 \
		50515253c0c1c2c3c4c5c6c7 \
		4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e
*/
/* 测试数据来源 : https://datatracker.ietf.org/doc/html/rfc9001#section-a.5-5
iv 对应文档中的nonce, 由文档中的iv和packet number计算得到
add对应unprotected header
plaintext对应unprotected payload
gcc -g -Wall -Wextra -pedantic chacha20_poly1305.c -o chacha20_poly1305 -lcrypto && \
	./chacha20_poly1305 \
		c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8 \
		e0459b3474bdd0e46d417eb0 \
		4200bff4 \
		01
*/

void print_hex(char *label, unsigned char *data, int len)
{
	fprintf(stdout, "%s(%d): ", label, len);
	for (int i = 0; i < len; i++)
	{
		fprintf(stdout, "%02x ", data[i]);
	}
	fprintf(stdout, "\n");
}

/* convert hex string to binary string
** str source hex string
** str_len destination string length
*/
unsigned char *hexstr2buf(const char *str, int *str_len)
{
	size_t len = strlen(str);
	int res_len;
	if (len % 2 != 0)
		return NULL;
	res_len = len / 2 + 1;
	unsigned char *res = (unsigned char *)malloc(res_len);

	for (size_t i = 0; i < len; i += 2)
	{
		sscanf(str + i, "%2hhx", res + i / 2);
	}
	*(res + res_len - 1) = '\0';
	if (str_len)
		*str_len = res_len - 1;
	return res;
}

int main(int argc, char *argv[])
{
	/* key iv add plaintext*/
	if (argc != 5)
	{
		fprintf(stderr, "Usage: ./chacha20_poly1305 KEY IV ADD PLAINTEXT\n");
		exit(-1);
	}

	int aad_len, plaintext_len, outlen;
	uint8_t out[4096];
	uint8_t tagout[TAG_LEN];

	unsigned char *key = hexstr2buf(argv[1], NULL);
	unsigned char *iv = hexstr2buf(argv[2], NULL);
	unsigned char *aad = hexstr2buf(argv[3], &aad_len);
	unsigned char *plaintext = hexstr2buf(argv[4], &plaintext_len);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, IV_LEN, 0);
	EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv);

	EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len);
	EVP_EncryptUpdate(ctx, out, &outlen, plaintext, plaintext_len);
	print_hex("ciphertext", out, outlen);

	EVP_EncryptFinal_ex(ctx, out, &outlen);
	print_hex("ciphertext final", out, outlen);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tagout);
	print_hex("auth tag", tagout, TAG_LEN);

	free(key);
	free(iv);
	free(aad);
	free(plaintext);
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}