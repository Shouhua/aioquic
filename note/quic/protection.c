/**
 * https://datatracker.ietf.org/doc/html/rfc9001#name-sample-packet-protection
 * OpenSSl version: 3.0.2
 * gcc -Wall -Wextra -pedantic -g -o protection protection.c -lssl -lcrypto
 * https://github.com/openssl/openssl/issues/12220 why aes-128-gcm is not working on command line
 * openssl kdf -keylen 32 -kdfopt digest:SHA2-256 -kdfopt hexkey:8394c8f03e515708 -kdfopt hexsalt:38762cf7f55934b34d179ae6a4c80cadccbb7f0a -kdfopt hexinfo:00200f746c73313320636c69656e7420696e00 HKDF
 * echo -e -n "\\xd1\\xb1\\xc9\\x8d\\xd7\\x68\\x9f\\xb8\\xec\\x11\\xd2\\x42\\xb1\\x23\\xdc\\x9b" > sample.txt
 * openssl enc -aes-128-ecb -v -p -e -nosalt -K 9f50449e04a0e810283a1e9933adedd2 -in sample.txt -out sample.aes
 */

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof(a[0]))
#define PAYLOAD_ALGORITHM "aes-128-gcm"
#define HEADER_ALGORITHM "aes-128-ecb"

/* 如果数据是16进制格式数据，可以利用 OPENSSL_hexstr2buf 将16进制转化为二进制数据, 比如
** char *header_hex = "c300000001088394c8f03e5157080000449e00000002";
** size_t header_len = 22;
** char *header = NULL;
** int decoded_header_len = 0;
** header = OPENSSL_hexstr2buf(header_hex, &decoded_header_len);
** if(!header || decoded_header_len != header_len)
** {
** 		fprintf(stderr, "Wrong header \"%s\", must be %lu hex digits\n", header_hex, header_len * 2);
** }
** 注意使用OPENSSL_free释放
** OPENSSL_free(header);
*/
unsigned char header[] = {195, 0, 0, 0, 1, 8, 131, 148, 200, 240, 62, 81, 87, 8, 0, 0, 68, 158, 0, 0, 0, 2};
unsigned char payload[] = {6, 0, 64, 241, 1, 0, 0, 237, 3, 3, 235, 248, 250, 86, 241, 41, 57, 185, 88, 74, 56, 150, 71, 46, 196, 11, 184, 99, 207, 211, 232, 104, 4, 254, 58, 71, 240, 106, 43, 105, 72, 76, 0, 0, 4, 19, 1, 19, 2, 1, 0, 0, 192, 0, 0, 0, 16, 0, 14, 0, 0, 11, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 255, 1, 0, 1, 0, 0, 10, 0, 8, 0, 6, 0, 29, 0, 23, 0, 24, 0, 16, 0, 7, 0, 5, 4, 97, 108, 112, 110, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 147, 112, 178, 201, 202, 164, 127, 186, 186, 244, 85, 159, 237, 186, 117, 61, 225, 113, 250, 113, 245, 15, 28, 225, 93, 67, 233, 148, 236, 116, 215, 72, 0, 43, 0, 3, 2, 3, 4, 0, 13, 0, 16, 0, 14, 4, 3, 5, 3, 6, 3, 2, 3, 8, 4, 8, 5, 8, 6, 0, 45, 0, 2, 1, 1, 0, 28, 0, 2, 64, 1, 0, 57, 0, 50, 4, 8, 255, 255, 255, 255, 255, 255, 255, 255, 5, 4, 128, 0, 255, 255, 7, 4, 128, 0, 255, 255, 8, 1, 16, 1, 4, 128, 0, 117, 48, 9, 1, 16, 15, 8, 131, 148, 200, 240, 62, 81, 87, 8, 6, 4, 128, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
unsigned char key[] = {31, 54, 150, 19, 221, 118, 213, 70, 119, 48, 239, 203, 227, 177, 162, 45};
unsigned char hp[] = {159, 80, 68, 158, 4, 160, 232, 16, 40, 58, 30, 153, 51, 173, 237, 210};
unsigned char iv[] = {250, 4, 75, 47, 66, 163, 253, 59, 70, 251, 37, 92};
unsigned char nonce[] = {250, 4, 75, 47, 66, 163, 253, 59, 70, 251, 37, 94};

void print_hex(char *label, unsigned char *data, int len)
{
	fprintf(stdout, "%s(%d): ", label, len);
	for (int i = 0; i < len; i++)
	{
		fprintf(stdout, "%02x ", data[i]);
	}
	fprintf(stdout, "\n");
}

int main()
{
	/* 对称加密时，密文大小最大可能到len(plaintext)+block_size-1
	** https://www.openssl.org/docs/man3.1/man3/EVP_EncryptUpdate.html
	** EVP_EncryptUpdate()的description里面有说到这个注意
	*/
	unsigned char outbuf[4096];
	unsigned char tag[16];
	unsigned char sample[16];
	unsigned char mask[31];
	int outlen, masklen, temlen;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = NULL;

	// payload encryption
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
	{
		fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if (!(cipher = EVP_CIPHER_fetch(NULL, PAYLOAD_ALGORITHM, NULL)))
	{
		fprintf(stderr, "EVP_get_cipherbyname failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if (!EVP_CipherInit_ex(
			ctx,
			cipher,
			NULL,
			key, nonce, 1))
	{
		fprintf(stderr, "EVP_CipherInit_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}

	/* !!!!!!!!!!!!!NOTE!!!!!!!!!!*/
	/* https://datatracker.ietf.org/doc/html/rfc9001#name-aead-usage
	** 加密payload时，header时The associated data
	** https://www.openssl.org/docs/man3.1/man3/EVP_EncryptUpdate.html
	** https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
	** 对于AEAD类型的操作模型，比如GCM，CCM等，openssl需要先使用EVP_CipherUpdate函数添加AAD或者associated data时，并且设置out参数为NULL，然后添加需要加密的文本
	*/
	if (!EVP_CipherUpdate(ctx, NULL, &outlen, header, ARRAY_LEN(header)))
	{
		fprintf(stderr, "EVP_CipherUpdate header failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if (!EVP_CipherUpdate(ctx, outbuf, &outlen, payload, ARRAY_LEN(payload)))
	{
		fprintf(stderr, "EVP_CipherUpdate payload failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if (!EVP_EncryptFinal_ex(ctx, NULL, &temlen))
	{
		fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
	{
		fprintf(stderr, "EVP_CIPHER_CTX_ctl failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	outlen += temlen;
	EVP_CIPHER_CTX_free(ctx);
	print_hex("protected payload", outbuf, 16);
	print_hex("AEAD tag", tag, ARRAY_LEN(tag));

	// header encryption
	ctx = NULL;
	cipher = NULL;
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
	{
		fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if (!(cipher = EVP_CIPHER_fetch(NULL, HEADER_ALGORITHM, NULL)))
	{
		fprintf(stderr, "EVP_get_cipherbyname failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if (!EVP_CipherInit_ex(
			ctx,
			cipher,
			NULL,
			hp, NULL, 1))
	{
		fprintf(stderr, "EVP_CipherInit_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}

	memcpy(sample, outbuf, 16);
	print_hex("sample", sample, ARRAY_LEN(sample));

	if (!EVP_CipherUpdate(ctx, mask, &masklen, sample, 16))
	{
		fprintf(stderr, "EVP_CipherUpdate failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if (!EVP_EncryptFinal_ex(ctx, mask + masklen, &temlen))
	{
		fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	masklen += temlen;
	EVP_CIPHER_CTX_free(ctx);

	print_hex("mask", mask, masklen);
	header[0] ^= mask[0] & 0x0f;
	for (int i = 0; i < 4; i++)
	{
		header[18 + i] ^= mask[i + 1];
	}
	print_hex("protected header", header, ARRAY_LEN(header));
	return 0;
}
