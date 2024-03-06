/*
** https://www.openssl.org/docs/man3.2/man7/Ed25519.html
** 签名算法默认先hash在sign，因此一般签名算法需要指定hash算法，也因此可以递归update需要签名的内容
** 本程序用于描述openssl Ed25519。EdDSA有两点跟其他签名算法不一样：
** 1. EdDSA分为pureEdDSA和hashEdDSA，openssl默认时前者，内部集成了hash函数，所以初始化不要指定
** 2. 需要一次性加入需要签名的内容，使用EVP_DigestSign(文档中叫oneshot类型的函数)一次就行
*/

/**
 * Run
 * echo -n "hello,world" ~/somefile.txt
 * openssl genpkey -algorithm ED25519 -out ~/ed25519.key
 * openssl pkeyutl -sign -inkey ed25519.key -in ~/somefile.txt -rawin -out ~/somefile.txt.sign
 * gcc -Wall -Wextra -pedantic -g ed25519.c -o ed25519 -lcrypto && ./ed25519 ~/somefile.txt ~/somefile.sign ~/ed25519.key
 * ckdum ~/somefile*.sign
 * rm -v ~/somefile.txt ~/ed25519.key ~/somefile.txt.sign ~/somefile.sign
 */
#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		fprintf(stderr, "USAGE: ./ed25519 ~/somefile.txt ~/somefile.sign ~/25519.key");
		exit(-1);
	}

	int exit_code = 0;
	size_t siglen;
	unsigned char *input = NULL, *output = NULL;
	long in_len;

	const char *in_fname = NULL, *out_fname = NULL, *pkey_fname = NULL;
	FILE *in_file, *out_file = NULL, *pkey_file = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *md_ctx = NULL;

	in_fname = argv[1];
	in_file = fopen(in_fname, "rb");
	if (!in_file)
	{
		perror("fopen failed");
		goto failure;
	}
	if (fseek(in_file, 0, SEEK_END) == -1)
	{
		perror("fseek end failed");
		goto failure;
	}
	if ((in_len = ftell(in_file)) == -1)
	{
		perror("ftell failed");
		goto failure;
	}
	if (fseek(in_file, 0, SEEK_SET))
	{
		perror("fseek begin failed");
		goto failure;
	}

	out_fname = argv[2];
	out_file = fopen(out_fname, "w+");
	if (!in_file)
	{
		perror("fopen failed");
		goto failure;
	}

	input = (unsigned char *)malloc(in_len + 1);
	if (!input)
	{
		fprintf(stderr, "malloc failed\n");
		goto failure;
	}
	if (fread(input, 1, in_len, in_file) != (size_t)in_len)
	{
		perror("fread failed");
		goto failure;
	}

	pkey_fname = argv[3];
	pkey_file = fopen(pkey_fname, "rb");
	if (!pkey_file)
	{
		perror("fopen pkey_fname(argc[3])");
		goto failure;
	}
	pkey = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
	if (!pkey)
	{
		fprintf(stderr, "PEM_read_PrivateKey failed");
		goto failure;
	}

	md_ctx = EVP_MD_CTX_new();
	const OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string("instance", "Ed25519ctx", 10),
		OSSL_PARAM_construct_octet_string(
			"context-string",
			(unsigned char *)"A protocol defined context string", 33),
		OSSL_PARAM_END,
	};
	/* 这里不需要说明hash函数，因为EdDSA(默认时pureEdDSA，自带hash)*/
	if (!EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, NULL, pkey, params))
	{
		fprintf(stderr, "Message digest initialization failed.\n");
		ERR_print_errors_fp(stderr);
		goto failure;
	}

	/* 需要一次性传入需要签名的内容，这个跟其他签名算法不一样 */
	/* 第一次获取输出长度 */
	if (EVP_DigestSign(md_ctx, NULL, &siglen, input, in_len) != 1)
	{
		ERR_print_errors_fp(stderr);
		goto failure;
	}
	output = (unsigned char *)OPENSSL_zalloc(siglen);
	/* 第二次填充sign结果 */
	if (EVP_DigestSign(md_ctx, output, &siglen, input, in_len) != 1)
	{
		ERR_print_errors_fp(stderr);
		goto failure;
	}

	if (fwrite(output, 1, siglen, out_file) != siglen)
	{
		fprintf(stderr, "fwrite failed\n");
		goto failure;
	}
	goto cleanup;

failure:
	exit_code = -1;
cleanup:
	if (input)
		free(input);
	if (in_file)
		fclose(in_file);
	if (out_file)
		fclose(out_file);
	if (pkey_file)
		fclose(pkey_file);
	if (output)
		OPENSSL_free(output);
	if (md_ctx)
		EVP_MD_CTX_free(md_ctx);
	return exit_code;
}