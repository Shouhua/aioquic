#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>

const long KEY_LENGTH = 32;
const size_t IV_LENGTH = 12;
const size_t AUTH_TAG_LENGTH = 16;

int encrypt(FILE* in_file, FILE* out_file, const unsigned char* key, FILE* stderr);

int main(int argc, char *argv[])
{
	int exit_code = 0;

	FILE *in_file = NULL;
	FILE *out_file = NULL;
	unsigned char* key = NULL;

	if(argc != 4)
	{
		fprintf(stderr, "Usage: %s INPUT_FILE OUTPUT_FILE KEY_HEX\n", argv[0]);
		exit_code = 1;
		goto cleanup;
	}

	const char* in_fname = argv[1];
	const char* out_fname = argv[2];
	const char* key_hex = argv[3];

	long decoded_key_len = 0;
	key = OPENSSL_hexstr2buf(key_hex, &decoded_key_len);
	if(!key || decoded_key_len != KEY_LENGTH)
	{
		fprintf(stderr, "Wrong key \"%s\", must be %lu hex digits\n", key_hex, KEY_LENGTH*2);
		goto failure;
	}

	in_file = fopen(in_fname, "rb");
	if(!in_file)
	{
		fprintf(stderr, "Could not open input file \"%s\"\n", in_fname);
		goto failure;
	}
	out_file = fopen(out_fname, "wb");
	if(!out_file)
	{
		fprintf(stderr, "Could not open input file \"%s\"\n", out_fname);
		goto failure;
	}
	int err = encrypt(in_file, out_file, key, stderr);
	if(err)
	{
		fprintf(stderr, "Encryption failed\n");
		goto failure;
	}
	fprintf(stdout, "Encryption succeeded\n");
	goto cleanup;

failure:
	exit_code = 1;
cleanup:
	OPENSSL_free(key);
	if(out_file)
		fclose(out_file);
	if(in_file)
		fclose(in_file);
	return exit_code;
}

int encrypt(FILE* in_file, FILE* out_file, const unsigned char* key, FILE* error_stream)
{
	int exit_code = 0;
	EVP_CIPHER_CTX* ctx = NULL;

	unsigned char iv[IV_LENGTH];
	unsigned char auth_tag[AUTH_TAG_LENGTH];

	const size_t BUF_SIZE = 64 * 1024;
	const size_t BLOCK_SIZE = 16;
	unsigned char* in_buf = malloc(BUF_SIZE);
	unsigned char* out_buf = malloc(BUF_SIZE + BLOCK_SIZE);
	if(!in_buf || !out_buf)
	{
		if(error_stream)
			fprintf(error_stream, "Could not allocate buffers\n");
		goto failure;
	}


	RAND_bytes(iv, IV_LENGTH);
	fwrite(iv, 1, IV_LENGTH, out_file);
	if(ferror(out_file))
	{
		if(error_stream)
			fprintf(error_stream, "Could not write IV to output file\n");
		goto failure;
	}
	ctx = EVP_CIPHER_CTX_new();
	int ok = EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv);
	if(!ctx || !ok)
	{
		if(error_stream)
			fprintf(error_stream, "Could not initialize encryption\n");
		goto failure;
	}

	while(!feof(in_file))
	{
		size_t in_nbytes = fread(in_buf, 1, BUF_SIZE, in_file);
		if(ferror(out_file))
		{
			if(error_stream)
				fprintf(error_stream, "Could not read from input file\n");
			goto failure;
		}
		int out_nbytes = 0;
		ok = EVP_EncryptUpdate(ctx, out_buf, &out_nbytes, in_buf, in_nbytes);
		if(!ok)
		{
			if(error_stream)
				fprintf(error_stream, "Could not encrypt data chunk\n");
			goto failure;
		}
		fwrite(out_buf, 1, out_nbytes, out_file);
		if(ferror(out_file))
		{
			if(error_stream)
				fprintf(error_stream, "Could not write to output file\n");
			goto failure;
		}
	}

	int out_nbytes = 0;
	ok = EVP_EncryptFinal(ctx, out_buf, &out_nbytes);
	if(!ok)
	{
		if(error_stream)
			fprintf(error_stream, "Could not finalize encryption\n");
		goto failure;
	}

	fwrite(out_buf, 1, out_nbytes, out_file);
	if(ferror(out_file))
	{
		if(error_stream)
			fprintf(error_stream, "Could not write to output file\n");
		goto failure;
	}

	ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LENGTH, auth_tag);
	if(!ok)
	{
		if(error_stream)
			fprintf(error_stream, "Could not get authentication tag\n");
		goto failure;
	}

	fwrite(auth_tag, 1, AUTH_TAG_LENGTH, out_file);
	if(ferror(out_file))
	{
		if(error_stream)
			fprintf(error_stream, "Could not write authentication tag to output file\n");
		goto failure;
	}

	goto cleanup;

failure:
	exit_code = 1;
cleanup:
	EVP_CIPHER_CTX_free(ctx);
	free(out_buf);
	free(in_buf);
	return exit_code;
}