#include <openssl/evp.h>
#include <string.h>

#include "functions.h"

int aes256_cbc_enc_bin(
	const bytebuffer_t *	key,			// (I )Shared Secret(32byte)
	const bytebuffer_t *	in,				// (I )暗号化したいデータ(16byte)
	bytebuffer_t *		out				// ( O)暗号化されたデータ
	)
{
	EVP_CIPHER_CTX	*ctx = NULL;
	unsigned char	 iv[32];
	int		 len;
	int		 ok = -1;

	memset(iv, 0, sizeof(iv));
	out->ptr = NULL;
	out->len = 0;

	/* sanity check */
	if (in->len > INT_MAX || (in->len % 16) != 0 ||
	    (out->ptr = (unsigned char*)calloc(1, in->len)) == NULL) {
		log_str("%s: in->len=%zu", __func__, in->len);
		goto fail;
	}

	if (
		(ctx = EVP_CIPHER_CTX_new()) == NULL || key->len != 32 ||
	    !EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key->ptr, iv) ||
	    !EVP_CIPHER_CTX_set_padding(ctx, 0) ||
	    !EVP_EncryptUpdate(ctx, out->ptr, &len, in->ptr, (int)in->len) ||
	    len < 0 || (size_t)len != in->len) {
		log_str("%s: EVP_Encrypt", __func__);
		goto fail;
	}

	out->len = (size_t)len;

	log_str("---");
	log_str("%s:Key(Shared Secret)", __func__);
	log_hex(key->ptr, key->len);
	log_str("%s:raw-data", __func__);
	log_hex(in->ptr, in->len);
	log_str("%s:enc-data", __func__);
	log_hex(out->ptr, out->len);

	ok = 0;
fail:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ok < 0) {
		free(out->ptr);
		out->ptr = NULL;
		out->len = 0;
	}

	return (ok);
}

// AES256CBCでデコードする
// iv=32byte
int aes256_cbc_dec_bin(const bytebuffer_t *key, const bytebuffer_t *in, bytebuffer_t *out)
{
	EVP_CIPHER_CTX	*ctx = NULL;
	unsigned char	 iv[32];
	int		 len;
	int		 ok = -1;

	memset(iv, 0, sizeof(iv));
	out->ptr = NULL;
	out->len = 0;

	/* sanity check */
	if (in->len > INT_MAX || (in->len % 16) != 0 ||
	    (out->ptr = (unsigned char*)calloc(1, in->len)) == NULL) {
		log_str("%s: in->len=%zu", __func__, in->len);
		goto fail;
	}

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL || key->len != 32 ||
	    !EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key->ptr, iv) ||
	    !EVP_CIPHER_CTX_set_padding(ctx, 0) ||
	    !EVP_DecryptUpdate(ctx, out->ptr, &len, in->ptr, (int)in->len) ||
	    len < 0 || (size_t)len > in->len + 32) {
		log_str("%s: EVP_Decrypt", __func__);
		goto fail;
	}

	out->len = (size_t)len;

	log_str("---");
	log_str("%s:Key(Shared Secret)", __func__);
	log_hex(key->ptr, key->len);
	log_str("%s:enc-data", __func__);
	log_hex(in->ptr, in->len);
	log_str("%s:dec-data", __func__);
	log_hex(out->ptr, out->len);

	ok = 0;
fail:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ok < 0) {
		free(out->ptr);
		out->ptr = NULL;
		out->len = 0;
	}

	return (ok);
}

