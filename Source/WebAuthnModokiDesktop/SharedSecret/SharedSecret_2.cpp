
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "functions.h"
#include "es256.h"

// �����Ő��������閧��sk , �擾�������J��pk
// ecdh = Shered Secret
static int
do_ecdh(
		const es256_sk_t *sk,		// (I )�����Ő��������閧��
		const es256_pk_t *pk,		// (I )Yubikey����擾�������J��
		bytebuffer_t **ecdh)			// ( O)��������Shered Secret
{
	EVP_PKEY	*pk_evp = NULL;
	EVP_PKEY	*sk_evp = NULL;
	EVP_PKEY_CTX	*ctx = NULL;
	bytebuffer_t	*secret = NULL;
	int		 ok = -1;

	*ecdh = NULL;

	/* allocate blobs for secret & ecdh */
	if ((secret = bytebuffer_new()) == NULL ||
	    (*ecdh = bytebuffer_new()) == NULL)
		goto fail;

	// OpenSSL��EVP�`���ɕϊ�����
	// sk -> sk_evp
	// pk -> pk_evp
	/* wrap the keys as openssl objects */
	if ((pk_evp = es256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (sk_evp = es256_sk_to_EVP_PKEY(sk)) == NULL) {
		log_str("%s: es256_to_EVP_PKEY", __func__);
		goto fail;
	}

	// ���L������
	// EVP_PKEY_derive_init() -> EVP_PKEY_derive_set_peer() -> EVP_PKEY_derive()

	// sk_evp�� ctx + pk_evp
	// EVP_PKEY_CTX_new()			���J���Í��R���e�L�X�g ctx �� �� sk_evp �Ŏw�肳���A���S���Y����p���Đ�������
	// EVP_PKEY_derive_init()		���L������:���J���Í��R���e�L�X�g ctx �����L�������p�ɏ���������D
	// EVP_PKEY_derive_set_peer()	���L������:���J���Í��R���e�L�X�g ctx �Ɍ��J��� peer (pk_evp)��ݒ肷��D
	/* set ecdh parameters */
	if (
		(ctx =	EVP_PKEY_CTX_new(sk_evp, NULL)) == NULL ||
				EVP_PKEY_derive_init(ctx) <= 0 ||
				EVP_PKEY_derive_set_peer(ctx, pk_evp) <= 0) {
		log_str("%s: EVP_PKEY_derive_init", __func__);
		goto fail;
	}

	/* perform ecdh */
	// EVP_PKEY_derive()
	//		���J���Í��R���e�L�X�g ctx ��p���ċ��L���������s��
	//		�������ꂽ���� secret
	if (EVP_PKEY_derive(ctx, NULL, &secret->len) <= 0 ||
	    (secret->ptr = (unsigned char*)calloc(1, secret->len)) == NULL ||
	    EVP_PKEY_derive(ctx, secret->ptr, &secret->len) <= 0) {
		log_str("%s: EVP_PKEY_derive", __func__);
		goto fail;
	}

	/* use sha256 as a kdf on the resulting secret */
	// ���Ő������ꂽsecret��SHA256��ecdh = Shered Secret�ƂȂ�
	(*ecdh)->len = SHA256_DIGEST_LENGTH;
	if (((*ecdh)->ptr = (unsigned char*)calloc(1, (*ecdh)->len)) == NULL ||
	    SHA256(secret->ptr, secret->len, (*ecdh)->ptr) == NULL) {
		log_str("%s: sha256", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pk_evp != NULL)
		EVP_PKEY_free(pk_evp);
	if (sk_evp != NULL)
		EVP_PKEY_free(sk_evp);
	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);
	if (ok < 0)
		bytebuffer_free(ecdh);

	bytebuffer_free(&secret);

	return (ok);
}

int fido_createSharedSecret(
	es256_pk_t *public_key_aG,		// (I )Yubikey����擾�������J��
	es256_pk_t **public_key_bG,		// ( O)�����Ő����������J��(bG)
	bytebuffer_t **shearedSecret		// ( O)Sheared Secret
)
{
	es256_sk_t	*private_key_b = NULL; /* our private key */
	int		 r;

	*public_key_bG = NULL; /* our public key; returned */
	*shearedSecret = NULL; /* shared ecdh secret; returned */

	if ((private_key_b = es256_sk_new()) == NULL || (*public_key_bG = es256_pk_new()) == NULL) {
		r = -9;
		goto fail;
	}

	// sk=�閧��(b)��pk=���J��(bG)�𐶐�
	//  ECDH P-256 key pair
	if (es256_sk_create(private_key_b) < 0 || es256_derive_pk(private_key_b, *public_key_bG) < 0) {
		log_str("%s: es256_derive_pk", __func__);
		r = -9;
		goto fail;
	}

	//str2bin("94a84fc8e9858cdcb2338578d87bbd36da858298f278248ff974cae4e5dcb788", private_key_b->d,64);
	//str2bin("7e47690ddeb48eef8d8998338fdcf00ddde6b6db105cc60bb2677418416d7201", (*public_key_bG)->x, 64);
	//str2bin("087b7568e1930ac3f5662550a90e3afcc11bcf8a273c843ef3d931c1f7f300c0", (*public_key_bG)->y, 64);

	// log
	log_str("---");
	log_str("%s:�yPrivate Key-b�z �����Ő��������閧��(COSE ES256 (ECDSA over P-256 with SHA-256))", __func__);
	log_hex(private_key_b->d, 32);
	log_str("---");
	log_str("%s:�yPublic Key-bG�z�����Ő����������J��(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_str("x");
	log_hex((*public_key_bG)->x, 32);
	log_str("y");
	log_hex((*public_key_bG)->y, 32);
	log_str("---");
	log_str("%s:�yPublic Key-aG�zYubikey�̌��J��(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_str("x");
	log_hex((public_key_aG)->x, 32);
	log_str("y");
	log_hex((public_key_aG)->y, 32);
	log_str("---");

	// �����Ő��������閧��sk , �擾�������J��ak
	// �����Ƃ� sharedSecret �𐶐�����
	if (do_ecdh(private_key_b, public_key_aG, shearedSecret) < 0) {
		log_str("%s: do_ecdh", __func__);
		r = -9;
		goto fail;
	}

	log_str("---");
	log_str("%s:�yShared Secret�z", __func__);
	log_hex((*shearedSecret)->ptr, (*shearedSecret)->len);
	log_str("---");

	r = 0;
fail:
	es256_sk_free(&private_key_b);
	if (r != 0) {
		es256_pk_free(public_key_bG);
		bytebuffer_free(shearedSecret);
	}

	return (r);
}
