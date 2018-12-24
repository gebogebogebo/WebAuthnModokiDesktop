
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "functions.h"
#include "es256.h"

// �����Ő��������閧��sk , �擾�������J��pk
// ecdh = Shered Secret
int do_ecdh(
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

int createSharedSecret_inter(
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

int verify_attsig_inter(
	const bytebuffer_t *dgst,
	const bytebuffer_t *x5c,
	const bytebuffer_t *sig
)
{
	BIO			*rawcert = NULL;
	X509		*cert = NULL;
	EVP_PKEY	*pkey = NULL;
	EC_KEY		*ec;
	int			ok = -1;

	/* openssl needs ints */
	if (dgst->len > INT_MAX || x5c->len > INT_MAX || sig->len > INT_MAX) {
		log_str("%s: dgst->len=%zu, x5c->len=%zu, sig->len=%zu",
			__func__, dgst->len, x5c->len, sig->len);
		return (-2);
	}

	/* fetch key from x509 */
	if ((rawcert = BIO_new_mem_buf(x5c->ptr, (int)x5c->len)) == NULL) {
		return (-3);
	}

	// �ؖ����o�C�g�X�g���[������ؖ����\���̂̐���
	if ((cert = d2i_X509_bio(rawcert, NULL)) == NULL) {
		return (-4);
	}

	// �ؖ�����񂩂���J�������o��
	if ((pkey = X509_get_pubkey(cert)) == NULL) {
		return (-5);
	}

	// EC KEY�ɕϊ�
	if((ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL ) {
		log_str("%s: x509 key", __func__);
		return (-6);
	}

	// ���O
	log_str("%s: x5c", __func__);
	log_str("x5c(%d byte)", x5c->len);
	log_hex(x5c->ptr, x5c->len);

	log_str("dgst(%d byte)", dgst->len);
	log_hex(dgst->ptr, dgst->len);

	log_str("sig(%d byte)", sig->len);
	log_hex(sig->ptr, sig->len);

	// ECDSA
	// dgst �� sig �����؂���iec���g���j
	// 1.dgst��x5c������o�������J���ňÍ�������ˏ���
	// 2.���̏�����sig���r
	// openssl �łł���
	if (ECDSA_verify(0,
		dgst->ptr, (int)dgst->len,
		sig->ptr, (int)sig->len,
		ec) != 1) {
		log_str("%s: ECDSA_verify", __func__);
		goto fail;
	}
	log_str("ECDSA_verify-Ok");

	ok = 0;
fail:
	if (rawcert != NULL)
		BIO_free(rawcert);
	if (cert != NULL)
		X509_free(cert);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return (ok);
}

EC_KEY * read_ec_pem_pubkey(const char* pubkeyPem,int pubkeyPemLen)
{
	BIO			*biokey = NULL;
	EVP_PKEY	*pkey = NULL;
	EC_KEY		*ec = NULL;

	// fetch string
	if ((biokey = BIO_new_mem_buf((void*)pubkeyPem, pubkeyPemLen)) == NULL) {
		log_str("%s: Error BIO_new_mem_buf", __func__);
		goto fail;
	}
	log_str("%s: Ok BIO_new_mem_buf", __func__);

	// read pem
	if ((pkey = PEM_read_bio_PUBKEY(biokey, NULL, NULL, NULL)) == NULL) {
		log_str("%s: Error PEM_read_bio_PUBKEY", __func__);
		goto fail;
	}
	log_str("%s: Ok PEM_read_bio_PUBKEY", __func__);

	// get EC_KEY
	if ((ec = EVP_PKEY_get1_EC_KEY(pkey)) == NULL) {
		log_str("%s: Error EVP_PKEY_get1_EC_KEY", __func__);
		goto fail;
	}
	log_str("%s: Ok EVP_PKEY_get1_EC_KEY", __func__);

fail:
	if (biokey != NULL) {
		BIO_free(biokey);
	}

	if (pkey!= NULL) {
		EVP_PKEY_free(pkey);
	}

	return (ec);
}

int verify_assertion_sig_inter(
				const bytebuffer_t*	dgst,
				const es256_pk_t*	pk,
				const bytebuffer_t*	sig
				)
{
	EVP_PKEY	*pkey = NULL;
	EC_KEY		*ec = NULL;
	int			ok = -1;

	/* ECDSA_verify needs ints */
	if (dgst->len > INT_MAX || sig->len > INT_MAX) {
		log_str("%s: dgst->len=%zu, sig->len=%zu", __func__,dgst->len, sig->len);
		ok = -2;
		goto fail;
	}

	if ((pkey = es256_pk_to_EVP_PKEY(pk)) == NULL) {
		log_str("%s: pk -> ec", __func__);
		ok = -3;
		goto fail;
	}

	if ((ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL) {
		log_str("%s: pk -> ec", __func__);
		ok = -4;
		goto fail;
	}

	// verify
	if (ECDSA_verify(0, dgst->ptr, (int)dgst->len, sig->ptr,(int)sig->len, ec) != 1) {
		ok = -4;
		log_str("%s: ECDSA_verify", __func__);
		goto fail;
	}

	log_str("%s: verify_assertion_sig_inter-ok", __func__);
	ok = 0;

fail:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return (ok);
}
