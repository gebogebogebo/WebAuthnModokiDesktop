
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "functions.h"
#include "es256.h"

// ここで生成した秘密鍵sk , 取得した公開鍵pk
// ecdh = Shered Secret
int do_ecdh(
		const es256_sk_t *sk,		// (I )ここで生成した秘密鍵
		const es256_pk_t *pk,		// (I )Yubikeyから取得した公開鍵
		bytebuffer_t **ecdh)			// ( O)生成したShered Secret
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

	// OpenSSLのEVP形式に変換する
	// sk -> sk_evp
	// pk -> pk_evp
	/* wrap the keys as openssl objects */
	if ((pk_evp = es256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (sk_evp = es256_sk_to_EVP_PKEY(sk)) == NULL) {
		log_str("%s: es256_to_EVP_PKEY", __func__);
		goto fail;
	}

	// 共有鍵生成
	// EVP_PKEY_derive_init() -> EVP_PKEY_derive_set_peer() -> EVP_PKEY_derive()

	// sk_evp⇒ ctx + pk_evp
	// EVP_PKEY_CTX_new()			公開鍵暗号コンテキスト ctx を 鍵 sk_evp で指定されるアルゴリズムを用いて生成する
	// EVP_PKEY_derive_init()		共有鍵生成:公開鍵暗号コンテキスト ctx を共有鍵生成用に初期化する．
	// EVP_PKEY_derive_set_peer()	共有鍵生成:公開鍵暗号コンテキスト ctx に公開情報 peer (pk_evp)を設定する．
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
	//		公開鍵暗号コンテキスト ctx を用いて共有鍵生成を行う
	//		生成された鍵が secret
	if (EVP_PKEY_derive(ctx, NULL, &secret->len) <= 0 ||
	    (secret->ptr = (unsigned char*)calloc(1, secret->len)) == NULL ||
	    EVP_PKEY_derive(ctx, secret->ptr, &secret->len) <= 0) {
		log_str("%s: EVP_PKEY_derive", __func__);
		goto fail;
	}

	/* use sha256 as a kdf on the resulting secret */
	// ↑で生成されたsecretのSHA256がecdh = Shered Secretとなる
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
	es256_pk_t *public_key_aG,		// (I )Yubikeyから取得した公開鍵
	es256_pk_t **public_key_bG,		// ( O)ここで生成した公開鍵(bG)
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

	// sk=秘密鍵(b)とpk=公開鍵(bG)を生成
	//  ECDH P-256 key pair
	if (es256_sk_create(private_key_b) < 0 || es256_derive_pk(private_key_b, *public_key_bG) < 0) {
		log_str("%s: es256_derive_pk", __func__);
		r = -9;
		goto fail;
	}

	// log
	log_str("---");
	log_str("%s:【Private Key-b】 ここで生成した秘密鍵(COSE ES256 (ECDSA over P-256 with SHA-256))", __func__);
	log_hex(private_key_b->d, 32);
	log_str("---");
	log_str("%s:【Public Key-bG】ここで生成した公開鍵(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_str("x");
	log_hex((*public_key_bG)->x, 32);
	log_str("y");
	log_hex((*public_key_bG)->y, 32);
	log_str("---");
	log_str("%s:【Public Key-aG】Yubikeyの公開鍵(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_str("x");
	log_hex((public_key_aG)->x, 32);
	log_str("y");
	log_hex((public_key_aG)->y, 32);
	log_str("---");

	// ここで生成した秘密鍵sk , 取得した公開鍵ak
	// をもとに sharedSecret を生成する
	if (do_ecdh(private_key_b, public_key_aG, shearedSecret) < 0) {
		log_str("%s: do_ecdh", __func__);
		r = -9;
		goto fail;
	}

	log_str("---");
	log_str("%s:【Shared Secret】", __func__);
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

	// 証明書バイトストリームから証明書構造体の生成
	if ((cert = d2i_X509_bio(rawcert, NULL)) == NULL) {
		return (-4);
	}

	// 証明書情報から公開鍵を取り出す
	if ((pkey = X509_get_pubkey(cert)) == NULL) {
		return (-5);
	}

	// EC KEYに変換
	if((ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL ) {
		log_str("%s: x509 key", __func__);
		return (-6);
	}

	// ログ
	log_str("%s: x5c", __func__);
	log_str("x5c(%d byte)", x5c->len);
	log_hex(x5c->ptr, x5c->len);

	log_str("dgst(%d byte)", dgst->len);
	log_hex(dgst->ptr, dgst->len);

	log_str("sig(%d byte)", sig->len);
	log_hex(sig->ptr, sig->len);

	// ECDSA
	// dgst と sig を検証する（ecを使う）
	// 1.dgstをx5cから取り出した公開鍵で暗号化する⇒署名
	// 2.この署名とsigを比較
	// openssl でできる
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
