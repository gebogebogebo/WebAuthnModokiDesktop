// SharedSecret.cpp : DLL アプリケーション用にエクスポートされる関数を定義します。
//

#include "stdafx.h"

#include "SharedSecret.h"
#include <string.h>
#include <stdio.h>

#include "es256.h"
#include "functions.h"
#include "aes256cbc.h"

int createSharedSecret_inter(
	es256_pk_t *public_key_aG,		// (I )Yubikeyから取得した公開鍵
	es256_pk_t **public_key_bG,		// ( O)ここで生成した公開鍵(bG)
	bytebuffer_t **shearedSecret		// ( O)Sheared Secret
);

int verify_attsig_inter(
	const bytebuffer_t *dgst,
	const bytebuffer_t *x5c,
	const bytebuffer_t *sig
);

EC_KEY * read_ec_pem_pubkey(const char* pubkeyPem, int pubkeyPemLen);
int verify_assertion_sig_inter(
	const bytebuffer_t*	dgst,
	const es256_pk_t*	pk,
	const bytebuffer_t*	sig
);

int CreateSharedSecretBin(
	unsigned char*	public_key_aG_x,		// I
	unsigned char*	public_key_aG_y,		// I
	unsigned char*	public_key_bG_x,		// O
	unsigned char*	public_key_bG_y,		// O
	unsigned char*	sharedSecret			// O
)
{
	es256_pk_t*		public_key_aG = NULL;		// I
	es256_pk_t*		public_key_bG = NULL;		// O
	bytebuffer_t*	blob_sharedSecret = NULL;		// O

	if ((public_key_aG = es256_pk_new()) == NULL) {
		return -9;
	}

	for (int intIc = 0; intIc < 32; intIc++) {
		public_key_aG->x[intIc] = public_key_aG_x[intIc];
		public_key_aG->y[intIc] = public_key_aG_y[intIc];
	}

	int st = createSharedSecret_inter(
		public_key_aG,
		&public_key_bG,
		&blob_sharedSecret);
	if (st != 0) {
		return -9;
	}

	if (blob_sharedSecret->len != 32) {
		return -9;
	}

	// set ouput
	for (int intIc = 0; intIc < 32; intIc++) {
		public_key_bG_x[intIc] = public_key_bG->x[intIc];
		public_key_bG_y[intIc] = public_key_bG->y[intIc];
		sharedSecret[intIc] = blob_sharedSecret->ptr[intIc];
	}

	es256_pk_free(&public_key_aG);
	es256_pk_free(&public_key_bG);
	bytebuffer_free(&blob_sharedSecret);

	return 0;

}

int CreateSharedSecret(
	const char*	str_public_key_aG_x,		// I 64文字
	const char*	str_public_key_aG_y,		// I 64文字
	char*		str_public_key_bG_x,		// O 64文字
	char*		str_public_key_bG_y,		// O 64文字
	char*		str_sharedSecret			// O 64文字
)
{
	int st = 0;

	if (strlen(str_public_key_aG_x) != 64 ||
		strlen(str_public_key_aG_y) != 64) {
		return -1;
	}

	unsigned char	public_key_aG_x[32];
	unsigned char	public_key_aG_y[32];
	for (int intIc = 0; intIc < 32; intIc++) {
		public_key_aG_x[intIc] = 0;
		public_key_aG_y[intIc] = 0;
	}

	// HEX文字列 -> BYTE変換
	str2bin(str_public_key_aG_x, public_key_aG_x, 64);
	str2bin(str_public_key_aG_y, public_key_aG_y, 64);

	unsigned char	public_key_bG_x[32];		// O
	unsigned char	public_key_bG_y[32];		// O
	unsigned char	sharedSecret[32];			// O
	for (int intIc = 0; intIc < 32; intIc++) {
		public_key_bG_x[intIc] = 0;
		public_key_bG_y[intIc] = 0;
		sharedSecret[intIc] = 0;
	}

	st = CreateSharedSecretBin(
		public_key_aG_x, public_key_aG_y,
		public_key_bG_x, public_key_bG_y,
		sharedSecret
	);
	if (st != 0) {
		return -2;
	}

	// BYTE->HEX文字列変換
	bin2str(str_public_key_bG_x, public_key_bG_x, 32);
	bin2str(str_public_key_bG_y, public_key_bG_y, 32);
	bin2str(str_sharedSecret, sharedSecret, 32);

	return st;
}


int Aes256cbc_Enc(
	const char*			key,			// (I )Shared Secret(Hex文字列64文字)
	const char*			in,				// (I )暗号化したいデータ
	char*				out				// ( O)暗号化されたデータ(Hex文字列32文字)
)
{
	bytebuffer_t*	keyb = NULL;
	bytebuffer_t*	inb = NULL;
	bytebuffer_t*	outb = NULL;

	if (strlen(key) != 64 ){
		return -1;
	}

	keyb = bytebuffer_new();
	if (keyb == NULL) {
		goto fail;
	}
	keyb->len = 32;
	keyb->ptr = (unsigned char*)calloc(keyb->len, 1);

	inb = bytebuffer_new();
	if (inb == NULL) {
		goto fail;
	}
	inb->len = strlen(in)/2;
	inb->ptr = (unsigned char*)calloc(inb->len, 1);

	outb = bytebuffer_new();
	if (outb == NULL) {
		goto fail;
	}
	outb->ptr = NULL;
	outb->len = 0;

	str2bin(key, keyb->ptr, (int)strlen(key));
	str2bin(in, inb->ptr, (int)strlen(in));

	if (aes256_cbc_enc_bin(keyb, inb, outb) < 0) {
		goto fail;
	}

	// BYTE->HEX文字列変換
	bin2str(out, outb->ptr, (int)outb->len);

fail:
	if (keyb != NULL)
		bytebuffer_free(&keyb);
	if (inb != NULL)
		bytebuffer_free(&inb);
	if (outb != NULL)
		bytebuffer_free(&outb);

	return(0);
}

int Aes256cbc_Dec(
	const char*			key,			// (I )Shared Secret(Hex文字列64文字)
	const char*			in,				// (I )復号化したいデータ(Hex文字列32文字)
	char*				out				// ( O)復号化されたデータ(Hex文字列32文字)
)
{
	bytebuffer_t*	keyb = NULL;
	bytebuffer_t*	inb = NULL;
	bytebuffer_t*	outb = NULL;

	if (strlen(key) != 64) {
		return -1;
	}

	keyb = bytebuffer_new();
	if (keyb == NULL) {
		goto fail;
	}
	keyb->len = 32;
	keyb->ptr = (unsigned char*)calloc(keyb->len, 1);

	inb = bytebuffer_new();
	if (inb == NULL) {
		goto fail;
	}
	inb->len = strlen(in) / 2;
	inb->ptr = (unsigned char*)calloc(inb->len, 1);

	outb = bytebuffer_new();
	if (outb == NULL) {
		goto fail;
	}
	outb->ptr = NULL;
	outb->len = 0;

	str2bin(key, keyb->ptr, (int)strlen(key));
	str2bin(in, inb->ptr, (int)strlen(in));

	if (aes256_cbc_dec_bin(keyb, inb, outb) < 0) {
		goto fail;
	}

	// BYTE->HEX文字列変換
	bin2str(out, outb->ptr, (int)outb->len);

fail:
	if (keyb != NULL)
		bytebuffer_free(&keyb);
	if (inb != NULL)
		bytebuffer_free(&inb);
	if (outb != NULL)
		bytebuffer_free(&outb);

	return(0);
}

int Verify_AttestaionSig(
	const char*			sigBaseSha256,	// (I )署名元データのSHA256ハッシュ(Hex文字列)
	const char*			x5c,			// (I )X5C証明書(Hex文字列)
	const char*			sig				// (I )署名(Hex文字列)
)
{
	bytebuffer_t*	sigBaseSha256_b = NULL;
	bytebuffer_t*	x5c_b = NULL;
	bytebuffer_t*	sig_b = NULL;
	int				verifyst = 0;

	log_str("%s:Start", __func__);

	// sigBaseSha256
	sigBaseSha256_b = bytebuffer_new();
	if (sigBaseSha256_b == NULL) {
		goto fail;
	}
	sigBaseSha256_b->len = strlen(sigBaseSha256) / 2;
	sigBaseSha256_b->ptr = (unsigned char*)calloc(sigBaseSha256_b->len, 1);
	str2bin(sigBaseSha256, sigBaseSha256_b->ptr, (int)strlen(sigBaseSha256));

	// x5c
	x5c_b = bytebuffer_new();
	if (x5c_b == NULL) {
		goto fail;
	}
	x5c_b->len = strlen(x5c) / 2;
	x5c_b->ptr = (unsigned char*)calloc(x5c_b->len, 1);
	str2bin(x5c, x5c_b->ptr, (int)strlen(x5c));

	// sig
	sig_b = bytebuffer_new();
	if (sig_b == NULL) {
		goto fail;
	}
	sig_b->len = strlen(sig) / 2;
	sig_b->ptr = (unsigned char*)calloc(sig_b->len, 1);
	str2bin(sig, sig_b->ptr, (int)strlen(sig));

	// verify
	verifyst = verify_attsig_inter(sigBaseSha256_b, x5c_b, sig_b);

fail:
	if (sigBaseSha256_b != NULL)
		bytebuffer_free(&sigBaseSha256_b);
	if (x5c_b != NULL)
		bytebuffer_free(&x5c_b);
	if (sig_b != NULL)
		bytebuffer_free(&sig_b);

	log_str("%s:Exit", __func__);

	return(verifyst);
}

int Verify_AssertionSig(
	const char*			sigBaseSha256,	// (I )署名元データのSHA256ハッシュ(Hex文字列)
	const char*			pubkeyPem,		// (I )AttestationPublicKey(PEM形式文字列)
	const char*			sig				// (I )署名(Hex文字列)
)
{
	bytebuffer_t*	sigBaseSha256_b = NULL;
	bytebuffer_t*	sig_b = NULL;
	es256_pk_t*		es256_pk = NULL;

	int				verifyst = 0;
	log_str("%s:Start", __func__);

	// sigBaseSha256
	sigBaseSha256_b = bytebuffer_new();
	if (sigBaseSha256_b == NULL) {
		goto fail;
	}
	sigBaseSha256_b->len = strlen(sigBaseSha256) / 2;
	sigBaseSha256_b->ptr = (unsigned char*)calloc(sigBaseSha256_b->len, 1);
	str2bin(sigBaseSha256, sigBaseSha256_b->ptr, (int)strlen(sigBaseSha256));

	// pubkeyPem -> EC_KEY
	{
		EC_KEY		*ec = NULL;
		if ((ec = read_ec_pem_pubkey((char*)pubkeyPem, (int)strlen(pubkeyPem))) == NULL) {
			log_str("%s: Error read_ec_pem_pubkey", __func__);
			goto fail;
		}

		if ((es256_pk = es256_pk_new()) == NULL) {
			log_str("%s: Error es256_pk_new", __func__);
			EC_KEY_free(ec);
			goto fail;
		}

		if (es256_pk_from_EC_KEY(es256_pk, ec) != 0) {
			log_str("%s: Error es256_pk_from_EC_KEY", __func__);
			EC_KEY_free(ec);
			goto fail;
		}

		EC_KEY_free(ec);
		ec = NULL;

		log_str("%s: es256_pk-Read-OK", __func__);
	}

	// sig
	sig_b = bytebuffer_new();
	if (sig_b == NULL) {
		goto fail;
	}
	sig_b->len = strlen(sig) / 2;
	sig_b->ptr = (unsigned char*)calloc(sig_b->len, 1);
	str2bin(sig, sig_b->ptr, (int)strlen(sig));

	// verify
	verifyst = verify_assertion_sig_inter(sigBaseSha256_b, es256_pk, sig_b);


fail:
	if (sigBaseSha256_b != NULL)
		bytebuffer_free(&sigBaseSha256_b);
	if (sig_b != NULL)
		bytebuffer_free(&sig_b);
	es256_pk_free(&es256_pk);

	log_str("%s:Exit", __func__);
	return(verifyst);
}
