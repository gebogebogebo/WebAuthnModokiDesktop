// SharedSecret.cpp : DLL アプリケーション用にエクスポートされる関数を定義します。
//

#include "stdafx.h"

#include "SharedSecret.h"
#include <string.h>
#include <stdio.h>

#include "es256.h"
#include "functions.h"
#include "aes256cbc.h"

int fido_createSharedSecret(
	es256_pk_t *public_key_aG,		// (I )Yubikeyから取得した公開鍵
	es256_pk_t **public_key_bG,		// ( O)ここで生成した公開鍵(bG)
	bytebuffer_t **shearedSecret		// ( O)Sheared Secret
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

	int st = fido_createSharedSecret(
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

	str2bin(key, keyb->ptr, strlen(key));
	str2bin(in, inb->ptr, strlen(in));

	if (aes256_cbc_enc_bin(keyb, inb, outb) < 0) {
		goto fail;
	}

	// BYTE->HEX文字列変換
	bin2str(out, outb->ptr, outb->len);

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

	str2bin(key, keyb->ptr, strlen(key));
	str2bin(in, inb->ptr, strlen(in));

	if (aes256_cbc_dec_bin(keyb, inb, outb) < 0) {
		goto fail;
	}

	// BYTE->HEX文字列変換
	bin2str(out, outb->ptr, outb->len);

fail:
	if (keyb != NULL)
		bytebuffer_free(&keyb);
	if (inb != NULL)
		bytebuffer_free(&inb);
	if (outb != NULL)
		bytebuffer_free(&outb);

	return(0);
}

