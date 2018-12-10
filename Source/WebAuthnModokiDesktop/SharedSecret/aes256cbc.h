
#ifndef _AES256CBC_H
#define _AES256CBC_H

int aes256_cbc_enc_bin(
	const bytebuffer_t *	key,			// (I )Shared Secret(32byte)
	const bytebuffer_t *	in,				// (I )暗号化したいデータ(16byte)
	bytebuffer_t *		out				// ( O)暗号化されたデータ
);
int aes256_cbc_dec_bin(
	const bytebuffer_t *	key,			// (I )Shared Secret(32byte)
	const bytebuffer_t *	in,				// (I )暗号化したいデータ(16byte)
	bytebuffer_t *		out				// ( O)暗号化されたデータ
);

#endif
