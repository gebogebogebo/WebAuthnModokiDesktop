
#ifndef _FIDO_ES256_H
#define _FIDO_ES256_H

#include <openssl/ec.h>

#include <stdint.h>
#include <stdlib.h>

/* COSE ES256 (ECDSA over P-256 with SHA-256) public key */
typedef struct es256_pk {
	unsigned char	x[32];
	unsigned char	y[32];
} es256_pk_t;

/* COSE ES256 (ECDSA over P-256 with SHA-256) (secret) key */
typedef struct es256_sk {
	unsigned char	d[32];
} es256_sk_t;

int es256_pk_from_EC_KEY(es256_pk_t *, const EC_KEY *);
EVP_PKEY *es256_pk_to_EVP_PKEY(const es256_pk_t *);
EVP_PKEY *es256_sk_to_EVP_PKEY(const es256_sk_t *);
es256_sk_t *es256_sk_new(void);
es256_pk_t *es256_pk_new(void);

int es256_sk_create(es256_sk_t *);
int es256_derive_pk(const es256_sk_t *, es256_pk_t *);
void es256_pk_free(es256_pk_t **);
void es256_sk_free(es256_sk_t **);


#endif /* !_FIDO_ES256_H */
