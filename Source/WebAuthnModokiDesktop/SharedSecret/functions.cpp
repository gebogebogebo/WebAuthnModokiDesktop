#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

#include "functions.h"

bytebuffer_t *
bytebuffer_new(void)
{
	return ((bytebuffer_t *)calloc(1, sizeof(bytebuffer_t)));
}

void
bytebuffer_free(bytebuffer_t **bp)
{
	bytebuffer_t *b;

	if (bp == NULL || (b = *bp) == NULL)
		return;

	if (b->ptr) {
		//explicit_bzero(b->ptr, b->len);
		SecureZeroMemory(b->ptr, b->len);		
		free(b->ptr);
	}

	//explicit_bzero(b, sizeof(*b));
	SecureZeroMemory(b, sizeof(*b));
	free(b);

	*bp = NULL;
}

static int logging = 1;

void log_hex(const void *buf, size_t count)
{
	const uint8_t	*ptr = (uint8_t*)buf;
	size_t		 i;

	if (!logging)
		return;

	fprintf(stderr, "  ");

	for (i = 0; i < count; i++) {
		fprintf(stderr, "%02x ", *ptr++);
		if ((i + 1) % 16 == 0 && i + 1 < count)
			fprintf(stderr, "\n  ");
	}

	fprintf(stderr, "\n");
	fflush(stderr);
}

void log_str(const char *fmt, ...)
{
	va_list	 ap;

	if (!logging)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	fflush(stderr);
}

// ystrËhexz
// str (I )HEX•¶Žš—ñ
// hex ( O)bin
// len (I )str‚ÌƒŒƒ“ƒOƒX
void str2bin(const char *str, unsigned char *hex, const int strlen)
{
	int i = 0;
	for (i = 0; i < (strlen >> 1); i++) {
		unsigned int tmp;
		sscanf((const char*)str + (i << 1), "%2x", &tmp);
		hex[i] = (unsigned char)tmp & 0xff;
	}
}

// yhexËstrz
// str ( O)HEX•¶Žš—ñ
// buf (I )bin
// len (I )buf‚ÌƒŒƒ“ƒOƒX
void bin2str(char *str, unsigned char *buf, const int buflen)
{
	unsigned char * pin = buf;
	const char * hex = "0123456789ABCDEF";
	char * pout = str;
	int i = 0;
	for (; i < buflen - 1; ++i) {
		*pout++ = hex[(*pin >> 4) & 0xF];
		*pout++ = hex[(*pin++) & 0xF];
		//*pout++ = ':';
	}
	*pout++ = hex[(*pin >> 4) & 0xF];
	*pout++ = hex[(*pin) & 0xF];
	*pout = 0;

}
