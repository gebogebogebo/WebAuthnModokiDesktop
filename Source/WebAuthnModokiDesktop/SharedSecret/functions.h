#ifndef _FUNCTIONS_H
#define _FUNCTIONS_H

typedef struct bytebuffer {
	unsigned char*	ptr;
	size_t			len;
} bytebuffer_t;

bytebuffer_t* bytebuffer_new(void);
void bytebuffer_free(bytebuffer_t **);

void str2bin(const char *str, unsigned char *hex, const int strlen);
void bin2str(char *str, unsigned char *buf, const int buflen);

void log_str(const char *, ...);
void log_hex(const void *, size_t);

#endif
