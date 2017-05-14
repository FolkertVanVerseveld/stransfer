#ifndef TRANSFER_H
#define TRANSFER_H

#include <stdint.h>

#define MODE_SERVER  1
#define MODE_CLIENT  2

extern struct cfg {
	uint16_t port;
	unsigned mode;
	const char *address;
	char **files;
	char *key;
} cfg;

#endif
