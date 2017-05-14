#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>
#include <endian.h>

#define PORT 25659
#define BACKLOG 1

#define NS_OK   0
#define NS_LEFT 1
#define NS_PROT 2
#define NS_ERR  3

#define NT_ACK  0
#define NT_ERR  1
#define NT_SALT 2
#define NT_STAT 3
#define NT_KEY  4
#define NT_MAX  4

#define N_HDRSZ  16
#define N_KEYSZ  256
#define N_NAMESZ 4088

struct npkg {
	uint16_t length;
	uint8_t prot, type;
	/* both for alignment and short unencrypted packets */
	union {
		uint8_t pad[12];
		uint8_t ack, err;
		uint32_t salt;
	} quick;
	/* data members must be multiple of 16 */
	union {
		struct {
			uint64_t size;
			char name[N_NAMESZ];
		} stat;
		uint8_t key[N_KEYSZ];
	} data;
};

struct pbuf {
	char data[UINT16_MAX];
	uint16_t size;
};

struct sock {
	int fd, other;
	struct pbuf pb;
};

void netinit(void);
uint32_t crc32(uint32_t crc, const void *buf, size_t n);
void pkginit(struct npkg *pkg, uint8_t type);
int pkgsend(struct npkg *pkg, int fd);
int pkgrecv(struct pbuf *pb, struct npkg *pkg, int fd);

int noclaim(int fd);

void sockzero(struct sock *s);
int sockinit(struct sock *s, uint16_t port, unsigned backlog, const char *address);
void sockfree(struct sock *s);

#endif
