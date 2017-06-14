#include "net.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>

const uint16_t nt_ltbl[NT_MAX + 1] = {
	[NT_ACK ] = 0,
	[NT_ERR ] = 0,
	[NT_SALT] = 0,
	[NT_STAT] = 8 + N_NAMESZ,
	[NT_AUTH] = 16,
	[NT_FBLK] = 16 + N_FBLKSZ,
};

static uint32_t chktbl[256];

void netinit(void)
{
	/* Calculate CRC table. */
	for (int i = 0; i < 256; i++) {
		uint32_t rem = i;  /* remainder from polynomial division */
		for (int j = 0; j < 8; j++) {
			if (rem & 1) {
				rem >>= 1;
				rem ^= 0xedb88320;
			} else
				rem >>= 1;
		}
		chktbl[i] = rem;
	}
}

uint32_t crc32(uint32_t crc, const void *buf, size_t n)
{
	const uint8_t *p, *q;
	crc = ~crc;
	q = (const uint8_t*)buf + n;
	for (p = buf; p < q; p++)
		crc = (crc >> 8) ^ chktbl[(crc & 0xff) ^ *p];
	return ~crc;
}

int pkgsend(struct npkg *pkg, int fd)
{
	uint16_t length;
	ssize_t size;

	assert(pkg->type <= NT_MAX);

	length = nt_ltbl[pkg->type] + N_HDRSZ;
	pkg->length = htobe16(length);

	for (unsigned char *src = (unsigned char*)pkg; length; src += size, length -= size) {
		size = send(fd, src, length, 0);
		if (!size)
			return NS_LEFT;
		if (size < 0)
			return NS_ERR;
	}
	return NS_OK;
}

ssize_t pkgread(struct pbuf *pb, int fd, void *buf, uint16_t n)
{
	ssize_t length;
	size_t need;
	char *dst = buf;
	if (pb->size) {
		uint16_t off;
		/* use remaining data if everything is buffered already */
		if (pb->size >= n)
			goto copy;
		/* we need to copy all buffered data and wait for the next stuff to arrive */
		memcpy(buf, pb->data, off = pb->size);
		pb->size = 0;
		for (need = n - pb->size; need; need -= length, pb->size += length) {
			length = recv(fd, &pb->data[pb->size], need, 0);
			if (length <= 0) return length;
		}
		dst += off;
		goto copy;
	}
	pb->size = 0;
	for (need = n; need; need -= length, pb->size += length) {
		length = recv(fd, &pb->data[pb->size], need, 0);
		if (length <= 0) return length;
	}
copy:
	memcpy(buf, pb->data, pb->size > n ? n : pb->size);
	if (pb->size > n)
		memmove(pb->data, &pb->data[pb->size], UINT16_MAX - pb->size);
	pb->size -= n;
	return n;
}

int pkgrecv(struct pbuf *pb, struct npkg *pkg, int fd)
{
	ssize_t n;
	uint16_t length, t_length;
	n = pkgread(pb, fd, pkg, N_HDRSZ);
	if (!n) return NS_LEFT;
	if (n == -1 || n != N_HDRSZ) return NS_ERR;
	length = be16toh(pkg->length);
	if (length < 4 || length > sizeof(struct npkg)) {
		fprintf(stderr, "impossibru: length=%u\n", length);
		return NS_ERR;
	}
	if (pkg->type > NT_MAX) {
		fprintf(stderr, "bad type: type=%u\n", pkg->type);
		return NS_ERR;
	}
	t_length = nt_ltbl[pkg->type];
	n = pkgread(pb, fd, &pkg->data, t_length);
	if (n == -1 || n != t_length) {
		fprintf(stderr, "impossibru: n=%zu\n", n);
		return NS_ERR;
	}
	length -= N_HDRSZ;
	if (length - N_HDRSZ > t_length)
		return NS_ERR;
	return NS_OK;
}

void pkginit(struct npkg *pkg, uint8_t type)
{
	assert(type <= NT_MAX);
	memset(pkg, 0, sizeof *pkg);
	pkg->type = type;
	pkg->prot = 0;
	pkg->length = htobe16(nt_ltbl[type] + N_HDRSZ);
}

int noclaim(int fd)
{
	register int level, optname;
	int optval;
	level = SOL_SOCKET;
	optname = SO_REUSEADDR;
	optval = 1;
	return setsockopt(fd, level, optname, &optval, sizeof(int));
}

void sockzero(struct sock *s)
{
	s->fd = s->other = -1;
	memset(&s->pb, 0, sizeof(s->pb));
}

void sockfree(struct sock *s)
{
	/* client has same fd for both directions */
	if (s->other != s->fd && s->other != -1) {
		close(s->other);
		s->other = -1;
	}
	if (s->fd != -1) {
		close(s->fd);
		s->fd = -1;
	}
}

static int sockserver(struct sock *s, uint16_t port, unsigned backlog)
{
	int ret = 1;
	struct sockaddr_in ca, sa;
	const socklen_t cl = sizeof(struct sockaddr_in);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htobe16(port);
	if (bind(s->fd, (struct sockaddr*)&sa, sizeof sa)) {
		perror("Can't bind socket");
		goto fail;
	}
	if (listen(s->fd, backlog)) {
		perror("Can't wait for incoming connections");
		goto fail;
	}
	puts("Waiting...");
	s->other = accept(s->fd, (struct sockaddr*)&ca, (socklen_t*)&cl);
	if (s->other == -1) {
		perror("Can't accept incoming connection");
		goto fail;
	}
	puts("Connection accepted");
	ret = 0;
fail:
	return ret;
}

static int sockclient(struct sock *s, uint16_t port, const char *address)
{
	int ret = 1;
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(address);
	sa.sin_port = htobe16(port);
	if (connect(s->fd, (struct sockaddr*)&sa, sizeof sa)) {
		perror("Can't connect to server");
		goto fail;
	}
	s->other = s->fd;
	ret = 0;
fail:
	return ret;
}

int sockinit(struct sock *s, uint16_t port, unsigned backlog, const char *address)
{
	int fd, ret = 1;
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	s->fd = fd;
	if (fd == -1) {
		perror("Can't create socket");
		goto fail;
	}
	if (noclaim(fd))
		// don't quit ctor, non-fatal error
		perror("Can't reuse socket");
	ret = backlog ? sockserver(s, port, backlog) : sockclient(s, port, address);
fail:
	return ret;
}
