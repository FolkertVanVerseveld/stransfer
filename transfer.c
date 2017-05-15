/**
 * Third generation file transfer server/client
 * Copyright Folkert van Verseveld
 * Released under GNU Affero Public License version 3
 */

#include "transfer.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "fs.h"
#include "net.h"

static int help = 0;
struct cfg cfg = {
	.port = PORT,
	.mode = 0,
	.address = "127.0.0.1",
	.files = NULL,
	.key = NULL
};

static const struct option long_opt[] = {
	{"help", no_argument, 0, 'h'},
	{"server", no_argument, 0, 's'},
	{"client", no_argument, 0, 'c'},
	{"port", required_argument, 0, 'p'},
	{"address", required_argument, 0, 'a'},
	{"key", required_argument, 0, 'k'},
	{0, 0, 0, 0},
};

static void usage(FILE *stream)
{
	fputs(
		"Secure file transfer program\n"
		"usage: transfer OPTIONS [--] FILE...\n"
		"  -h  --help     This help\n"
		"  -s  --server   Run in server mode\n"
		"  -c  --client   Run in client mode\n"
		"  -p  --port     Network port to use\n"
		"  -a  --address  Address to connect client to\n"
		"  -k  --key      Password\n",
		stream
	);
}

static int parse_opt(int argc, char **argv)
{
	int c, o_i;
	while (1) {
		c = getopt_long(argc, argv, "hscp:a:k:", long_opt, &o_i);
		if (c == -1) break;
		switch (c) {
		case 'h':
			help = 1;
			usage(stdout);
			break;
		case 's':
			if (cfg.mode & MODE_CLIENT) {
				fputs(
					"Can't run as client and server, "
					"client mode already specified.\n",
					stderr
				);
				return -1;
			}
			cfg.mode |= MODE_SERVER;
			break;
		case 'c':
			if (cfg.mode & MODE_SERVER) {
				fputs(
					"Can't run as server and client, "
					"server mode already specified.\n",
					stderr
				);
				return -1;
			}
			cfg.mode |= MODE_CLIENT;
			break;
		case 'p': {
			int port;
			port = atoi(optarg);
			if (port < 1 || port > UINT16_MAX) {
				fprintf(stderr, "%s: bad port, use 1-65535\n", optarg);
				return -1;
			}
			cfg.port = port;
		}
			break;
		case 'a':
			cfg.address = optarg;
			break;
		case 'k':
			cfg.key = optarg;
			break;
		}
	}
	return o_i;
}

static int sendfiles(struct sock *s)
{
	struct npkg pkg;
	struct bfile file;
	int ret = 1;
	binit(&file);
	for (char **f = cfg.files; *f; ++f) {
		bclose(&file);
		if (bopen(&file, *f, BM_READ, 0)) {
			fprintf(stderr, "Skipping \"%s\"\n", *f);
			continue;
		}
		pkginit(&pkg, NT_STAT);
		strcpy(pkg.data.stat.name, file.name);
		pkg.data.stat.size = htobe64(file.size);
		printf("Sending \"%s\"\n", file.name);
		if ((ret = socksend(s, &pkg)))
			goto fail;
		if ((ret = sockrecv(s, &pkg)))
			goto fail;
		if (pkg.type != NT_ACK) {
			fputs("File rejected\n", stderr);
			continue;
		}
		uint64_t offset, max; uint16_t n;
		for (offset = 0, max = file.size; offset < max; offset += N_FBLKSZ) {
			n = N_FBLKSZ;
			if (offset + n >= max)
				n = max - offset;
			pkginit(&pkg, NT_FBLK);
			pkg.data.fblk.offset = htobe64(offset);
			pkg.data.fblk.size = htobe16(n);
			memcpy(pkg.data.fblk.data, file.data + offset, n);
			//printf("block %" PRIX64 ", %" PRIu16 "\n", offset, n);
			if ((ret = socksend(s, &pkg))) {
				fputs("Transfer failed\n", stderr);
				goto fail;
			}
		}
		pkginit(&pkg, NT_ACK);
		pkg.quick.ack = NA_FILE_DONE;
		if ((ret = socksend(s, &pkg)))
			goto fail;
	}
	pkginit(&pkg, NT_ACK);
	pkg.quick.ack = NA_LIST_DONE;
	if ((ret = socksend(s, &pkg)))
		goto fail;
	ret = 0;
fail:
	bclose(&file);
	return ret;
}

static int recvfiles(struct sock *s)
{
	struct npkg pkg;
	struct bfile file;
	int ret = 1;
	binit(&file);
	while (1) {
		if ((ret = sockrecv(s, &pkg)))
			goto fail;
		if (pkg.type == NT_ACK) {
			if (pkg.quick.ack == NA_LIST_DONE)
				break;
			fputs("Communication error\n", stderr);
			ret = 1;
			goto fail;
		} else if (pkg.type == NT_STAT) {
			char *name = pkg.data.stat.name;
			uint64_t size = be64toh(pkg.data.stat.size);
			name[N_NAMESZ - 1] = '\0';
			printf("Incoming file: \"%s\" (%" PRIu64 " bytes)\n", name, size);
			if (bopen(&file, name, BM_WRITE, size)) {
				pkginit(&pkg, NT_ERR);
				pkg.quick.err = NE_FILE_SKIP;
				if ((ret = socksend(s, &pkg)))
					goto fail;
				continue;
			}
			pkginit(&pkg, NT_ACK);
			pkg.quick.ack = NA_FILE;
			if ((ret = socksend(s, &pkg)))
				goto fail;
			while (1) {
				if ((ret = sockrecv(s, &pkg)))
					goto fail;
				if (pkg.type == NT_ACK) {
					if (pkg.quick.ack == NA_FILE_DONE)
						break;
					fputs("Communication error\n", stderr);
					ret = 1;
					goto fail;
				} else if (pkg.type == NT_FBLK) {
					uint64_t offset; uint16_t n;
					offset = be64toh(pkg.data.fblk.offset);
					n = be16toh(pkg.data.fblk.size);
					//printf("block %" PRIX64 ", %" PRIu16 "\n", offset, n);
					if (offset + n > size) {
						fputs("Bad data block\n", stderr);
						ret = 1;
						goto fail;
					}
					memcpy(file.data + offset, pkg.data.fblk.data, n);
				}
			}
		}
	}
	ret = 0;
fail:
	bclose(&file);
	return ret;
}

static int handle(struct sock *s)
{
	int ret = 1;
	if (cfg.mode & MODE_SERVER) {
		if ((ret = authrecv(s)))
			goto fail;
		if ((ret = sendfiles(s)))
			goto fail;
		if ((ret = recvfiles(s)))
			goto fail;
	} else {
		if ((ret = authsend(s)))
			goto fail;
		if ((ret = recvfiles(s)))
			goto fail;
		if ((ret = sendfiles(s)))
			goto fail;
	}
	ret = 0;
fail:
	return ret;
}

int main(int argc, char **argv)
{
	struct sock s;
	int argp, ret = 1;
	unsigned nlog = 0;
	sockzero(&s);
	ret = parse_opt(argc, argv);
	if (ret < 0) return -ret;
	if (help) return 0;
	if (!(cfg.mode & (MODE_SERVER | MODE_CLIENT))) {
		fputs(
			"Nothing to do\n"
			"Specify -s or -c to run as server or client\n",
			stderr
		);
		goto fail;
	}
	if (!cfg.key) {
		fputs(
			"Missing password\n"
			"Specify -k the_password\n",
			stderr
		);
		goto fail;
	}
	argp = optind;
	if (argp != argc)
		cfg.files = &argv[argp];
	netinit();
	authinit();
	if (cfg.mode & MODE_SERVER)
		nlog = BACKLOG;
	if ((ret = sockinit(&s, cfg.port, nlog, cfg.address)))
		goto fail;
	ret = handle(&s);
fail:
	sockfree(&s);
	return ret;
}
