/**
 * Third generation file transfer server/client
 * Copyright Folkert van Verseveld
 * Released under GNU Affero Public License version 3
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "net.h"
#include "transfer.h"

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

static int handle(struct sock *s)
{
	int ret = 1;
	if (cfg.mode & MODE_SERVER) {
		if ((ret = authrecv(s)))
			goto fail;
	} else {
		if ((ret = authsend(s)))
			goto fail;
	}
	fputs("TODO handle\n", stderr);
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
