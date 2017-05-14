#include "net.h"
#include "serpent.h"
#include "string.h"
#include "transfer.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <stdio.h>
#include <inttypes.h>

static int ctx_init = 0;
static serpent_ctx ctx;

void authinit(void)
{
	srand(time(NULL));
	memset(&ctx, 0, sizeof ctx);
	long seed = (rand() << 16) + rand();
	srand48(seed);
}

int authrecv(struct sock *s)
{
	struct npkg pkg;
	uint32_t salt[3], salt2[3], crc, crc2, *sp;
	char pass[N_HDRSZ + N_KEYSZ];
	int ret = 1;
	memset(&pkg, 0, sizeof pkg);
	pkginit(&pkg, NT_SALT);
	salt[0] = mrand48();
	salt[1] = mrand48();
	salt[2] = mrand48();
	pkg.quick.salt[0] = htobe32(salt[0]);
	pkg.quick.salt[1] = htobe32(salt[1]);
	pkg.quick.salt[2] = htobe32(salt[2]);
	printf("salt[0] = %" PRIX32 "\n", salt[0]);
	printf("salt[1] = %" PRIX32 "\n", salt[1]);
	printf("salt[2] = %" PRIX32 "\n", salt[2]);
	if ((ret = socksend(s, &pkg)))
		goto fail;
	sp = (uint32_t*)pass;
	sp[0] = salt[2];
	sp[1] = salt[0];
	sp[2] = salt[1];
	sp[3] = (salt[2] & salt[1]) | salt[0];
	printf("key = %s\n", cfg.key);
	strncpyz(pass + N_HDRSZ, cfg.key, N_KEYSZ);
	crc = crc32(0, pass, sizeof pass);
	printf("chksum = %" PRIX32 "\n", crc);
	serpent_init(&ctx, pass, sizeof pass);
	ctx_init = 1;
	if ((ret = sockrecv(s, &pkg)))
		goto fail;
	/* check whether login succeeded */
	if (pkg.type != NT_AUTH) {
		fputs("Communication error\n", stderr);
		goto fail;
	}
	sp = pkg.data.auth.salt;
	salt2[0] = be32toh(sp[0]);
	salt2[1] = be32toh(sp[1]);
	salt2[2] = be32toh(sp[2]);
	crc2 = be32toh(pkg.data.auth.crc);
	if (salt2[0] != salt[0] || salt2[1] != salt[1] || salt2[2] != salt[2] || crc2 != crc) {
		fputs("Authentication failure\n", stderr);
		ret = 1;
		goto fail;
	}
	/* acknowledge salt */
	pkginit(&pkg, NT_ACK);
	pkg.quick.ack = NA_SALT;
	if ((ret = socksend(s, &pkg)))
		goto fail;
	ret = 0;
fail:
	return ret;
}

int authsend(struct sock *s)
{
	struct npkg pkg;
	uint32_t salt[3], crc, *sp;
	char pass[N_HDRSZ + N_KEYSZ];
	int ret = 1;
	if ((ret = sockrecv(s, &pkg)))
		goto fail;
	if (pkg.type != NT_SALT) {
		fputs("Communication error\n", stderr);
		goto fail;
	}
	salt[0] = be32toh(pkg.quick.salt[0]);
	salt[1] = be32toh(pkg.quick.salt[1]);
	salt[2] = be32toh(pkg.quick.salt[2]);
	printf("salt[0] = %" PRIX32 "\n", salt[0]);
	printf("salt[1] = %" PRIX32 "\n", salt[1]);
	printf("salt[2] = %" PRIX32 "\n", salt[2]);
	sp = (uint32_t*)pass;
	sp[0] = salt[2];
	sp[1] = salt[0];
	sp[2] = salt[1];
	sp[3] = (salt[2] & salt[1]) | salt[0];
	printf("key = %s\n", cfg.key);
	strncpyz(pass + N_HDRSZ, cfg.key, N_KEYSZ);
	crc = crc32(0, pass, sizeof pass);
	printf("chksum = %" PRIX32 "\n", crc);
	serpent_init(&ctx, pass, sizeof pass);
	ctx_init = 1;
	pkginit(&pkg, NT_AUTH);
	/* copy salt to encrypted block */
	sp = pkg.data.auth.salt;
	sp[0] = htobe32(salt[0]);
	sp[1] = htobe32(salt[1]);
	sp[2] = htobe32(salt[2]);
	pkg.data.auth.crc = htobe32(crc);
	if ((ret = socksend(s, &pkg)))
		goto fail;
	if ((ret = sockrecv(s, &pkg))) {
		if (ret == NS_LEFT) {
			fputs("Authentication failure\n", stderr);
			goto fail;
		}
	}
	if (pkg.type != NT_ACK || pkg.quick.ack != NA_SALT) {
		fputs("Communication error\n", stderr);
		goto fail;
	}
	ret = 0;
fail:
	return ret;
}

int socksend(struct sock *s, struct npkg *pkg)
{
	if (ctx_init) {
		struct npkg pkg2;
		/* copy header because it must remain intact */
		memcpy(&pkg2, pkg, N_HDRSZ);
		assert(pkg->type <= NT_MAX);
		serpent_encblk(&ctx, (char*)pkg + N_HDRSZ, (char*)&pkg2 + N_HDRSZ, nt_ltbl[pkg->type]);
		puts("encrypt");
		return pkgsend(&pkg2, s->other);
	}
	return pkgsend(pkg, s->other);
}

int sockrecv(struct sock *s, struct npkg *pkg)
{
	if (ctx_init) {
		struct npkg pkg2;
		int ret = pkgrecv(&s->pb, &pkg2, s->other);
		if (ret) return ret;
		/* copy header because it must remain intact */
		memcpy(pkg, &pkg2, N_HDRSZ);
		assert(pkg->type <= NT_MAX);
		serpent_decblk(&ctx, (char*)&pkg2 + N_HDRSZ, (char*)pkg + N_HDRSZ, nt_ltbl[pkg2.type]);
		puts("decrypt");
		return ret;
	}
	return pkgrecv(&s->pb, pkg, s->other);
}
