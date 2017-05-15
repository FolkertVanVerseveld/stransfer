#ifndef FS_H
#define FS_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "net.h"

struct bfile {
	int fd;
	char *data;
	size_t size;
	unsigned flags;
	struct stat st;
	char name[N_NAMESZ];
};

#define BM_WRITE 0
#define BM_READ  1

void binit(struct bfile *file);
int bopen(struct bfile *file, const char *name, unsigned mode, size_t size);
void bclose(struct bfile *file);

#endif
