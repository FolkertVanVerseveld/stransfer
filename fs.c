#include "fs.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "string.h"

void binit(struct bfile *f)
{
	f->fd = -1;
	f->data = MAP_FAILED;
	f->size = 0;
	f->flags = 0;
}

static int bopenr(struct bfile *f, const char *name)
{
	int ret = 1;
	f->fd = open(name, O_RDONLY);
	if (f->fd == -1) {
		fprintf(stderr, "Can't open \"%s\": %s\n", name, strerror(errno));
		goto fail;
	}
	if (fstat(f->fd, &f->st)) {
		fprintf(stderr, "Can't access \"%s\": %s\n", name, strerror(errno));
		goto fail;
	}
	f->data = mmap(NULL, f->size = f->st.st_size, PROT_READ, MAP_SHARED, f->fd, 0);
	if (f->data == MAP_FAILED) {
		fprintf(stderr, "Can't map \"%s\": %s\n", name, strerror(errno));
		goto fail;
	}
	ret = 0;
fail:
	return ret;
}

static int bopenw(struct bfile *f, const char *name, size_t size)
{
	int ret = 1, flags = O_RDWR | O_CREAT | O_EXCL;
	f->fd = open(name, flags, 0664);
	if (f->fd == -1) {
		fprintf(stderr, "Can't create \"%s\": %s\n", name, strerror(errno));
		goto fail;
	}
	if (ftruncate(f->fd, size)) {
		fprintf(stderr, "Can't truncate \"%s\": %s\n", name, strerror(errno));
		goto fail;
	}
	if (fstat(f->fd, &f->st)) {
		fprintf(stderr, "Can't access \"%s\": %s\n", name, strerror(errno));
		goto fail;
	}
	f->data = mmap(NULL, f->size = size, PROT_READ | PROT_WRITE, MAP_SHARED, f->fd, 0);
	if (f->data == MAP_FAILED) {
		fprintf(stderr, "Can't map \"%s\": %s\n", name, strerror(errno));
		goto fail;
	}
	ret = 0;
fail:
	return ret;
}

int bopen(struct bfile *f, const char *name, unsigned mode, size_t size)
{
	int ret = mode & BM_READ ? bopenr(f, name) : bopenw(f, name, size);
	if (!ret) {
		const char *start = strrchr(name, '/');
		if (!start)
			start = name;
		else
			++start;
		strncpyz(f->name, start, N_NAMESZ);
		printf("name: \"%s\"\n", f->name);
	}
	return ret;
}

void bclose(struct bfile *f)
{
	if (f->data != MAP_FAILED) {
		munmap(f->data, f->size);
		f->data = MAP_FAILED;
	}
	if (f->fd != -1) {
		close(f->fd);
		f->fd = -1;
	}
}
