#include "string.h"
#include <stdio.h>
#include <string.h>

char *strncpyz(char *restrict dest, const char *restrict src, size_t n)
{
	if (n) {
		strncpy(dest, src, n - 1);
		dest[n - 1] = '\0';
	}
	return dest;
}

unsigned strtosi(char *str, size_t n, size_t num, unsigned fnum)
{
	static const char *sibase = " KMGTPE";
	const char *si = sibase;
	size_t d = num;
	unsigned rem = 0;
	while (d >= 1024) {
		rem = d % 1024;
		d /= 1024;
		++si;
	}
	if (!fnum || si == sibase)
		snprintf(str, n, "%u%cB", (unsigned)d, *si);
	else {
		char sbuf[32];
		snprintf(sbuf, sizeof sbuf, "%%u.%%0%du%%cB", fnum);
		snprintf(str, n, sbuf, (unsigned)d, (unsigned)(rem / 1.024f), *si);
	}
	return (unsigned)(si - sibase);
}

void streta(char *str, size_t n, size_t bdiff, struct timespec *last, struct timespec *now)
{
	struct timespec diff;
	char sbuf[32];
	tsdiff(&diff, last, now);
	unsigned long dt = diff.tv_sec * 1000 + (diff.tv_nsec / 1000000L);
	//printf("dt=%lu\n", dt);
	float speed = 1000.0f * bdiff / dt;
	strtosi(sbuf, sizeof sbuf, speed, 3);
	snprintf(str, n, "%s/s", sbuf);
}
