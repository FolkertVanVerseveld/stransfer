#include "string.h"
#include <string.h>

char *strncpyz(char *restrict dest, const char *restrict src, size_t n)
{
	if (n) {
		strncpy(dest, src, n - 1);
		dest[n - 1] = '\0';
	}
	return dest;
}
