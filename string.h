#ifndef STRING_H
#define STRING_H

#include <stddef.h>
#include "time.h"

char *strncpyz(char *restrict dest, const char *restrict src, size_t n);
unsigned strtosi(char *str, size_t n, size_t num, unsigned fnum);
void streta(char *str, size_t n, size_t diff, struct timespec *last, struct timespec *now);

#endif
