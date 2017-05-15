#ifndef TIME_H
#define TIME_H

#include <stdint.h>
#include <time.h>

struct eta {
	uint64_t index_old, index, max;
	struct timespec start, last, now;
};

void tsdiff(struct timespec *dest, const struct timespec *start, const struct timespec *end);

void eta_init(struct eta *e, uint64_t index, uint64_t max);
void eta_step(struct eta *e, uint64_t inc);
void eta_done(struct eta *e);

#endif
