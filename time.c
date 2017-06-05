#include "time.h"
#include "string.h"
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

void tsdiff(struct timespec *dest, const struct timespec *start, const struct timespec *end)
{
	if (start->tv_nsec <= end->tv_nsec) {
		dest->tv_sec  = end->tv_sec  - start->tv_sec;
		dest->tv_nsec = end->tv_nsec - start->tv_nsec;
	} else {
		dest->tv_sec  = end->tv_sec  - start->tv_sec - 1;
		dest->tv_nsec = 1000000000LL - (end->tv_nsec - start->tv_nsec);
	}
}

void eta_init(struct eta *e, uint64_t index, uint64_t max)
{
	e->index = index;
	e->max = max;
	e->index_old = 0;
	clock_gettime(CLOCK_MONOTONIC, &e->now);
	e->last = e->start = e->now;
}

void eta_step(struct eta *e, uint64_t inc)
{
	int print = 0;
	if (e->index + inc >= e->max) {
		e->index = e->max;
		return;
	} else
		e->index += inc;
	clock_gettime(CLOCK_MONOTONIC, &e->now);
	struct timespec diff;
	tsdiff(&diff, &e->last, &e->now);
	if (diff.tv_sec || diff.tv_nsec > 100000000LL)
		print = 1;
	if (!print) return;
	//printf("d: %ld %ld\n", (long)diff.tv_sec, (long)diff.tv_nsec);
	float perc = (float)e->index / e->max;
	char buf[256];
	uint64_t bdiff = e->index - e->index_old;
	//printf("bdiff: %" PRIu64 "\n", bdiff);
	streta(buf, sizeof buf, bdiff, &e->last, &e->now);
	printf("\033[u%s (%.2f%%)\033[K", buf, 100.0 * perc);
	e->last = e->now;
	e->index_old = e->index;
}

void eta_done(struct eta *e)
{
	struct timespec diff;
	char buf[256], dbuf[256];
	tsdiff(&diff, &e->start, &e->now);
	clock_gettime(CLOCK_MONOTONIC, &e->now);
	streta(buf, sizeof buf, e->max, &e->start, &e->now);
	if (diff.tv_sec) {
		float dt = diff.tv_sec + diff.tv_nsec / 1000000000.0f;
		snprintf(dbuf, sizeof dbuf, "%.2fsec", dt);
	} else
		snprintf(dbuf, sizeof dbuf, "%.2fmsec", diff.tv_nsec / 1000000.0f);
	printf("\033[u%s in %s\033[K\n", buf, dbuf);
}
