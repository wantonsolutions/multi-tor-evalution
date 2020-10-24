#ifndef NANOSLEEP_H
#define NANOSLEEP_H

#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

//#define ITERS 100*1000

static inline uint64_t clock_gettime_us(struct timespec* ts1){
	clock_gettime(CLOCK_REALTIME, ts1);
	uint64_t ts1_nsec = (uint64_t) ts1->tv_nsec + 1000000000 * (uint64_t) ts1->tv_sec;
	return ts1_nsec/1000;
}

static inline uint64_t clock_gettime_diff_us(struct timespec* ts1, struct timespec* ts2){
	uint64_t ts1_nsec = (uint64_t) ts1->tv_nsec + 1000000000 * (uint64_t) ts1->tv_sec;
	uint64_t ts2_nsec = (uint64_t) ts2->tv_nsec + 1000000000 * (uint64_t) ts2->tv_sec;
	if(ts2_nsec > ts1_nsec)
		return (ts2_nsec/1000) - (ts1_nsec/1000);
	else
		return (ts1_nsec/1000) - (ts2_nsec/1000);
}

static inline uint64_t clock_gettime_ns(struct timespec* ts1){
	clock_gettime(CLOCK_REALTIME, ts1);
	return (uint64_t) ts1->tv_nsec + 1000000000 * (uint64_t) ts1->tv_sec;
}

static inline uint64_t clock_gettime_diff_ns(struct timespec* ts1, struct timespec* ts2){
	uint64_t ts1_nsec = (uint64_t) ts1->tv_nsec + 1000000000 * (uint64_t) ts1->tv_sec;
	uint64_t ts2_nsec = (uint64_t) ts2->tv_nsec + 1000000000 * (uint64_t) ts2->tv_sec;
	if(ts2_nsec > ts1_nsec)
		return ts2_nsec - ts1_nsec;
	else
		return ts1_nsec - ts2_nsec;
}

static inline uint64_t realnanosleep(uint64_t target_latency, struct timespec* ts1, struct timespec* ts2){
    uint64_t accum = 0;
    while(accum < target_latency){
        clock_gettime(CLOCK_REALTIME, ts2);
		if(ts1->tv_sec == ts2->tv_sec){
        	accum = accum + (uint64_t)(ts2->tv_nsec - ts1->tv_nsec);
		}
		else{
			uint64_t ts1_nsec = (uint64_t) ts2->tv_nsec + 1000000000 * (uint64_t) ts2->tv_sec;
			uint64_t ts2_nsec = (uint64_t) ts2->tv_nsec + 1000000000 * (uint64_t) ts2->tv_sec;
			accum = accum + (ts2_nsec - ts1_nsec);
    	}
		ts1->tv_nsec = ts2->tv_nsec;
		ts1->tv_sec = ts2->tv_sec;
	}
	return accum;
}

#endif //NANOSLEEP_H