#ifndef JOBS_H
#define JOBS_H
typedef void *(*job_fn)(void *);
int start_job(job_fn fn, void *arg);
#endif
