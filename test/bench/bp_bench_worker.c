/*
 * bp_bench_worker.c - Multi-threaded worker for breakpoint benchmarking
 *
 * Spawns N threads that sleep forever. The main thread writes its PID
 * to a file and then sleeps. This process is meant to be checkpointed
 * and restored by the benchmark driver script.
 *
 * Usage: ./bp_bench_worker <num_threads> <pid_file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

static void *thread_func(void *arg)
{
	(void)arg;
	while (1)
		sleep(1000);
	return NULL;
}

int main(int argc, char **argv)
{
	int nr_threads;
	const char *pid_file;
	FILE *f;
	int i;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <num_threads> <pid_file>\n",
			argv[0]);
		return 1;
	}

	nr_threads = atoi(argv[1]);
	pid_file = argv[2];

	if (nr_threads < 0 || nr_threads > 100000) {
		fprintf(stderr, "num_threads must be 0..100000\n");
		return 1;
	}

	for (i = 0; i < nr_threads; i++) {
		pthread_t th;
		int ret = pthread_create(&th, NULL, thread_func, NULL);

		if (ret) {
			fprintf(stderr, "pthread_create #%d: %s\n",
				i, strerror(ret));
			return 1;
		}
		pthread_detach(th);
	}

	/* Write PID so the driver script can find us */
	f = fopen(pid_file, "w");
	if (!f) {
		perror("fopen pid_file");
		return 1;
	}
	fprintf(f, "%d\n", getpid());
	fclose(f);

	/* Sleep until killed or checkpointed */
	while (1)
		sleep(1000);

	return 0;
}
