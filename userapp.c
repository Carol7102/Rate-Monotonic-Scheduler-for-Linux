#include "userapp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

int is_in_list(unsigned int pid){
	char buf[5000];
	FILE* file_pr;
	char* token;
	size_t len;
	unsigned int temp_pid;
	unsigned int pid_list[100];
	int counter = 0;
	file_pr = fopen("/proc/mp2/status", "r");
	len = fread(buf, sizeof(char), 4999, file_pr);
	buf[len] = '\0';
	fclose(file_pr);
	// transfer to a list
	for (token = strtok(buf,"\n"); token != NULL; token = strtok(NULL, "\n")){
		sscanf(token, "%u", &temp_pid);
		pid_list[counter] = temp_pid;
		counter++;
	}
	// check if the current pid in the list
	for (int i = 0; i < counter; i ++) {
		if (pid_list[i] == pid) {
                return 1;
		}
	}
        return 0;
}

void job_yield(unsigned int pid)
{
	FILE* file_pr;
	file_pr = fopen("/proc/mp2/status", "w+");
	fprintf(file_pr, "Y, %u", pid);
	fclose(file_pr);
}

void job_deregister(unsigned int pid)
{
	char command[500];
	memset(command, '\0', 500);
	sprintf(command, "echo \"D, %u\" > /proc/mp2/status", pid);
	system(command);
}

void do_job(int num) {
	long long int ret = 1;
	for (int i = 1; i <= num; i ++) {
  		ret *= i;
	}
}

int main(int argc, char *argv[])
{
	struct timeval t0, wakeup_time, job_processing_time;
	unsigned int pid;
	unsigned int factorial_number;
	char *period;
	char *proc_time;
	pid = getpid();
	period = argv[1];
	proc_time = argv[2];
	int num_jobs;
	char command[500];
	factorial_number = 10;
	memset(command, '\0', 500);
	sprintf(command, "echo \"R, %u, %s, %s\" > /proc/mp2/status", pid, period, proc_time);
        system(command);
	// check if in list
	if (!is_in_list(pid)){
                exit(1);
	}
	num_jobs = atoi(argv[3]);
	// record start time t0
	gettimeofday(&t0, NULL);
	// yield to Proc filesystem
	job_yield(pid);
	// do multiple jobs
	for (int i = 0; i < num_jobs; i++) {
		// record wakeup time wakeup_time
		gettimeofday(&wakeup_time, NULL);
		do_job(factorial_number);
		// record job process time
		gettimeofday(&job_processing_time, NULL);
		job_yield(pid);
	}
	// de-register
	job_deregister(pid);
	return 0;
    
}
