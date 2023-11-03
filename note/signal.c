/**
 * cat /proc/pid/status | grep -E 'Sig.*'
 * 1. 查看父子进程signal继承，规则是除了父进程ignore的signal保留，其他都恢复成default
 * 2. siganlaction, sigprocmask, sigsuspend流程
 * 3. fork, execve, wait, waitpid(pid, &status, WUNTRACED | WCONTINUED)，也别是验证使用waipid的options后，可以获取子进程stopped,continued, killed, terminated的状态
 * 		kill -STOP child_pid
 * 		kill -CONT child_pid
 * 		kill -KILL child_pid
 * 		会看到waitpid分支都会有相应的响应
 * 4. SIGCHLD每当子进程状态发生变化时，kernel会给其父进程发送SIGCHLD消息，包括子进程stopped，continued，terminated
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <errno.h>

void handler_event(int signo, siginfo_t *info, void *context)
{
	(void)(context);
	fprintf(stdout, "sno: %d\nsigno: %d( %s )\nsigcode: %d\nsendpid: %d\nuid: %d\n",
			signo,
			info->si_signo,
			sigabbrev_np(info->si_signo),
			info->si_code,
			info->si_pid,
			info->si_uid);

	printf("\n");
}

void handler_usr1(int signo)
{
	fprintf(stdout, "signo: %d\n", signo);
	printf("handle done...\n");
}

void handler_usr2(int signo, siginfo_t *info, void *context)
{
	(void)(context);
	fprintf(stdout, "sno: %d\nsigno: %d\nsigcode: %d\nsendpid: %d\nuid: %d\n",
			signo,
			info->si_signo,
			info->si_code,
			info->si_pid,
			info->si_uid);
	printf("handle done...\n");
}

int main()
{
	pid_t ppid, pid;
	int status;

	// struct sigaction sa_usr1, sa_usr2, sa_chld, sa;
	struct sigaction sa;
	sigset_t block_set, origin_set, empty_set;

	sigemptyset(&block_set);
	sigaddset(&block_set, SIGUSR1);
	sigaddset(&block_set, SIGUSR2);
	sigprocmask(SIG_BLOCK, &block_set, &origin_set);

	int events[] = {SIGUSR1, SIGUSR2, SIGCHLD};
	long unsigned int i;
	for (i = 0; i < sizeof(events) / sizeof(int); i++)
	{
		sa.sa_sigaction = &handler_event;
		sa.sa_flags = SA_SIGINFO;
		sigemptyset(&sa.sa_mask);
		if (sigaction(events[i], &sa, NULL) == -1)
		{
			perror("sigaction");
			exit(EXIT_FAILURE);
		}
	}
	// sa_chld.sa_sigaction = &handler_chld;
	// sa_chld.sa_flags = SA_SIGINFO;
	// sigemptyset(&sa_chld.sa_mask);
	// if (sigaction(SIGUSR1, &sa_usr1, NULL) == -1)
	// {
	// 	perror("sigaction");
	// 	exit(EXIT_FAILURE);
	// }

	// // sa_usr1.sa_handler = &handler_usr2;
	// sa_usr1.sa_sigaction = &handler_usr2;
	// sa_usr1.sa_flags = SA_SIGINFO;
	// sigemptyset(&sa_usr1.sa_mask);

	// if (sigaction(SIGUSR1, &sa_usr1, NULL) == -1)
	// {
	// 	perror("sigaction");
	// 	exit(EXIT_FAILURE);
	// }

	// sa_usr2.sa_handler = SIG_IGN;
	// // sa_usr2.sa_handler = SIG_IGN;
	// sa_usr2.sa_flags = SA_SIGINFO;
	// sigemptyset(&sa_usr2.sa_mask);
	// if (sigaction(SIGUSR2, &sa_usr2, NULL) == -1)
	// {
	// 	perror("sigaction");
	// 	exit(EXIT_FAILURE);
	// }

	ppid = getpid();
	if ((pid = fork()) == 0)
	{
		// char *param = (char *)malloc(64 * sizeof(char));
		// pid = getpid();
		// sprintf(param, "/proc/%d/status", pid);
		// printf("param: %s\n", param);
		// fflush(stdout);
		// if (execlp("bash", "bash", "signal.sh", (char *)0) == -1)
		// {
		// 	perror("execl");
		// }
		execlp("bash", "bash", "signal.sh", (char *)0);
		// 不用判断，能到这里来，肯定是execve出问题了。。。
		perror("execl");
		exit(EXIT_FAILURE);
	}
	else if (pid == -1)
	{
		perror("fork");
		exit(EXIT_FAILURE);
	}
	else
	{
		printf("ppid: %d, pid: %d\n", ppid, pid);

		sigemptyset(&empty_set);
		for (;;)
		{
			if (sigsuspend(&empty_set) == -1 && errno != EINTR)
			{
				perror("sigsuspend");
			}
		}

		if (sigprocmask(SIG_SETMASK, &empty_set, NULL) == -1)
			perror("sigprocmask origin_set");

		for (;;)
		{
			pid_t wpid = waitpid(pid, &status, WUNTRACED | WCONTINUED);
			if (wpid == -1 && errno != EINTR)
			{
				perror("waitpid");
				exit(EXIT_FAILURE);
			}
			if (WIFEXITED(status))
			{
				fprintf(stdout, "child process %d is exited with code: %d\n", wpid, WEXITSTATUS(status));
				break;
			}
			else if (WIFSIGNALED(status))
			{
				fprintf(stdout, "child process %d is terminated by signal: %d( %s ), coredump: %d\n", wpid, WTERMSIG(status), sigabbrev_np(WTERMSIG(status)), WCOREDUMP(status));
			}
			else if (WIFSTOPPED(status))
			{
				fprintf(stdout, "child process %d is stopped by signal: %d( %s )\n", wpid, WSTOPSIG(status), sigabbrev_np(WSTOPSIG(status)));
			}
			else if (WIFCONTINUED(status))
			{
				fprintf(stdout, "child process %d is continued by signal: SIGCONT\n", wpid);
			}
			else
			{
				fprintf(stderr, "never go here\n");
				exit(EXIT_FAILURE);
			}
		}
		printf("parent done...\n");
		return 0;
	}
}