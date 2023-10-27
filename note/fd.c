/*
sudo apt install inotify-tools
while inotifywait -q -e modify fd.c; do echo -e '\n'; make; done
*/
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

void show(int fd1)
{
	int flags;
	long int offset = 0;
	flags = fcntl(fd1, F_GETFL);

	if (flags & O_APPEND)
	{
		fprintf(stdout, "%d has O_APPEND\n", fd1);
	}
	else
	{
		fprintf(stdout, "%d doesn't have O_APPEND attribute\n", fd1);
	}

	offset = lseek(fd1, 0, SEEK_CUR);
	if (offset == -1)
	{
		fprintf(stderr, "lseek failed: %s\n", strerror(errno));
	}
	fprintf(stdout, "file offset: %ld\n", offset);
	fprintf(stdout, "------------\n");
}

int main(int argc, char *argv[])
{
	int fd1, fd2;
	int flags;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s file_path\n", argv[0]);
		exit(1);
	}

	fd1 = open(argv[1], O_RDWR);
	fd2 = dup(fd1);

	printf("fd1: %d, fd2: %d\n", fd1, fd2);

	show(fd1);

	flags = fcntl(fd2, F_GETFL);
	flags |= O_APPEND;
	fcntl(fd2, F_SETFL, flags);

	if (lseek(fd2, 3, SEEK_SET) == -1)
	{
		fprintf(stderr, "lseek set failed: %s\n", strerror(errno));
		exit(-1);
	}

	show(fd1);

	close(fd1);
	close(fd2);
	return 0;
}