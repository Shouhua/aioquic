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
	int flags, amode;
	// long int offset = 0;
	flags = fcntl(fd1, F_GETFL);

	amode = flags & O_ACCMODE;
	fprintf(stdout, "amode: %d\n", amode);
	if (amode == O_RDONLY || amode == O_RDWR)
	{
		fprintf(stdout, "file is readable, amode: %d\n", amode);
	}

	if (flags & O_APPEND)
	{
		fprintf(stdout, "%d has O_APPEND\n", fd1);
	}
	else
	{
		fprintf(stdout, "%d doesn't have O_APPEND attribute\n", fd1);
	}

	// offset = lseek(fd1, 0, SEEK_CUR);
	// if (offset == -1)
	// {
	// 	fprintf(stderr, "lseek failed: %s\n", strerror(errno));
	// 	exit(-1);
	// }
	// fprintf(stdout, "file offset: %ld\n", offset);
	fprintf(stdout, "------------\n");
}

int main()
{
	show(10);
	close(10);
	return 0;
}