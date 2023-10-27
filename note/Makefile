# sudo apt install inotify-tools
# while inotifywait -q -e modify fd.c; do echo -e '\n'; make; done

all:
	@gcc -Wall -Wextra -pedantic -o fd fd.c
	@gcc -Wall -Wextra -pedantic -o fd_stat fd_stat.c
	@./fd_stat