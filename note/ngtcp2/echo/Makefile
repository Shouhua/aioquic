SHELL := /bin/bash
SRC = $(wildcard *.c)
CLIENT_SRC = $(filter-out server.c, ${SRC})
SERVER_SRC = $(filter-out client.c, ${SRC})
# EXE = $(patsubst %.c, %, ${SRC})
EXE=client server

# -Wl,--trace-symbol,SYMBOL
# CREF=-Wl,--cref
TRACE=-Wl,--trace # 打印GCC搜寻共享库目录
RPATH=-Wl,-rpath=/usr/local/lib64
PEDANTIC=-pedantic
CFLAGS= -g -Wall -Wextra \
	${PEDANTIC} \
	${RPATH} \
	# ${CREF} \
	# ${TRACE} 

# quictls(openssl)
LDFLAGS=-L/usr/local/lib64 

.PHONY: build_dir all run run_server run_client debug_client debug_server client server clean
all: build_dir client server
	
build_dir: 
	@mkdir -p build

client: ${CLIENT_SRC}
	@gcc ${CFLAGS} -o build/$@ ${CLIENT_SRC}  \
		${LDFLAGS} \
		-lssl -lcrypto \
		-lngtcp2 -lngtcp2_crypto_quictls

run_client: client
	./build/client "localhost" "4433" "/home/shouhua/project/aioquic/tests/pycacert.pem"

debug_client: client
	gdb --args ./build/client "localhost" "4433" \
	"/home/shouhua/project/aioquic/tests/pycacert.pem"

server: ${SERVER_SRC}
	@gcc ${CFLAGS} -o build/$@ ${SERVER_SRC}  \
		${LDFLAGS} \
		-lssl -lcrypto \
		-lngtcp2 -lngtcp2_crypto_quictls
	
debug_server: server
	@gdb --args ./build/server localhost 4433 "/home/shouhua/project/aioquic/tests/ssl_cert.pem" "/home/shouhua/project/aioquic/tests/ssl_key.pem"

run_server: server
	@./build/server localhost 4433 "/home/shouhua/project/aioquic/tests/ssl_cert.pem" "/home/shouhua/project/aioquic/tests/ssl_key.pem"

run: server client
	if tmux has-session -t quic 2>/dev/null; then tmux kill-session -t quic; fi; \
	tmux new-session -t "quic" -d; \
	tmux send-keys -t quic:0 "cd ~/project/aioquic/note/ngtcp2/echo" C-m; \
	tmux split-window -t quic -v; \
	tmux send-keys -t quic:0.0 "make run_server" C-m; \
	sleep 1; \
	tmux send-keys -t quic:0.1 "make run_client" C-m; \
	if [[ -z "$$TMUX" ]]; then tmux attach-session -t quic; else tmux switch-client -t quic; fi;

clean: 
	rm -rfv build