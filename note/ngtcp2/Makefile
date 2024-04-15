SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, ${SRC})

# -Wl,--trace-symbol,SYMBOL
# CREF=-Wl,--cref
TRACE=-Wl,--trace # 打印GCC搜寻共享库目录
RPATH=-Wl,-rpath=/usr/local/lib64
PEDANTIC=-pedantic
CFLAGS= -rdynamic -DDEBUG -g -O0 -Wall -Wextra \
	${PEDANTIC} \
	${RPATH} \
	# ${CREF} \
	# ${TRACE} 

# quictls(openssl)
LDFLAGS=-L/usr/local/lib64 

.PHONY: build_dir all
all: build_dir ${EXE}
	
build_dir: 
	@mkdir -p build

%: %.c
	@gcc ${CFLAGS} -o build/$@ $<  \
		${LDFLAGS} \
		-lssl -lcrypto \
		-lngtcp2 -lngtcp2_crypto_quictls \
		-lnghttp3 

run_quic: client
	@SSLKEYLOGFILE=keylog.txt ./build/client $${REMOTE_IP} 8443 "/home/shouhua/project/aioquic/note/ngtcp2/ca_cert.pem"

debug_quic: client
	gdb --args ./build/client $${REMOTE_IP} 8443  "/home/shouhua/project/aioquic/note/ngtcp2/ca_cert.pem"

run_http3: http3_client
	@SSLKEYLOGFILE=keylog.txt ./build/http3_client $$REMOTE_IP 443 ca_cert.pem

debug_http3: http3_client
	gdb --args ./build/http3_client $${REMOTE_IP} 443  "/home/shouhua/project/aioquic/note/ngtcp2/ca_cert.pem"

clean: 
	rm -rfv build