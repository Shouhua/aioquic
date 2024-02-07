SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, ${SRC})

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
		-lev

run: client
	./build/client "/home/shouhua/project/aioquic/tests/pycacert.pem"

debug: client
	gdb --args ./build/client "/home/shouhua/project/aioquic/tests/pycacert.pem"

clean: 
	rm -rfv build