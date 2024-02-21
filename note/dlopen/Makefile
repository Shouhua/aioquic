CFLAGS=-Wall -Wextra

# This causes DT_RUNPATH to be used instead of DT_RPATH (at least here on
# Fedora). This causes the library not to be found by dlopen.
EXTRA_LD=-Wl,--enable-new-dtags

# This causes DT_RPATH to be used. This does work!
#EXTRA_LD=-Wl,--disable-new-dtags

all: run

run: lib/liblib.so main_direct main_indirect
	./main_direct
	./main_indirect

main_direct: main.c dl_wrapper/libdl_wrapper.c
	gcc -o $@ $(CFLAGS) $< -ldl $(EXTRA_LD) -Wl,-rpath,lib

# 因为main_indirect的dynamic section是这样的(readelf -d main_indirect)：
# DT_NEEDED libdl_wrapper.so
# DT_RUNPATH lib:dl_wrapper
# 上面2行能找到libdl_wrapper.so, 因为是libdl_wrapper.so是DT_NEEDED，但是如果libdl_wrapper.so需要liblib.so, 
# 递归查找就不能使用DT_RUNPATH中的目录了(DT_RUNPATH不支持transitive search)，但是DT_RPATH可以
# 所以会出现找不到liblib.so的错误
main_indirect: main.c dl_wrapper/libdl_wrapper.so
	gcc -o $@ $(CFLAGS) $< -ldl $(EXTRA_LD) -Wl,-rpath,lib -Wl,-rpath,dl_wrapper -Ldl_wrapper -ldl_wrapper -DUSE_WRAPPER

%.so: %.c
	gcc -shared -fPIC -o $@ $(CFLAGS) $<

main.c: Makefile
	echo '#include <stdio.h>' > $@
	echo '#include <dlfcn.h>' >> $@
	echo '#ifdef USE_WRAPPER' >> $@
	echo 'void *dlopen_wrapper(const char *filename);' >> $@
	echo 'void *dlsym_wrapper(void *handle, const char *symbol);' >> $@
	echo 'int dlclose_wrapper(void *handle);' >> $@
	echo '#else' >> $@
	echo '#include "dl_wrapper/libdl_wrapper.c"' >> $@
	echo '#endif' >> $@
	echo 'int main() {' >> $@
	echo '    void *handle = dlopen_wrapper("liblib.so");' >> $@
	echo '    if (handle == NULL) {' >> $@
	echo '        fprintf(stderr, "dlopen failed: %s\\n", dlerror());' >> $@
	echo '        return 1;' >> $@
	echo '    }' >> $@
	echo '    const char **some_text = dlsym_wrapper(handle, "some_text");' >> $@
	echo '    printf("some_text is: %s\\n", *some_text);' >> $@
	echo '    dlclose_wrapper(handle);' >> $@
	echo '    return 0;' >> $@
	echo '}' >> $@

lib/liblib.c: Makefile
	mkdir -p lib
	echo 'const char *some_text = "Hello world!";' > $@

dl_wrapper/libdl_wrapper.c: Makefile
	mkdir -p dl_wrapper
	echo '#include <dlfcn.h>' > $@
	echo 'void *dlopen_wrapper(const char *filename) {' >> $@
	echo '    return dlopen(filename, RTLD_NOW | RTLD_LOCAL);' >> $@
	echo '}' >> $@
	echo 'void *dlsym_wrapper(void *handle, const char *symbol) {' >> $@
	echo '    return dlsym(handle, symbol);' >> $@
	echo '}' >> $@
	echo 'int dlclose_wrapper(void *handle) {' >> $@
	echo '    return dlclose(handle);' >> $@
	echo '}' >> $@

clean:
	rm -f main_direct main_indirect dl_wrapper/libdl_wrapper.so lib/liblib.so dl_wrapper/libdl_wrapper.c lib/liblib.c main.c
	-rmdir lib dl_wrapper 2> /dev/null