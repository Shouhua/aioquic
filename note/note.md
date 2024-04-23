## 2024-04-22
### getopt(man 3 getopt)
getopt用来处理程序options, 可以处理短格式(-)和长格式(--), 前者使用getopt函数, ；后者使用getopt_long函数处理, 她可以同时处理长格式和短格式。
```c
extern char *optarg;
extern int optind, opterr, optopt;
int getopt(int argc, char * const argv[], const char *optstring);
int getopt_long(int argc, char * const argv[], const char *optstring, const struct option *longopts, int *longindex);
struct option {
	const char *name;
	int has_arg; // no_argument(0), required_argument(1), optional_argument(2)
	int *flag; // flag为
	int val; 
}
```
1. optstring类似`"ab:c::"`
':'表示需要argument
'::'表示argument是optional的, 但是**如果有argument, 那么option和arugument之间不能有空格**

2. struct option需要使用使用空struct结尾；
flag == NULL或者0, getopt_long返回val; 此时如果val为0, 则始终返回0；
其他情况getopt_long返回0, 并且如果发现了long argument, flag会指向val, 否则没有发现的话, flag保持不变；比如：
```c
struct option long_options[] = 
{
     {.name="add", .has_arg=required_argument, .flag=0, .val=0},
     {0, 0, 0, 0}
}
```

3. longindex表示longopts数组里面的index, 库会填充。可以使用这个index获得struct option, 比如--add, longindex=0, 可以使用longopts[longindex]获取struct对象。

4. `optind` is the index of the next element to be processed in argv。

5. `extern char *optarg;` 如果option有argument, 那么optarg指向argument。

6.  `extern int opterr;`, 默认情况下有两种错误情况
     - 不存在的option
     - missing argument
默认情况库会打印错误, 并且返回'?'。设置`opterr=0`就不会打印库错误。根据返回值是否为'?'判断是否出现错误。

### getopts (man 1 getopts)
```bash
# ./test.sh -a hello -c world
OPTIND=1
while getopts ":a:c:" name; do
     case "${name}" in
          a) echo "a: ${OPTARG}";;
          c) echo "c: ${OPTARG}";;
          ?) echo "?";;
          :) echo ":";;
          *) echo "others";;
     esac
done
```

## 2024-04-17
### ngtcp2 Connection Migration代码流程
`Connection Migration`主要使用变更port, 从9000变为9001。当使用输入`\m`后触发port change, 现实中可能是IP变化, 总之会触发事件。
1. 重新生成并且绑定UDP socket
```c
fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
bind(fd, (struct sockaddr *)&source, sizeof(source));
connect(fd, (struct sockaddr *)(&remote), remote_len);
getsockname(fd, (struct sockaddr *)&local, &local_len)
```
2. ngtcp2提供了两种方式处理Connection Migration
     - nat rebinding
这种使用了`void ngtcp2_conn_set_local_addr(ngtcp2_conn *conn, const ngtcp2_addr *addr)`, 而这个函数说只用于test。所以这种方法只是设置了local address为新的地址, 仅此而已。
     - 根据协议规定, 发送`Path Challenge`, 对端回复`Path Response`
这种方式提供了两个接口
`int ngtcp2_conn_initiate_immediate_migration(ngtcp2_conn *conn, const ngtcp2_path *path, ngtcp2_tstamp ts)`
`int ngtcp2_conn_initiate_migration(ngtcp2_conn *conn, const ngtcp2_path *path, ngtcp2_tstamp ts)`
两者都会发送`Path Challenge Frame`, 但是前者不会等待server端的`Path Response`才迁移, 后者是最严格的流程。
```c
ngtcp2_addr addr;
ngtcp2_addr_init(&addr, (struct sockaddr *)&local, local_len);
if (0) // nat rebinding
{
     ngtcp2_conn_set_local_addr(conn, &addr);
     ngtcp2_conn_set_path_user_data(conn, client);
}
else
{
     ngtcp2_path path = {
          addr,
          {
               (struct sockaddr *)&remote,
               remote_len,
          },
          client,
     };
     if ((res = ngtcp2_conn_initiate_immediate_migration(conn, &path, timestamp())) != 0)
     // if ((res = ngtcp2_conn_initiate_migration(conn, &path, timestamp())) != 0)
     {
          fprintf(stderr, "ngtcp2_conn_initiate_immediate_migration: %s\n", ngtcp2_strerror(res));
          return -1;
     }
}
```
3. 处理path_validation callback
```c
int path_validation(ngtcp2_conn *conn, uint32_t flags, const ngtcp2_path *path,
					const ngtcp2_path *old_path,
					ngtcp2_path_validation_result res, void *user_data)
{
	(void)conn;
	if (old_path) // 一般没有填充
	{
		get_ip_port((struct sockaddr_storage *)(old_path->local.addr), ip, &port);
		fprintf(stdout, ", old local: %s:%d", ip, port);
	}

	if (flags & NGTCP2_PATH_VALIDATION_FLAG_PREFERRED_ADDR)
	{
		struct client *c = (struct client *)(user_data);
		memcpy(&c->remote_addr, path->remote.addr, path->remote.addrlen);
		c->remote_addrlen = path->remote.addrlen;
	}
	return 0;
}
```

### nghttp3 early data代码流程
当使用nghttp3客户端可以发送http3 get请求后, 下面开始添加支持early data代码流程
1. OpenSSL session管理
TLS1.3目前已经抛弃前面版本使用的[Session IDs或者Session tickets](https://datatracker.ietf.org/doc/html/rfc8446#section-2.2), 转而使用PSK(Pre Shared Key)。OpenSSL库还是使用Session的概念管理TLS的Session Resumption。

2. OpenSSL可以配置使用外部pem文件保存session数据
```c
/* 在成功新建SSL Context后配置callback保存PSK数据 */
if (c->session_file)
{
     // session stored externally by hand in callback function
     SSL_CTX_set_session_cache_mode(c->ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
     SSL_CTX_sess_set_new_cb(c->ssl_ctx, new_session_cb);
}
```
3. Callback中先使用max_early_data参数判断是否支持early data, 然后保存session数据
```c
uint32_t max_early_data;
if ((max_early_data = SSL_SESSION_get_max_early_data(session)) != UINT32_MAX)
{
     fprintf(stderr, "max_early_data_size is not 0xffffffff: %#x\n", max_early_data);
}
BIO *f = BIO_new_file(c->session_file, "w");
if (f == NULL)
{
     fprintf(stderr, "Could not write TLS session in %s\n", c->session_file);
     return 0;
}

if (!PEM_write_bio_SSL_SESSION(f, session))
{
     fprintf(stderr, "Unable to write TLS session to file\n");
}

BIO_free(f);
```
4. 新建SSL对象后, 加载session数据
```c
BIO *f = BIO_new_file(c->session_file, "r");
if (f == NULL) /* open BIO file failed */
{
     fprintf(stderr, "BIO_new_file: Could not read TLS session file %s\n", c->session_file);
}
else
{
     SSL_SESSION *session = PEM_read_bio_SSL_SESSION(f, NULL, 0, NULL);
     BIO_free(f);
     if (session == NULL)
     {
          fprintf(stderr, "PEM_read_bio_SSL_SESSION: Could not read TLS session file %s\n", c->session_file);
     }
     else
     {
          if (!SSL_set_session(c->ssl, session))
          {
               fprintf(stderr, "SSL_set_session: Could not set session\n");
          }
          else if (!c->disable_early_data && SSL_SESSION_get_max_early_data(session))
          {
               c->early_data_enabled = 1;
               SSL_set_quic_early_data_enabled(c->ssl, 1);
          }
          SSL_SESSION_free(session);
     }
}
```
5. 在应用代码侧, 如果可以使用early data功能, 就开始传递上次保存的Quic Transport Parameters, 这个是上次通信时保存的pem文件, 可以在ngtcp2的handshake_completed的callback中保存
```c
/* load quic transport parameters */
if (c->early_data_enabled && c->tp_file)
{
     char *data;
     long datalen;
     if ((data = read_pem(c->tp_file, "transport parameters", "QUIC TRANSPORT PARAMETERS", &datalen)) == NULL)
     {
          fprintf(stderr, "client quic init early data read pem failed\n");
          c->early_data_enabled = 0;
     }
     else
     {
          rv = ngtcp2_conn_decode_and_set_0rtt_transport_params(c->conn, (uint8_t *)data, (size_t)datalen);
          if (rv != 0)
          {
               fprintf(stderr, "ngtcp2_conn_decode_and_set_0rtt_transport_params failed: %s\n", ngtcp2_strerror(rv));
               c->early_data_enabled = 0;
          }
          else if (make_stream_early(c) != 0) // setup nghttp3 connection and populate http3 request
          {
               free(data); // free memory which allocated in read_pem function
               return -1;
          }
     }
     free(data); // free memory which allocated in read_pem function
}
```
```c
/* save quic transport parameters */
if (c->tp_file)
{
     uint8_t data[256];
     ngtcp2_ssize datalen = ngtcp2_conn_encode_0rtt_transport_params(c->conn, data, 256);
     if (datalen < 0)
     {
          fprintf(stderr, "Could not encode 0-RTT transport parameters: %s\n", ngtcp2_strerror(datalen));
          return -1;
     }
     else if (write_transport_params(c->tp_file, data, datalen) != 0)
     {
          fprintf(stderr, "Could not write transport parameters in %s\n", c->tp_file);
     }
}
```

### [autotools tutorial](https://www.lrde.epita.fr/~adl/dl/autotools.pdf), 见[pdf](./autotools/autotools.pdf)
#### Tutorial
1. https://www.lrde.epita.fr/~adl/dl/autotools.pdf
2. https://elinux.org/images/4/43/Petazzoni.pdf
3. https://www.chungkwong.cc/makefile.html

#### 宏解释
1. AC_DEFINE(VARIABLE, VALUE, DESCRIPTION)
会将定义写入config headers, 比如config.h, `#define VARIABLE VALUE`

2. AC_SUBST(VARIABLE, [VALUE])
将本地的变量全局化, 其他文件可以引用, 比如in文件中可以使用, Makefile.am也可以使用, `$(VARIABLE)`

3. AC_CHECK_LIB(LIBRARY, FUNCT, [ACT-IF-FOUND], [ACT-IF-NOT])
```bash
AC_CHECK_LIB([efence], [malloc], [EFENCELIB=-lefence])
AC_SUBST([EFENCELIB])
```
如果没有添加`ACT-IF-FOUND`, 会自动添加`LIBS="-lLIBRARY LIBS"`, automake会使用`$LIBS`进行链接, 还会添加定义到`config.h`, `#define HAVE_LIBLIBRARY`

4. AC_CONFIG_HEADERS([config.h:config.hin])
从`config.hin`文件生成`config.h`头文件, 包括各种check定义等, `config.h.in`文件里面可以引用m4宏, 使用类似`@foo@`语法

5. AC_CONFIG_FILES([Makefile sub/Makefile script.sh:script.in])
一般根据in文件生成文件, 一般用于生成Makefile文件, in文件和最终文件里面使用`@VAR@`引用, 但是`Makefile.in`也可以使用`Makefile`方式, 比如`$(VAR)`或者`${VAR}`引用, 因为automake做了处理, `VAR=@VAR@`

### CPPFLAGS, CFLAGS, CXXFLAGS
CPPFLAGS(Pre-Processor) 针对C或C++公有的预处理参数, 比如`-I/local/include`或者`-D`
CFLAGS 针对C语言的compiler flags
CXXFLAGS 针对C++语言的compiler flags

### CFLAGS默认值
CFLAGS在autotools中默认为`'-g -O2'`, 不知道为什么, 清除默认值
`autoreconf -i && ./configure CFLAGS= && make`
配置文件中一般使用`AM_CFLAGS`和`AM_CPPFLAGS`, `CFLAGS`, `CPPFLAGS`留给用户使用时设置

## 2024-04-15
### tshark
```shell
tshark -i ens33 -o tls.keylog_file:/home/shouhua/project/aioquic/note/ngtcp2/keylog.txt -Px -Y 'quic'
```

## 2024-04-02
'//' 是C99-style, C89-style没有

## 2024-03-19
### nginx ssl_cipher ssl_conf_command
```shell
# 指定ssl或者tls支持的算法列表
ssl_cipher ECDHE-ECDSA-AES256-GCM-SHA384

# 主要用于设置tls1.3的ciphersuits, 这里只能使用CHACHA20_POLY1305_SHA256
ssl_conf_command Ciphersuites TLS_CHACHA20_POLY1305_SHA256

# 报错, 因为nginx only support CHACHA20_POLY1305_SHA256
curl --capath "$(pwd)" --cacert ca_cert.pem --http3 -vv --tls13-ciphers TLS_AES_128_GCM_SHA256 https://my.web

# 这个值可作为上面tls1.3的支持算法(Ciphersuits)
openssl ciphers -s -tls1_3
openssl ciphers -V -s -tls1_3  | column -t
```

### volatile in c
https://www.geeksforgeeks.org/understanding-volatile-qualifier-in-c/
https://dev.to/pauljlucas/what-volatile-does-in-c-and-c-5147
valatile本质上是告诉编译器, 跟她相关的变量别优化, 因为可能有side-effect会修改她, 而compiler你有可能不知道
```c
/**
默认不优化, 输出正常
gcc -Wall -Wextra -pedantic -o test test.c
-O相当于-O1, 优化后, 可以查看汇编, ptr没有在汇编代码存在过, 因为编译器认为const不会被改变, 就把相关优化掉了
gcc -O -Wall -Wextra -pedantic -o test test.c

objdump -D -M intel test
*/
#include <stdio.h>

int
main()
{
        const int local = 10;
        int *ptr = (int *)&local;

        printf("initial value: %d\n", local);

        *ptr = 100;

        printf("modified value: %d\n", local);

        return 0;
}
```


## 2024-03-14
### vim中view文件夹
```vi
set foldenable
set foldmethod=manual
" loadview and mkview when buffer enter and leave
autocmd BufWinLeave *.* mkview
autocmd BufWinEnter *.* silent loadview
```
上述配置本来是要每次退出时保存当前的`vim`状态, 比如折叠等信息, 再次进入的时候会加载这些信息。这些信息存储在 `~/.vim/view` 文件夹中。这个配置也带了一些不清晰的误会, 比如每次修改`.vimrc`文件后, 再次打开其他文件时, 发现修改没有生效, 比如`tabstop`, 问题就出在这个`view`文件, 使用`:scriptnames`查看配置文件加载, 发现最后加载`view`文件覆盖`.vimrc`文件。如果不需要保存相关信息, 可以不使用`mkview`和`loadview`, 但是如果想使用配置文件, 就需要手动加载`.vimrc`文件(`source ~/.vimrc`)。

### C经验
1. C中struct分配内存可以连带内部指针一起分配
ngtcp2_crpyto.c ngtcp2_crypto_km_nocopy_new

### 
free -h
lscpu
or
cat /proc/cpuinfo
df -l -T -h -t ext4

## 2024-03-12
### 查看linux版本信息
除了通常的lsb_release外, 还可以使用如下几个文件查看`/etc/os-release`, `/etc/lsb_release`, `/etc/issue`

### Alpine Linux
alpine使用ash, musl作为libc, apk作为包管理器, 源位于/etc/apk/repositories, 源仓库为aports, 管理着所有的alpine仓库软件, 不同版本软件有不一样

### Docker中Ubuntu, Alpine基础镜像都是non-login shell, 可以修改添加shell参数修改, 修改后会加载/etc/profile文件
```bash
CMD ["bash", "--login"] # for Ubuntu
# or
CMD ["sh", "--login"] # for Alpine
```

## 2024-03-07
https://xiaolincoding.com/network/3_tcp/tcp_feature.html
重传
超时重传   RTO(Retransmission Timeout) 根据超时时间来判断是否重传
快速重传 三次连续的相同ACK, 表示某一个packet丢失了
	如果连续多个packet丢失, 需要一个一个重传后, 再次触发快速重传, 需要接收方将收到packet信息id区间发送给发送方, 引入SACK
	如果接收方收到了packet, 但是只是ACK丢失了, 同样会触发重传, 使用D-SACK告诉对方

滑动窗口(SWND)
发送一次等待ACK再继续进行, 效率低下, 引入窗口概念, 这要已发送的内容没有占满这个窗口, 就可以继续发送, 直至占满窗口。
窗口的实现实际上是操作系统开辟的一个缓存空间, 发送方主机在等到确认应答返回之前, 必须在缓冲区中保留已发送的数据。如果按期收到确认应答, 此时数据就可以从缓存区清除。
TCP头部中的Window字段表示接收方窗口大小, 本地还有多少缓存来接受数据。


流量控制(flow control)
解决发送端和接收端窗口关闭风险
滑动窗口 swnd = (rwnd - in_flight)

拥塞控制
控制网络路径拥堵状况。拥塞窗口(CWND)。CWND默认是MSS的倍数, 比如1, 2, 4MSS
swnd = min(cwnd, rwnd)
如何判断发生了拥塞, 发生了超时重传
拥塞控制算法：RENO, CUBIC, BBR
慢启动阶段(slow start) cwnd < ssthresh(Slow start thresh), 收到多少个ack, cwnd增加多少
拥塞避免阶段(congestion avoidance) cwnd >= ssthresh, 每收到一个ack, cwnd增加1/cwnd, 如果发送都受到, 相当于增加1
拥塞控制阶段 
	超时重传, ssthresh = cwnd / 2; cwnd = 1 -> slow start
	快速重传还能收到3个ack, 说明网络还行, cwnd = cwnd/2；ssthresh = cwnd -> 快速恢复
快速恢复阶段
拥塞窗口 cwnd = ssthresh + 3 （ 3 的意思是确认有 3 个数据包被收到了）；
重传丢失的数据包；
如果再收到重复的 ACK, 那么 cwnd 增加 1；
如果收到新数据的 ACK 后, 把 cwnd 设置为第一步中的 ssthresh 的值, 原因是该 ACK 确认了新的数据, 说明从 duplicated ACK 时的数据都已收到, 该恢复过程已经结束, 可以回到恢复之前的状态了, 也即再次进入拥塞避免状态；

AIMD(additive increase/multiplicative decrease)
Congestion Avoidance Algorithm
Tahoe and Reno, 都将RTO和duplicate ACKs作为packet loss events, 但是对duplicate ACKs方式不同, 前者使用超时重传方式, 后者使用快速重传方式
New Reno 解决Reno没遇到double ACKs就将cwnd减半, 如果遇到2个, 就减少4倍。
在Reno的快速恢复中, 一旦出现3次重复确认, TCP发送方会重发重复确认对应序列号的分段并设置定时器等待该重发分段包的分段确认包, 当该分段确认包收到后, 就立即退出快速恢复阶段, 进入拥塞控制阶段, 但如果某个导致重复确认的分段包到遇到重复确认期间所发送的分段包存在多个丢失的话, 则这些丢失只能等待超时重发, 并且导致拥塞窗口多次进入拥塞控制阶段而多次下降。而New Reno的快速恢复中, 一旦出现3次重复确认, TCP发送方先记下3次重复确认时已发送但未确认的分段的最大序列号, 然后重发重复确认对应序列号的分段包。如果只有该重复确认的分段丢失, 则接收方接收该重发分段包后, 会立即返回最大序列号的分段确认包, 从而完成重发；但如果重复确认期间的发送包有多个丢失, 接收方在接收该重发分段后, 会返回非最大序列号的分段确认包, 从而发送方继续保持重发这些丢失的分段, 直到最大序列号的分段确认包的返回, 才退出快速恢复阶段。
New Reno主要是没有SACK的tcp中使用解决问题, 有了SACK就比较少使用了（https://zh.wikipedia.org/wiki/TCP%E6%8B%A5%E5%A1%9E%E6%8E%A7%E5%88%B6）


https://xiaolincoding.com/network/3_tcp/quic.html
1. RTO使用RTT计算, TCP的packet number不是严格递增的, 如果重传, 无法知道是原先的响应延迟了, 还是重传包的ACK, 所以无法计算采样RTT的正确时间, 影响RTO
2. TCP丢包后, 窗口不滑动, 必须确认后才能继续滑动


## 2024-03-06
1. /usr/lib/locale/C.utf8/
包含默认的各种locale category

2. /usr/share/locale/
包含各种安装的locale, LC_COLLATE不在上面文件夹中, glib直接处理

3. ssh配置中可以传递locale相关环境变量(LANG LC_*), 具体参见参数SendEnv, 还可以传递其他全局环境变量, 但是两者均需要服务端支持, 服务端配置参数AcceptEnv

4. 如果命令中遇到文件不存在等, 可以直接使用strace跟踪看看到底是哪些文件找不到, 比如locale报错, 提示
`warning: setlocale: LC_CTYPE: cannot change locale (UTF-8): No such file or directory`, 可以使用如下命令查询:
```shell
strace locale 2&>1 | grep ENOENT
sudo strace -eopen locale-gen &> output
```

## 2024-03-05
### OpenSSL3.0引入OSSL_PARAM辅助函数, 比如OSSL_PARAM_utf8_string("bar", bar, sizeof(bar))等
```c
include <openssl/params.h>
// https://www.openssl.org/docs/manmaster/man3/OSSL_PARAM_construct_utf8_string.html
```

### Demystifying Cryptography with OpenSSL 3.0 第六章 Asymmetric Encryption and Decryption
非对称加密算法可用于加密和签名, OpenSSL中只有RSA算法用于直接加密, 其他需要通过session key(对称密钥)加解密
对称密钥只是字节, 没有格式意义; 非对称密钥一般使用格式化的密钥, 比如RSA有素数等, RSA至少2048bits才安全
`ECC` - `Elliptic Curve Cryptography`

#### 密钥文件格式
非对称密钥和公钥称为keypair, keypair文件格式有PEM(Privacy Enhanced Mail)和DER(Distinguished Encoding Rules), OpenSSL默认使用PEM存储keys和certificates。
PEM和DER关系
PEM format is really a Base64 wrapping around some binary data,
with a text header (the BEGIN line) and a text footer (the END line). If you remove the header and the
footer from the keypair PEM file and Base64-decode it, you will get the keypair in the Distinguished
Encoding Rules (DER) format

#### RSA padding 
PKCS#1 v2.0 OAEP(Optimal Asymmetric Encryption Padding) padding type, **-pkeyopt rsa_padding_mode:oaep**
```shell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_key.pem
openssl pkey -in rsa_key.pem -noout -text # 查看公私钥信息
openssl pkey -in rsa_key.pem -pubout -out rsa_public_key.pem #  到处公钥, 用于后面加密session key, 后者是真正用于加解密的key
openssl rand -out session_key.bin 32 # 生成session key
openssl pkeyutl -encrypt -in session_key.bin -out session_key.bin.encrypted -pubin -inkey rsa_public_key.pem -pkeyopt rsa_padding_mode:oaep
```

#### Session key
**RSA输出密文跟key长度一致**, 比如2048等(这也是其他非对称算法优势), 除去padding, 最大可以加密长度比如：key_size - 42 = 4096 - 42 = 4054,所以需要使用对称session key加密很长的plaintext

#### OpenSSL error handle
1. 每个线程有自己的OpenSSL error queue, 用户不需要初始化和释放
2. error queue主要用于 `asymmetric cryptography`, `X.509 certificates`和`TLS`, 但是`symmetric cryptgraphy`, `HMAC`等没有使用, 有可能泄露关键信息
```c
// Get the code of the earliest error in the queue and remove that error from the queue
ERR_get_error() 
ERR_peek_error()
ERR_GET_LIB()
ERR_GET_REASON()
ERR_error_string_n()

// Clear the queue and remove all the errors from it
ERR_clear_error() 

// Print the error queue to FILE stream and clear the queue , 这个函数有可能报错, 比如磁盘满了等. 这个函数很适合debug。k
ERR_print_errors_fp() 
if (ERR_peek_error()) {
     exit_code = 1;
     if (error_stream) {
          fprintf(error_stream, "Errors from the OpenSSL error queue:\n"); 
          ERR_print_errors_fp(error_stream);
     }
}
```
**注意, OpenSSL返回的code跟error queue中的code是不一样的**

### Demystifying Cryptography with OpenSSL 3.0 第七章 Digital Signatures and Their Verification
签名一般是用hash算法比如SHA256缩短plaintext长度, 然后使用非对称算法对hash值签名, 即为hash and sign
一个例外是EdDSA(pureEdDSA), 信息一次性全部作为输入, 其内部会对内容做hash处理, 见[例子](./openssl/ed25519.c)

#### ECDSA 
ECC(Elliptic Curve Cryptography) based signature, OpenSSL ECDSA支持两种椭圆曲线, `NIST curves`和`Brainpool curves`
其中NIST曲线有`P-256 curve`和`P-224 curve`, 非常快, 不同组织曲线名称有可能不一样, 见https://datatracker.ietf.org/doc/html/rfc4492#appendix-A
ECDSA需要非常好的随机数生成器, 已有一个版本使用hash of private key替代随机数

#### EdDSA
EC(Edwards Curve)-based signature algorithm, EdDSA不需要随机数, 没有泄露私钥风险, 支持两种曲线: `Curve25519`, `Curve448`。`Curve25519`表示曲线, **`Ed25519`表示使用Curve25519的EdDSA签名算法**, **`X25519`表示使用`Curve25519`的DH密钥交换算法**。<br>
OpenSSL中生成keypair时, 会有ED25519和X25519的区别, 前者用于签名, 后者用于key exchange, 混用会报错。
```shell
openssl genkey -algorithm ED25519 -out ed25519.pem
openssl genkey -algorithm X25519 -out ed25519.pem
```

https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
Key Exchange使用DH方式有两种：基于椭圆曲线(ECDHE), 基于有限域(DHE)
ECDHE(Elliptic Curve Diffie-Hellman Ephemeral) 包括SECP256r1, x25519等

#### OpenSSL命令
1. 以下命令, ED25519不需要指定曲线, 签名时也不需要指定MD方法, 指定会报错
2. 同样如果生成X25519的keypair, 签名时报错

```shell
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp521r1 -out secp512.key
openssl pkeyutl -sign -digest sha3-512 -inkey secp512.key -in somefile.txt -rawin -out somefile.txt.sign

openssl genpkey -algorithm ED25519 -out 25519.key
openssl pkeyutl -sign -inkey 25519.key -in somefile.txt -rawin -out somefile.txt.sign
```

## 2024-03-01
### 十六进制转化成字符串, 使用sscanf或者使用OPENSSL_hexstr2buf
#### sscanf的[format格式介绍](https://docwiki.embarcadero.com/RADStudio/Alexandria/en/Scanf_Format_Specifiers)<br>
https://www.eskimo.com/~scs/cclass/int/sx2f.html<br>
`%[*][maximum_field_width][length_modifier]conversion_specifier`

|format string| Description | Example | Matching Input | Results |
|--|--|--|--|--|
|*| 匹配输入但不赋值 | int anInput;<br> scanf("%*s %i", &anInput); | Age: _29| anInput = 29, return value = 1|
|maximum_field_width| 标识匹配输入的字节个数 | int anInt;<br>char s[10];<br>scanf("%2i", &anInt);<br>scanf("%9s", s); | 2345<br>VeryLongString | anInt==23,<br>return value==1<br>s=="VeryLongS"<br>return value==1 |
|length_modifier|标识目的匹配参数的类型(或者叫做大小)|char *src="12";<br>char des[2];<br>sscanf(src, "%2hhx\n", des);<br>printf("des[0] = %d\n",des[0]);||des[0] = 12|

#### sscanf返回值
正常情况成功返回成功匹配和赋值的个数。
如果部分成功匹配和赋值, 返回成功的个数; 如果input结束(EOF)时, 没有匹配成功或者匹配失败, 返回EOF, 使用errno查看。
```c
// https://wpollock.com/CPlus/PrintfRef.htm#printfLen
char buf[BUFSIZ], junk[BUFSIZ];
int income;

fprintf( stderr, "Please enter your income: " );
// Loop until the user enters a correct value:
while ( fgets( buf, sizeof(buf), stdin ) != NULL )
{
   if ( sscanf( buf, "%i%[^\n]", &income, junk ) == 1 )
      break;
   // Do some sort of error processing:
   fprintf( stderr, "\nError reading your income, please try again.\n" );
   fprintf( stderr, "Please enter your income: " );
}
// income correctly enters read at this point.
```
#### hexstr2buf
```c
unsigned char *hexstr2buf(const char *str)
{
	size_t len = strlen(str);
	if (len % 2 != 0)
		return NULL;
	size_t res_len = len / 2 + 1;
	unsigned char *res = (unsigned char *)malloc(res_len);

	for (int i = 0; i < len; i += 2)
	{
		sscanf(str + i, "%2hhx", res + i / 2);
	}
	*(res + res_len - 1) = '\0';
	return res;
}
```

### OpenSSL编程中AEAD(Authenticated Encryption with Associated Data)加密[注意点](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
对称加密通常使用EVP_EncryptUpdate或者EVP_CipherUpdate
```c
__owur int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            int *outl, const unsigned char *in, int inl);

/*__owur*/ int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
```
1. 必须先加入AAD(Additional Authenticated Data或者叫associated data)数据, 这是需要设置out为NULL
2. 然后加入需要加密数据, 加入解密数据后, 不能再加入ADD数据

### [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
ChaCha20-Poly1305 类似AES-128-GCM, 也是一种AEAD类型算法, ChaCha20是流式对称加密算法, Poly1305是MAC算法(Message Authentication Code)。
这个算法也加入[IETF协议规范](https://datatracker.ietf.org/doc/html/rfc8439)
1. ChaCha20可以使用128位或者256位的key, 但是在OpenSSL中仅支持256位的key。
2. OpenSSL中ChaCha20算法使用256位key和128位的IV(32bits counter+96bits nonce)。OpenSSL中默认IV是96bits(12bytes), 所以使用ChaCha20时, 需要显式设置下IV长度, 但是ChaCha20-Poly1306使用256bits的key和96bits的IV。
```c
/* https://stackoverflow.com/questions/75007626/openssl-3-not-verifying-using-tag-using-chacha20-poly1305
** https://www.openssl.org/docs/man3.1/man3/EVP_chacha20_poly1305.html
*/
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 16, NULL)
```
3. ChaCha20使用block counter, 并且block count大小是32位, 在256G以内被认为是安全的, 一般网络数据够用, 如果超过可以分开重置参数后在加密

4. python密码库有多个, 比较常用的有[pycryptography](https://cryptography.io/en/latest/), [pycryptodome](https://www.pycryptodome.org/), 其中pycrypto库不再维护了, 作者推荐使用前两个库替换, 其中 `pycryptodome` 的API是兼容的。两者都支持 `ChaCha20`和 `ChaCha20-Poly1305` , 但是前者不兼容RFC 8439, 后者兼容, 但是不支持自定义counter。其中的代码解释见[chacha20_poly1305.py](./quic/chacha20_poly1305.py) 和 [chacha20.c](./quic/chacha20.c) 以及 [chacha20_poly1305.c](./quic/chacha20_poly1305.c) 。

## 2024-02-29
### pigz
1. pigz获取原始DELFATE算法数据
```shell
pigz -k -z -c -f raw.txt | xxd -ps | tail --bytes=+5 | head --bytes=-9
```
**BASH中凡是字符跟字节关系的, 想到hexdump, xxd或者od**

2. 在[zlib.c](./zlib/zlib.c)使用deflateInit2代替deflateInit, 设置`windowBits`参数为负数可以输出原始DEFLATE算法的数据

## 2024-02-26
### [zlib](https://www.zlib.net/)
1. zlib是什么
zlib库提供内存压缩和解压缩功能, 包括未压缩数据的完整性检查。

2. 概念
- [`Deflate`（通常按早期计算机编程习惯写为`DEFLATE`）是同时使用了`LZ77`算法与哈夫曼编码(`Huffman Coding`)的一个无损数据压缩算法](https://zh.wikipedia.org/wiki/Deflate), 已经标准化参考[RFC 1951](https://datatracker.ietf.org/doc/html/rfc1951)。
- `zlib` 可以被认为是一种 `DEFALTE` 算法的封装格式, 标准化参考 [RFC 1950](https://datatracker.ietf.org/doc/html/rfc1950). 目前`zlib`库只支持`DEFLATE`算法, `zlib`已经成为了事实上的业界标准, 标准文档中, `zlib`和`DEFLATE`常常互换使用, 比如常见的`http`协议压缩格式就使用`deflate`代表`zlib`封装格式(`Content-Encoding: defalte`)。
- `gzip` 也可以认为是一种`DEFLATE`算法的封装格式, 标准化参考[RFC 1952](https://datatracker.ietf.org/doc/html/rfc1952), 由于`gzip`仅用来压缩单个文件, 多个文件的压缩归档先合并成tar包, 然后再使用gzip进行压缩, 最后生成`.tar.gz`文件(`tarball`或者tar压缩包)。`gunzip`是解压缩gzip包命令. 其中 `g` 表示`graits`(免费)的意思; gzip也是http协议内容压缩的选项之一。
- `zip`格式, 也使用DEFLATE算法, 相对于gzip来说, 可以包容多个文件, 但是zip是对每个文件单独压缩, 没有利用文件间的冗余信息, 压缩率会稍逊于tar压缩包。

3. 各种语言的实现
下面以 `hello,world!\n` 为数据看下各个版本的实现。
```shell
# 原始DEFLATE算法压缩数据
# cb48cdc9c9d729cf2fca4951e40200
# zlib或者defalte格式数据
# 789c cb48cdc9c9d729cf2fca4951e40200 23710494
# 789c 表示认为是zlib或者deflate格式的magic number; 23710494是原始数据的adler32校验数据
# gzip一般使用10字节的头部, 尾部由4字节的CRC校验和4字节原始数据大小组成, 不同语言的头部字段有可能不一样, 比如日期可以是0等
# 1f8b08000867dd6502ff cb48cdc9c9d729cf2fca4951e40200 fbba78560d000000
# 1f8b08可以认为是gzip的magic number; 00 表示flags, 没有任何附加字段; 0867dd65当前时间戳, 如果是文件可能是修改的时间戳; 
# 02 DEFLATE算法使用的算法等级(最慢的, 04表示最快); ff 表示OS代码(unknown, 03表示unix)
# 后缀fbba7856表示原始数据的CRC校验码; d000000表示原始数据的长度(13)
```
```python
import zlib, gzip, datetime
raw_data = b"hello,world!\n"
# 注意二进制数据的大小端
hex(zlib.crc32(raw_data))
# fbba7856 
hex(zlib.adler32(raw_data))
# 23710494
"".join([ f"{i:02x}" for i in zlib.compress(raw_data) ])
# 789ccb48cdc9c9d729cf2fca4951e4020023710494
"".join([ f"{i:02x}" for i in gzip.compress(raw_data) ])
# 1f8b08000867dd6502ffcb48cdc9c9d729cf2fca4951e40200fbba78560d000000
int.from_bytes(b'\x86\x7d\xd6\x50', byteorder="little")
# 1709008648
datetime.datetime.fromtimestamp(1709008648)
```

C语言参考[zlib.c](./zlib/zlib.c)文件和pigz命令
```shell
# https://www.zlib.net/zpipe.c
# install zlib
gcc -Wall -Wextra -pedantic -o zlib zlib.c $(pkg-config --libs zlib)
./zlib <<< $'hello,world!' > compressed.bin
./zlib -d < compressed.bin
# OR
pigz -d < compressed.bin
xxd -ps compress.bin
# zlib或者defalte格式压缩数据
# 789ccb48cdc9c9d729cf2fca4951e4020023710494

# 在zlib.c使用deflateInit2代替deflateInit, 可以输出原始DEFLATE算法的数据
```

JS语言参考[zlib.js](./zlib/zlib.js)文件
```js
// 注释一部分是根据文件生成gzip文件, 可以查看raw.txt.gz的内容查看
xxd -ps raw.txt.gz

// 1f8b0800000000000003cb48cdc9c9d729cf2fca4951e40200fbba78560d000000
// 现有部分为http server, 主要是验证Content-Encoding, 运行后使用chrome请求和wireshark查看
echo 'hello,world!' > raw.txt 
tshark -i lo -w zlib.pcapng 'tcp and port 1337 
curl -H 'Accept-Encoding: deflate' --compressed localhost:1337
tshark -r zlib.pcapng -Px -Y 'http'

// Content-Encoding: defalte 格式头部和数据是分开的, 以下是Transfer-Encoding: chunked的数据
32 0d 0a (表示长度, 后面数据是2个字节)
78 9c 0d 0a (deflate头部, 789c)
31 33 0d 0a (压缩数据长度, 13个字节)
cb 48 cd c9 c9 d7 29 cf 2f ca 49 51 e4 02 00 23 71 04 94 (压缩数据, 包括后面4个字节的adler32校验数据)
30 0d 0a 0d 0a (0的ASCII值, chunked数据结束)
```

### zlib格式标准 [RFC 1950](https://datatracker.ietf.org/doc/html/rfc1950)
通常两个字节头部(可以存在扩展字段)和四个字节adler32原始数据校验值
1. 两个字节头部：[CMF, FLG](https://stackoverflow.com/questions/9050260/what-does-a-zlib-header-look-like)
```
# 常用值
78 01 - No Compression/low
78 5E - Fast Compression
78 9C - Default Compression
78 DA - Best Compression

CMF
bits 0 to 3  CM     Compression method, 8代表DEFLATE算法
bits 4 to 7  CINFO  Compression info, 7代表32k window size
FLG
bits 0 to 4  FCHECK  (check bits for CMF and FLG), 保证2个头部字节是31的倍数, (CMF*256 + FLG)/31
bit  5       FDICT   (preset dictionary), 0
bits 6 to 7  FLEVEL  (compression level), 2代表default compression algorithm
```

### gzip格式标准 [RFC 1952](https://datatracker.ietf.org/doc/html/rfc1952)
通常十个字节头部和八个字节尾部, 包括四字节CRC32原始数据校验值和四字节原始数据长度
1. 十字节头部
```
ID1|ID2|CM |FLG|     MTIME     |XFL|OS 
ID1(0x1f), ID2(0x8b) 为gzip的magic number, 标识为gzip格式
CM Compress Method, 8代表DEFLATE
FLG, 不描述, 见文档
     bit 0   FTEXT
     bit 1   FHCRC
     bit 2   FEXTRA
     bit 3   FNAME
     bit 4   FCOMMENT
     bit 5   reserved
     bit 6   reserved
     bit 7   reserved
MTIME The most recent Modification Time of original file, 如果是字节流, 则为当前时间戳
XFL eXtra Flags, 2为最大压缩, 4为最快速度
OS Operation System, 3为Unix, 255为unknown
```

## 2024-02-22
### C中隐藏内部结构
header文件中声明对外结构, 实际声明在C文件中, 如果要获取结构中内容, 提供相关的接口, 比如
```c
// connection.h
typedef struct _Connection Connection;
// connection.c
#include <connection.h>
struct _Connection
{
     struct sockaddr_storage remote_addr;
} _Connection;

struct sockaddr_storage *connection_get_remote_addr(Connection *conn)
{
     return &conn->remote_addr;
}

```

## 2024-02-21
### [socket地址以及转化](./sockaddr.c)
```c
// struct sockaddr 用于装载协议地址内容, 比如ipv4等协议, 但是IPv6需要更大, 出现了sockaddr_storage, 以前的接口都是使用struct sockaddr, 现在可以混合使用sockaddr_storage,  然后指定size

#include <sys/socket.h> // AF_INET, AF_INET6
#include <netinet/in.h> // struct sockaddr_in, struct sockaddr_in6
#include <arpa/inet.h> // inet_aton, inet_ntoa, inet_pton, inet_ntop

struct sockaddr_storage addr;
memset(&addr, 0, sizeof(struct sockaddr_storage));
if (isIPv6 == TRUE)
{
    struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)&addr;
    addr_v6->sin6_family = AF_INET6;
    addr_v6->sin6_port = 1234;
    inet_pton(AF_INET6, "2001:3211::1", &(addr_v6->sin6_addr));
}
else
{
    struct sockaddr_in *addr_v4 = (struct sockaddr_in *)&addr;
    addr_v4->sin_family = AF_INET;
    addr_v4->sin_port = 1234;
    inet_aton("192.168.1.228", &(addr_v4->sin_addr));
}
 // 注意这里的addr和后面的size
sendto(sock, buf, len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_storage));
```

## 2024-02-20
### [quic-echo](./ngtcp2/echo), 使用ngtcp2实现server echo client发送的信息, 依赖tmux, 详情见[Makefile](./ngtcp2/echo/Makefile)

### [Understand Dynamic Loading](https://amir.rachum.com/shared-libraries/)

### [quictls](https://github.com/quictls/openssl)编译运行问题
环境: Ubuntu 22.04.4 LTS, gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0<br>  
[编译quictls](https://curl.se/docs/http3.html)后, quictls默认的openssl命令位于`/usr/local/bin/openssl`, 默认安装的openssl位于`/usr/bin/openssl`, 环境变量PATH中也是按照这个目录顺序, 所以如果键入`openssl version`, 使用的是quictls版本的`openssl`命令, 这时会报错:<br>
```openssl: error while loading shared libraries: libssl.so.81.3: cannot open shared object file: No such file or directory```<br>
问题原因是openssl在运行时找不到依赖的动态库, 使用`ldd`命令可以看下哪些依赖库没有找到:<br>
```shell
ldd $(which openssl)
     linux-vdso.so.1 (0x00007fff7****000)
     libssl.so.81.3 => not found
     libcrypto.so.81.3 => not found
     libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb650****00)
     /lib64/ld-linux-x86-64.so.2 (0x00007fb65****000)

```
可以看到`libssl.so.81.3`和`libcrypto.so.81.3`找不到, 官方OpenSSL的动态库是`libssl.so.3`和`libcrypto.so.3`, 位于`/usr/lib/x86_64-linux-gnu`, 前者中 **81** 是 **Q** 的ASCII码值, 以示区分:<br>
```shell
ls -l /usr/lib/x86_64-linux-gnu | grep -E 'libssl|libcrypto'
     -rw-r--r--  1 root root   9098630  2月  1 02:43 libcrypto.a
     lrwxrwxrwx  1 root root        14  2月  1 02:43 libcrypto.so -> libcrypto.so.3
     -rw-r--r--  1 root root   4451632  2月  1 02:43 libcrypto.so.3
     -rw-r--r--  1 root root    418464  2月 17  2023 libssl3.so
     -rw-r--r--  1 root root   1231268  2月  1 02:43 libssl.a
     lrwxrwxrwx  1 root root        11  2月  1 02:43 libssl.so -> libssl.so.3
     -rw-r--r--  1 root root    667864  2月  1 02:43 libssl.so.3
```
通过阅读[ld.so的manpage文档](https://man7.org/linux/man-pages/man8/ld.so.8.html), 如果共享库没有包含slash, 按照以下的顺序寻找, 下面是原文:<br>
```
If a shared object dependency does not contain a slash, then it is searched for in the following order:
(1)  Using the directories specified in the DT_RPATH dynamic section attribute of the binary if present and DT_RUNPATH attribute does not exist.  Use of DT_RPATH is deprecated.

(2)  Using the environment variable LD_LIBRARY_PATH, unless the executable is being run in secure-execution mode (see below), in which case this variable is ignored.

(3)  Using the directories specified in the DT_RUNPATH dynamic section attribute of the binary if present.  Such directories are searched only to find those objects required by DT_NEEDED (direct dependencies) entries and do not apply to those objects' children, which must themselves have their own DT_RUNPATH entries.  This is unlike DT_RPATH, which is applied to searches for all children in the dependency tree.

(4)  From the cache file /etc/ld.so.cache, which contains a compiled list of candidate shared objects previously found in the augmented library path.  If, however, the binary was linked with the -z nodefaultlib linker option, shared objects in the default paths are skipped.  Shared objects installed in hardware capability directories (see below) are preferred to other shared objects.

(5)  In the default path /lib, and then /usr/lib.  (On some 64-bit architectures, the default paths for 64-bit shared objects are /lib64, and then /usr/lib64.)  If the binary was linked with the -z nodefaultlib linker option, this step is skipped.
```
1. 设置ELF文件的DT_RPATH, 上面文档指出这个参数过时了, 但是依然很多在使用。编译时指定GCC的相关参数, 比如`-Wl,-rpath=/usr/local/lib64`, 默认情况下文档说是设置`DT_RPATH`,
```
man 1 ld
...
--enable-new-dtags
--disable-new-dtags
     This linker can create the new dynamic tags in ELF. But the older ELF systems may not understand them. If you specify --enable-new-dtags, the new dynamic tags will be created as needed and
     older dynamic tags will be omitted.  If you specify --disable-new-dtags, no new dynamic tags will be created. By default, the new dynamic tags are not created. Note that those options are only
     available for ELF systems.
...
```
 但是在我机器 `Ubuntu22.04, GCC11.04` 验证是默认设置的`DT_RUNPATH`, 如果要设置`DT_RPATH`, 可以显式设置关闭开关`-Wl,--disable-new-dtags`, 编译完成后可以使用如下命令检验: <br>
```shell
readelf -d build/client | grep -E 'RUNPATH|RPATH'
```
2. 可以设置`LD_LIBRARY_PATH`, 比如`LD_LIBRARY_PATH="/usr/local/lib64" openssl version`也能正确运行
3. 设置DT_RUNPATH, 方法同1, 但是需要她的使用顺序以及她只应用与DT_NEEDED的依赖库, 他们的子依赖不会使用这个参数指定的地址, 这也是争议的地方, DT_RPATH说是过时了, 而且存在安全争议, 但是在检索第一位管用
4. /etc/ld.so.cache本地缓存, 这个需要在机器上自己设置, 一般在目录 `/etc/ld.so.conf.d/` 添加配置文件, 然后刷新缓存: <br>
```shell
echo "/usr/local/lib64" | sudo tee /etc/ld.so.conf.d/quictls.conf # 添加配置文件
sudo ldconfig # 刷新 ld.so.cache
openssl version # 现在能正常执行
# OpenSSL 3.1.4+quic 24 Oct 2023 (Library: OpenSSL 3.1.4+quic 24 Oct 2023)
```
上面是检索顺序也是解决前面问题的方法。下面根据QUIC-ECHO工程依赖quictls的例子解释下GCC编译参数, 具体可以参见相关的 [Makefile](./ngtcp2/echo/Makefile) :<br>
```shell
gcc -g -Wall -Wextra -DDEBUG -pedantic -Wl,-rpath=/usr/local/lib64  -o build/client client.c connection.c quictls.c stream.c utils.c  \
        -L/usr/local/lib64  \ # 影响后面的-lssl -lcrypto, 使她们使用quictls而不是openssl的共享库
        -lssl -lcrypto \ # libssl.so.81.3 libcrypto.so.81.3
        -lngtcp2 -lngtcp2_crypto_quictls
```
**\[TIPS]**: ld 默认搜索的动态库路径可以通过如下途径查看:<br>
```shell
ld --verbose | grep SEARCH_DIR | tr -s ' ;' '\n'
# OR
ldconfig -v 2>/dev/null | grep '^/'
```

## 2024-02-02
1. aioquic中的数据重传是通过recover中的_on_packets_lost函数调用packet.delivery_handlers(QuicDeliveryState.LOST, *args), 然后在stream.py和其他文件中都有相应的handles判断不是QuicDeliveryState.ACKED的操作, 重新放入缓冲, 下次发送的时候就会重新发送
2. [Congestion Control and Flow Control](https://ggn.dronacharya.info/Mtech_CSE/Downloads/QuestionBank/ISem/Data_Communication_Computer_Networks/section-3/lect1.pdf)
- Congestion control is a global issue – involves every router and host within the subnet
- Flow control – scope is point-to-point; involves just sender and receiver.

## 2024-02-01
### signalfd and pidfd
https://unixism.net/2021/02/making-signals-less-painful-under-linux
signalfd主要是将信号转化为文件描述符fd, 可以使用类似epoll接口监听
同样, pidfd可以将pid跟文件描述符fd关联, 如果process退出, fd会收到可读信号, 可以避免进程结束后, 新进程使用旧的进程号导致的问题

### openSSL error handling
Demystifying-Cryptography-with-OpenSSL-3.0 page 111

## 2024-01-23
### 编译ngtcp2, curl
如果运行时发现链接库有问题, 首先使用`ldd file`查看哪些共享库链接找不到
GCC编译使用外部的共享库, 有两种情况需要考虑, 但是都可以通过`-L`指定路径解决, 比如 `-L/usr/local/lib64 -lssl -lcrypto`, 明确说明`libssl`和`libcrypto`在`/usr/local/lib64`搜索。
1. 不在默认的搜索路径(可以通过如下查找默认路径)
```shell
ld --verbose | grep SEARCH_DIR | tr -s ' ;' '\n'
# OR
ldconfig -v 2>/dev/null | grep '^/'
```
2. 存在两个一样的共享库, 需要解决冲突, 明确指定引用的库路径
运行时, 如果共享库找不到, 很可能编译时路径能找到共享库, 但是运行时找不到, 将路径添加到 `LD_LIBRARY_PATH`, 或者在编译时设置连接器参数 `-Wl,rpath=/usr/local/lib64` 设置elf文件的[`DT_RPATH`或者`DT_RUNPATH`](https://en.wikipedia.org/wiki/Rpath)。

### pkg-config
`pkg-config`跟`ld`不一样, 前者用于给出编译时的链接参数, 有时候使用编译工具时很方便给出`libs`和`includes`。quictls编译后生成的共享库有`libssl.so.81.3`, 其中 **81** 为 **Q** 的ASCII码值, 用于区别官方openssl的共享库。
```shell
pkg-config --variable=pc_path pkg-config | tr ':' '\n' # pkg-config默认搜索路径, PKG_CONFIG_PATH对这个路径没有影响

PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig pkg-config --libs libssl # 先检索PKG_CONFIG_PATH, 如果检索不到, 在检索默认路径
# -L/usr/local/lib64 -lssl

pkg-config --libs libssl
# -lssl

# openssl的共享库地址, pkg-config默认路径中包含 
ls -l /usr/lib/x86_64-linux-gnu | grep -E 'libssl|libcrypto'
# quictls共享库地址
ls -l /usr/local/lib64 | grep -E 'libssl|libcrypto'
```
编译应用时, 默认使用了openssl的共享库(-lssl), 但是也只是报警, 说与所依赖的libssl.so.81.3不一致, 运行时就会报错库冲突了。
gcc编译时手动指定-L, 并且在运行时指定rpath(可以通过readelf查看), 因为运行时寻找共享库也有默认地址, gcc编译时, pkg-config寻找共享库地址

## 2024-01-19
### QUIC中使用的tls1.3不同点
1. tls中处理的是headshake header和payload, 没有原先的record, 取而代之是quic long/short header
2. 传入client initial header中的dcid作为初始key计算, 后面tls层计算除各种加解密的对称密钥封装

### Ubuntu中history多个ssh终端无法共享
```shell
# Avoid duplicates
HISTSIZE=1000
HISTFILESIZE=1000
HISTCONTROL="ignoreboth:erasedups"
# When the shell exits, append to the history file instead of overwriting it
shopt -s histappend

# After each command, append to the history file and reread it
PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND$'\n'}history -a; history -c; history -r"
```
## 2023-11-23
### Bash中的set builtin
1. 一般在新建脚本时候, 都会使用set设置shell配置, 比如 `set -eEuo pipefail`, 其中的 `-e` 用于设置发生错误时立即退出脚本。如果有`trap 'cmd' ERR`, 会先执行`cmd`再退出脚本。如果没有`-e`, `cmd`执行后会继续执行后面脚本, 除非`cmd`里面有退出脚本的命令, 比如`exit`。但是有些命令返回不为0也并不意味着发生错误, 因此需要绕过这类, 主要有以下几种方式：
1) 不使用全局set -e, 使用trap方式在handler中控制
2) 局部使用set +e
3) false || echo "failed", 这个不会触发

2. 默认情况下shell functions, command substitutions, and commands executed in a subshell environment这些环境不会继承ERR trap, 使用 set -E开放继承。

```bash
#!/usr/bin/env bash
set -uo pipefail
set -e
set -E

trap 'echo "#$LINENO: $BASH_COMMAND RETURNS $?"' ERR

echo "before false"
false
echo "after false"
```

## 2023-11-21
### Bash中 `[]` 和 `[[]]` 的区别
根本区别是`[]`是命令, 路径位于`/usr/bin/[`, 而`[[]]`只是Bash中的关键字, 这就决定了两者执行的不同。
```bash
type -a [ # [ is a shell builtin\n[ is /usr/bin/[ ...
type -a [[ # [[ is a shell keyword
```
`[ expression ]`在执行的时候, 中间的expression会被解释为函数参数, 因此会被一次性执行各种expansion；但是`[[ expression ]]`是**keyword**, 中间的expression可以根据Bash自己的规则解释, 比如如果expression有多个子expression, 然后执行且、或等操作, 就会先执行第一个, 使用[lazy evaluation](https://lists.gnu.org/archive/html/help-bash/2014-06/msg00013.html)。
```bash
# 如果$3为空, [ $# -gt 3 -a = "-ks" ] 式子不知道怎么解析
[ $# -gt 3 -a $3 = "-ks" ]
```
相信这也是`[]`里面不能使用`&&`的原因, 这样无法解析语句了, 比如
```bash
[ -z $SHELL && -n $PWD ] # 报错, 找不到]
```

### Linux中目录切换技巧
使用pushd和popd, 临时切换目录执行后回到当前目录

### --no-clobber
Linux文档中经常出现`--no-clobber`, 意思是是否要覆盖已存在文件

### Node流跟文件联系
```js
const fs = require('fs')

const ws = fs.createWriteStream('filePath')
ws.write(buffer)
ws.end()
```

## 2023-11-10
### vim命令行执行Ex命令
```bash
vi -E -e -c "1d" -c "wq" -s bootstrap.sh
vi -E -s -u "$HOME/.vimrc" +PlugUpdate +qall
```

## 2023-11-08
### Bash printf
`%q`, 用于生成可以在bash命令中使用的字符串, 比如有些options为`key = value`, 这样去使用肯定有问题, 所以可以格式化下
```bash
printf "%q " "a = b" # a\ =\ b
```

### Bash Alias和原生命令
```bash
command ls
\ls # 转义使用原生命令
shopt -u expand_aliases
type -a ls
```

### [Postgres docker shell file](https://github.com/docker-library/postgres/blob/master/16/bookworm/docker-entrypoint.sh)
1. indirect expansion, `${!var}` 感叹号开头的变量, 要不就是数组的key, 要不就要考虑indirect expansion
```bash
# 比如脚本中file_env中, 使用本地变量indirect expansion获取外边环境变量的值
var=hello var1=var bash -c 'echo ${!var1}' # hello
```
2. 函数内部引用外部变量, 填补了不能返回值的问题
```bash
myvar="hello world"
function ref_test() {
#    declare -n var="$1"
     local -n var="$1"
     var="hello again"
}

echo "$myvar"
ref_test 
echo "$myvar"
```
3. FUNCNAME, BASH_SOURCE  
`FUNCNAME`, 数组, 默认情况函数调用名称, 最下面是`main`, 如果使用source执行文件, 则为`source`, 脚本中判断是否使用source执行函数`is_source`使用此环境变量
```bash
function _is_source() {
     [ "${#FUNCNAME[@]}" -ge 2 ] \
          && [ "${FUNCNAME[0]}" == 'is_source' ] \
          && [ "${FUNCNAME[1]}" == 'source' ]
}
```
`BASH_SOURCE`, 比如嵌套执行文件中, 想正确获取$0, 可以使用此变量, 调用栈的$0, 可以试想下, `./hello.sh`在新进程中执行
```bash
# hello.sh
echo "BASH_SOURCE: $BASH_SOURCE"
echo -n '$0: '
echo "$0"

# test.sh
source hello.sh
# BASH_SOURCE: hello.sh ./test.sh
# $0: ./test.sh
./hello.sh
# BASH_SOURCE: ./hello.sh
# $0: ./hello.sh
```

### Linux setid bit, setgroup bit, sticky bit
可以使用octal表示, 比如setid bit为4***, 比如搜索setid bit设置的文件:
```bash
find /bin/* -perm /4000 -ls
```
其他setgroup bit为2000, sticky bit为1000, 其中000表示user, group, other的permission八进制表示

## 2023-11-02
### Bash debug
1. 使用`trap command DEBUG`
```bash
function _trap_DEBUG() 
{
     echo "# $BASH_COMMAND"
     while read -r -e -p "debug> " _command; do
          if [[ -n _command ]]; then
               eval "$_command"
          else
               break;
          fi
     done
}

trap '_trap_DEBUG' DEBUG
```
2. `set -x` 或者 `bash -x`
3. 类似于 `set -x` 方式, 将信息输出到文件, 主要使用两个builtin变量, `$PS4`和`$BASH_XTARCEFD`
```bash
exec 5<> debug.log
PS4='$LINENO: '
BASH_XTRACEFD='5'
bash -x test.sh
```
4. 检查bash文件是否语法正确, 不执行bash文件, `bash -n bash_script`

### Bash network
Linux中`/dev/[tcp|upd]/host/port`会自动建立网络连接
1. Client
```bash
exec 3<>/dev/tcp/www.google.com/80
echo -e "GET / HTTP/1.1\nHost: www.google.com\n\n" >&3
cat <&3 | head # 默认取了返回的前10行
```

2. Server
```bash
coproc nc -l localhost 3000
while read -r cmd; do
     case $cmd in
     d) date ;;
     q) break ;;
     *) echo 'What?' ;;
     esac
done <&${COPROC[0]} >&${COPROC[1]}

kill ${COPROC_PID} # coproc会自动生成变量NAME_PID
```

## 2023-10-31
### 单词
`disposable product` 一次性产品<br>
`rationale` 基本原理(为什么要这么整), 很多manpage中有这么一段<br>
`displacement` 移动, 位移, 排水量<br>

### [Signal](https://man7.org/linux/man-pages/man7/signal.7.html)
1. Signal dispositions, each signal has a current *disposition*, which determines how the process behaves when it is delivered the signal. for example, "Term", "Ign", "Core" etc, 即信号的默认行为方式。可以通过signal或者sigaction(推荐方式, 从portable方面考虑)更改disposition(fork copy signal disposition after execve(), ignore keeped and other set default disposition)。
2. A child created via fork(2) inherits a copy of its parent's signal dispositions. During an execve(2), the dispositions of handled signals are reset to the default; the dispositions of ignored signals are left unchanged. 这句话注意fork后, exceve前时间signal状态, **另外就是所有忽略的signal直接继承, 不会更改为默认**
3. **SIGKILL(9)**和**SIGSTOP(19)**不能被caught, ignore, block
4. **SIGINT, SIGQUIT**对后台进程无效, because **interrupt from keyboard**
5. [查看进程的所有singal的disposition](https://unix.stackexchange.com/questions/85364/how-can-i-check-what-signals-a-process-is-listening-to)
6. *SIGCHLD* 每当子进程状态发生变化时, kernel会给其父进程发送SIGCHLD消息, 包括子进程stopped, continued, terminated
7. *SIGPIPE* 用于管道或者socket, 写入一个不能读或者读一个不能写入的管道, 一端socket已经意外关闭, 还继续读写等情况触发
8. *SIGALARM* 使用`alarm(seconds)`触发
```bash
cat /proc/pid/status | grep -E 'Sig.+'
```
6. kill, killall
```bash
kill -0 pid # 测试pid是否存在, check existence and permission
kill -l # 1) SIGHUB 2) SIGINT ...
kill -9 pid # send 9(sigkill) to operation system, 不给程序机会捕获机会
kill -2 pid # send SIGINT(Ctrl+C) to 程序
kill %1 # terminate a background job
kill pid # terminate a program using the default SIGTERM(terminate) signal

# killall kill process by name
killall -9 sleep
killall -l # HUB INT QUIT ...
```
7. trap
- SYNOSIS:
```bash
trap -- INT QUIT TERM EXIT # diposition: default 恢复成默认行为
trap "" INT # ignore
trap "echo INT signal caught" INT # caught and execute custom command
```
- `kill -2 pid` VS  `CTRL+C`
CTRL+C会发送SIGINT给所有的*foreground process group*(有terminal的process group), 而前者仅仅发送给相应的pid

8. 程序流程套路
fork,execve,wait, waitpid
sigprocmask, sigaction, sigsuspend
详细参考[例子](./signal.c)

### fork and execve
exec+e覆盖env, 使用传入的环境变量, 使用getenv, putenv, setenv and unsetenv等方法修改
execvep _GNU_SOURCE

## 2023-10-30
### [Bash启动文件(bash startup files)](https://cjting.me/2020/08/16/shell-init-type/)
1. login+interactive/non-interactive, 比如ssh登录等, 也可以设置terminal为登录shell(一般terminal设置中有相应的项去check)
- `/etc/profile`, 一般这个脚本里面会执行`/etc/profile.d/*`里面多有脚本
- *`~/.bash_profile`, `~/.bash_login`, `~/.profile`* 按这个顺寻寻找文件, 只执行最先找到的可执行文件
- 退出时执行`~/.bash_logout`
2. non-login+interactive, 比如使用UI界面中使用terminal, 或者在terminal中使用执行bash命令
- `~/.bashrc`
3. non-login+non-interactive, 比如使用bash命令执行脚本, 比如`bash test.txt`
- 执行`$BASH_ENV`指向的文件

**CAVEATS**
1. bash命令可以使用`-l`, `-i`强迫使用login或者interactive方式执行, 另外还有`--norc`, `--noprofile`, `--init-file`/`--rc-file`(Execute commands from filename (**instead of ~/.bashrc**) in an **interactive shell**.)
2. 判断login或者interactive shell
```bash
# 是否为login shell
shopt login_shell

#是否为interactive shell
case $- in *i*) echo "interactive shell";; *) echo "non-interactive shell";; esac
echo $- # 里面包含i
echo $PS1 # 不为空
```

### xdg-open
根据不同参数使用不同默认打开方式打开, `open`命令指向她

### realpath, readlink, dirname, basename
```bash
# 获取全路径
realpath test.txt # /home/user/test.txt
readlink test.ln # 查看软连接目标
realpath test.txt | xargs dirname # /home/user
realpath test.txt | xargs basename # test.txt
realpath test.txt | xargs basename -s .txt # test 去掉后缀
```

## 2023-10-25
### strace使用
strace trace system calls and signals, [man page](https://man7.org/linux/man-pages/man1/strace.1.html)更有趣<br>
```strace -v -qq -f -e signal=none -e execve,file -p 12345```
```
-v 显示所有参数
-qq 隐藏部分事件, 详细可以使用--quiet=attach,..设置
-f 包含子进程
-e 设置过滤条件
```

### lsof使用, list open files
[man 8 lsof](https://man7.org/linux/man-pages/man8/lsof.8.html) (system administration commands (usually only for root))<br>
```
lsof -a -P -n -R -p $$ -u 0,1,2,3 -i 4tcp@localhost:1234
lsof -c /cr[ao]/ # 支持正则表达式
lsof /run # 查看哪些进程使用/run文件夹

-P 不做端口转换port names, 速度会快点
-n inhibits the conversion of network numbers to host names for network files, 速度会快点
-a 所有条件使用and, 放的位置没有关系
-p 指定process
-u 指定file descriptor
-i 指定网络相关, 格式为 -i [46][tcp|udp][@hostname|hostaddr][:service|port]
-c commands
-R 显示PPID
-U unix socket
-t [file] 返回关联file的process ids, 只输出pid
```

### fcntl使用, [manipulate file descriptor](https://man7.org/linux/man-pages/man2/fcntl.2.html)
获取文件描述符的fd flag(Process级别信息), 就一个close_on_exec, 对应参数F_GETFD, FD_CLOEXEC
```
flags = fcntl(fd, F_GETFD)
flags & FD_CLOEXEC
flags |= FD_CLOEXEC
fcntl(fd, F_SETFD, flags)
```
获取OFD(Open File Descriptor)中的文件状态, offset等, 使用F_GETFL, 
```
flags = fcntl(fd, F_GETFL)
access_mode = flags & O_ACCMODE
O_RDONLY  00
O_WRONLY  01
O_RDWR    10
O_ACCMODE 11
readable: access_mode == O_RDONLY || access_mode == O_RDWR
```
还可以设置nonblocking, dup, file lock等操作

### [flock](https://man7.org/linux/man-pages/man1/flock.1.html), manage locks from shell scripts
1. advisory locks vs mandatory locks
- advisory locks开发者自己去操作锁, 如果不操作锁, 也可以去读写文档, 但是会出现信息错乱问题。
- mandatory locks是操作系统级别的锁, 读写都会检查是否有锁, 性能上肯定有折扣

2. lslocks 查看有哪些锁

### 重温链接
- 硬链接 同一个inode点, inode信息的引用+1, 互相不影响
- 软连接 不同的inode节点, 内容指向原始路径
```bash
ln -s test.txt test.ln
ln test.txt test.hard
readlink ./test.ln # test.txt路径
ls -i -l test.*
stat test.txt
```

### 自动make
```bash
sudo apt install inotify-tools
while inotifywait -q -e modify ./fd.c; do echo -e '\n'; make; done
```

## 2023-10-17
### [Bash](https://www.gnu.org/software/bash/manual/bash.html#Basic-Shell-Features)
[bash学习文档](bash.md)<br>
[bash子进程解惑](https://juejin.cn/post/7293783188233027596)<br>
[bash重定向和文件描述符](https://juejin.cn/post/7294284628377419788)<br>

## 2023-10-13
### URI
`scheme(protocol) name/password host port path query fragment`<br>
`https://user:pass@example.com:9090/list?start=3#content`
### Build curl
```shell
./configure --with-openssl --prefix=$HOME/curl
PKG_CONFIG_PATH=$HOME/curl/lib/pkgconfig pkg-config --libs --cflags libcurl
```
### HTML
1. url-encoding 也叫 percent-encoding
2. form tag默认的enctype为application/x-www-form-urlencoded(curl -d), 也可以改为[enctype=multipart/form-data(curl -F)](https://www.w3.org/Protocols/rfc1341/7_2_Multipart.html), application/x-www-form-urlcoded用于简单的key-value传递, 使用 `&` 连接, 比如 `name=james&age=39`；如果有二进制内容需要传递, 可以使用`multipart/form-data`, 报文如下格式:
```
Content-Type: multipart/form-data; boundary=abc

--abc
Content-Disposition: form-data; name="name"

James
--abc
Content-Disposition: form-data; name="age"

39
--abc--
```
**上面内容开始需要在boundary前面加 `--`, 结尾时需要在头尾均加上 `--`**

### Curl command line use
```shell
# only show response header
curl -I http://example.com
# only show request and response header
curl -v -I http://example.com
# show request conent data
curl --trace curl.log -d "name=john" http://example.com
# -d 传输数据默认使用Content-Type: application/x-www-form-urlencoded 如果需要修改type, 可以添加相应的头部, 比如-H "application/json"
curl -d "name=john" -H "application/json" http://example.com 
# -c file 存储cookie到file, -b [data/file] 读取cookie
curl -c cookies -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" https://www.baidu.com
curl -c cookies -b cookies http://www.baidu.com
```
## 2023-10-12
### 查看标准C库头文件的man page, 安装manpage-posix-dev
```shell
sudo apt install manpage-posix-dev
man sys_time.h # sys/time.h
man time.h
```
### glibc之datetime
```c
// sys/time.h
struct timeval {
     time_t tv_sec;        // seconds
     suseconds_t tv_usec; // microseconds
};
int gettimeofday(struct timeval *, void *);

// time.h
time_t now = time(NULL); // time_t seconds from epoch(1970-1-1 00:00:00)
struct tm {
     int tm_sec;  // [0, 60] leap second, 有可能有闰秒
     int tm_min;  // [0, 59]
     int tm_hour; // [0, 23]
     int tm_mday; // day of month[1,31]
     int tm_mon;  // month of year[0, 11]
     int tm_year; // years since 1900
     int tm_wday; //day of week[0-6] sunday=0
     int tm_yday; // day of year [0-365]
     int tm_iddst; // daylight savings flags, 据说linux平台一直为0(没有)(-1不知道, 1使用)
     long int tm_gmtoff; // 距离utc的秒数
};
char *asctime(const struct tm *tm); // Thu Oct 12 14:51:17 2023
struct tm *localtime(const time_t *timep);
struct tm *gmtime(const time_t *timep);

time_t mktime(struct tm *tm);
// 1. 一般使用如下方式获取时区offset
tzset();
time_t now = time(NULL);
local = mktime(localtime(now));
std = mktime(gmtime(now));
diff = std - local;  // offset seconds
// 这个有个前提, 如果使用localtime_r或者gmtime_r需要手动调用tzset()要设置下, 无论什么都可以先调用下
// 2. 还可以通过标准库中全局变量获取, [man tzset](https://man7.org/linux/man-pages/man3/tzset.3.html)
extern long timezone;
extern char *tzname[2];
extern int daylight;
tzset();
printf("The time zone is '%ld's\n", timezone);
printf("The time zone is '%s'\n", *tzname);
printf("The daylight is '%d'\n", daylight);
```

### [Datetime format](https://man7.org/linux/man-pages/man3/strftime.3.html)
1. 文档中提及的[`broken-down time`](https://www.gnu.org/software/libc/manual/html_node/Broken_002ddown-Time.html), 表示将年月日等信息单独出来的二进制, 人类友好可阅读, 使用 `struct tm` 表示; 机器使用[time_t](https://www.gnu.org/software/libc/manual/html_node/Time-Types.html)表示, 表示距离1970-1-1 00:00:00 UTC的秒数
2. ctime操作(transform date and time to broken-down time or ASCII)可以查看[文档](https://man7.org/linux/man-pages/man3/ctime.3.html)
```C
char *asctime(const struct tm *tm);
struct tm * localtime (const time_t *time)
time_t mktime(struct tm *tm);

// 给定tm结构按照format输出到s
size_t strftime(char s[restrict .max], size_t max,
               const char *restrict format,
               const struct tm *restrict tm);

char *strptime(const char *restrict s, const char *restrict format,
               struct tm *restrict tm);
```
其中format转义字符大部分其他语言都遵守这个规则, 比如python, 使用python调试这些更方便
```python
from datetime import datetime
now = datetime.now()
now.strftime("%Y-%m-%e") # 2023-10-11
datetime.strptime("2020-10-11", "%Y-%m-%d") # datetime.datetime(2020, 10, 11, 0, 0)
```
## 2023-10-11
### [locale](https://wiki.archlinuxcn.org/wiki/Locale)
man 5 locale <br>
locate categories: LC_COLLATE, LC_TIME, LC_MESSAGES, LC_NAME, LC_NUMERIC等<br>
locale keys: name_fmt, decimal_point, thousands_seperator等<br>
```shell
locale # 查看所有locale categores和LC_ALL, LANG, LANGUAGE
# locale -k [category|key]
locale -ck decimal_point
locale -k LC_NAME
locale -ck name_fmt
```
1. LC_ALL一般不设置, 用于在命令行中临时设置控制程序行为, 比如用于使用原生C类型排序时, `LC_ALL=C sort file.txt`
2. env环境变量中都是有值的键值对, LC_\*, LANGUAGE, LANG如果没有被设置, env没有相应的变量；尽管使用`locale`命令都会显示出来, 特别是LC_*(LC_ALL除外), 有个规则
如果LC_\*不存在, 则使用LANG的值填充, 这就是为什么命令`locale`结果中LC_\*有的值没有对应环境变量, [如果LANG也没有值, 则值为"POSIX"](https://unix.stackexchange.com/questions/449318/how-does-the-locale-program-work) and [here](https://unix.stackexchange.com/questions/449318/how-does-the-locale-program-work)
```shell
LANG= locale | grep 'POSIX'
```
3. **如果env中不存在值, 那就被设置为局部变量, 比如：假设LC_COLLATE不存在env中, 那就无法被子shell继承, 并且无法对使用该环境变量的命令产生影响**
```shell
env | grep LC_COLLATE # 空 LC_COLLATE不存在
locale | grep LC_COLLCATE # LC_COLLCATE="en_US.UTF-8" 因为LANG="en_US.UTF-8" 
LC_COLLATE="zh_CN.UTF-8" ; locale | grep LC_COLLATE # LC_COLLATE="en_US.UTF-8", 因为LC_COLLATE不存在env中, 设置只是局部变量, 无法影响全局
env | grep LC_COLLATE # 空 LC_COLLATE不存在

env | grep LC_NAME # LC_NAME=en_US.UTF-8
locale | grep LC_NAME # LC_NAME="en_US.UTF-8"
LC_NAME="zh_CN.UTF-8" ; locale | grep LC_NAME # LC_NAME="zh_CN.UTF-8", 因为LC_NAME存在env中, 设置改变了当前shell全局
env | grep LC_NAME # LC_NAME="zh_CN.UTF-8" 当前shell全局变量已经在上一步改变了
```
4. [类型C或者POSIX会使用ascii char set, 都转化成127字节进行操作, 机器可读](https://askubuntu.com/questions/801933/what-does-c-in-lc-all-c-mean) and [here](https://unix.stackexchange.com/questions/87745/what-does-lc-all-c-do), 还有[sort manual中描述](https://man7.org/linux/man-pages/man1/sort.1.html)
```shell
*** WARNING *** The locale specified by the environment affects sort order. Set LC_ALL=C to get the traditional sort order that uses native byte values.
```
### shell中有趣的问题
```shell
A="hello" echo $A # 空
A="hello"; echo $A # hello
# 原因是第一行中因为bash运行前先展开变量, 使用 ; 表示语句分隔符
A="hello" bash -c 'echo $A' # hello 使用单引号, 不会在运行前展开变量, 并且A会临时加入到env环境变量中, 当前语句执行结束会一处, 这个时候bash -c新开进程会继承A环境变量, 只要执行不展开就ok
A="hello" bash -c "echo $A" # 空
A="hello"; bash -c 'echo $A' # 空, bash -c会新建进程执行, 这个时候不会继承A变量, 除非A是全局环境变量

# 假设当前环境变量LC_NAME=zh_CN.UTF-8
LC_NAME=en_US.UTF-8 env | grep LC_NAME # LC_NAME=en_US.UTF-8 设置LC_NAME到当前的环境变量, 不对其他任何环境产生影响
env | grep LC_NAME # LC_NAME=zh_CN.UTF-8
LC_NAME=en_US.UTF-8; env | grep LC_NAME # LC_NAME=en_US.UTF-8 设置当前环境变量LC_NAME, 
env | grep LC_NAME # LC_NAME=en_US.UTF-8
LC_NAME=zh_CN.UTF-8 # 还原
LC_NAME=C && locale | grep 'LC_NAME' # LC_NAME=en_US.UTF-8 效果跟上面一样, 但是意义不同, 首先修改环境变量, 成功后在执行后面语句
```
1. **bash -c会新建进程处理, pipe符号 `|` 也有类似流程**
2. [空格和`;`在定义环境变量中的区别](https://unix.stackexchange.com/questions/36745/when-to-use-a-semi-colon-between-environment-variables-and-a-command)

### 有趣的sort
```shell
# 结果：A/nB/na/n/b/n
echo -e 'a\nb\nA\nB\n' | LC_COLLATE=C sort
# 注意$'str'和$""区别
sort <<< $'a\nb\nA\nB\n' 
# 结果：a/nA/n/b/nB/n
echo -e 'a\nb\nA\nB\n' | LC_COLLATE=en_US.UTF-8 sort
```
1. sort默认根据LC_COLLATE比较, 比如en_US, 根据字符比较, 看起来像不区分大小写字符比较, 但是**C会转化为字节后比较**
2. 其中shell中`<<<`代表[here string](https://www.gnu.org/software/bash/manual/bash.html#Here-Strings), `<<`表示here document<br>
3. [\$'\x31' vs \$"\x31"](https://unix.stackexchange.com/questions/48106/what-does-it-mean-to-have-a-dollarsign-prefixed-string-in-a-script) \$'str'转义字符串, 类似echo -e；$"str"用于根据locale翻译str

## 2023-10-09
### [BRE and ERE](https://www.gnu.org/software/sed/manual/sed.html#BRE-vs-ERE)
Basic and extended regular expressions are two variations on the syntax of the specified pattern. Basic Regular Expression (BRE) syntax is the default in sed (and similarly in grep). Use the POSIX-specified -E option (-r, --regexp-extended) to enable Extended Regular Expression (ERE) syntax.

In GNU sed, the only difference between basic and extended regular expressions is in the behavior of a few special characters: `'?'`, `'+'`, `parentheses('()')`, `braces('{}')`, and `'|'`.

With basic (BRE) syntax, these characters do not have special meaning unless prefixed with a backslash (‘\’); While with extended (ERE) syntax it is reversed: these characters are special unless they are prefixed with backslash (‘\’).

| Desired pattern | Basic (BRE) Syntax | Extended (ERE) Syntax |
| -- | ---- | ---- |
|literal ‘+’ (plus sign)|```$ echo 'a+b=c' > foo```<br>```$ sed -n '/a+b/p' foo a+b=c```| ```$ echo 'a+b=c' > foo```<br>```$ sed -E -n '/a\+b/p' foo a+b=c```|
|One or more ‘a’ characters followed by ‘b’ (plus sign as special meta-character)| ```$ echo aab > foo```<br>```$ sed -n '/a\+b/p' foo aab```|```$ echo aab > foo```<br>```$ sed -E -n '/a+b/p' foo aab```|

### man 1 printf
`printf "%s\n" abode bad bed bit bid byte body` 会将后面的arguments执行7次, 得到结果: `abode\nbad\nbed\nbit\nbid\nbyte\nbody\n`

### [awk redirect](https://www.gnu.org/software/gawk/manual/gawk.html#Redirection)
`netstat -t | awk 'NR != 1 && NR != 2 { print > $6 }'`<br>
这里的 **>** 与shell种的redirect行为不同, 这里是append, 详见上面链接文档
### sed有趣的指令
- [pattern space and hold space](https://www.gnu.org/software/sed/manual/sed.html#advanced-sed)
- n 跳过当前行, 类似awk中的`next`命令
- `N` `pattern_space += '\n' + next_line`
- `l n` 打印pattern space, 可以打印不可见字符, n表示多少字符后换行
```shell
# \u00b7 middle dot
# basic regular expression ? + () {} | 需要转义
# [[:alpha:]] [[:alnum:]] [[:digit:]] [0-9]
(echo "hello";seq 10 | awk 'BEGIN { ORS = "" } { print }';echo -ne "\nwo\u00b7ld123\n") | sed -n '/[[:digit:]]\+$/l 3'
```

## 2023-09-29
### QUIC加解密用到的cid
1. **计算密钥时要用到的cid, 如果没有retry packet的话, 使用client发送initial packet中的destination cid。如果发生retry, 则在下次client initial packet中使用这个scid作为dcid, 并且server和client都以此作为加解密使用的cid。** retry packet中的source cid必须是自己选择的, 不能与前面的client initial packet中的destination cid相同, 这个跟version negotiation不同
2. [version negotiation destination cid和source cid必须跟client initial packet中的source cid和destination cid保持一致](https://github.com/alibaba/xquic/blob/main/docs/translation/rfc9000-transport-zh.md#1721-%E7%89%88%E6%9C%AC%E5%8D%8F%E5%95%86%E5%8C%85version-negotiation-packet)

## 2023-09-27
### [TLS1.3变长字段编码](https://datatracker.ietf.org/doc/html/rfc8446#section-3.4)
在使用HKDF计算时, 其中的label需要按照[文档](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)编码, 很容易错误是对于**变长字段需要添加长度前缀**, 这个在文档的3.4章有提及, 太隐晦○|￣|_
```
HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)

Where HkdfLabel is specified as:

struct {
     uint16 length = Length;
     opaque label<7..255> = "tls13 " + Label;
     opaque context<0..255> = Context;
} HkdfLabel;

Derive-Secret(Secret, Label, Messages) =
     HKDF-Expand-Label(Secret, Label,
                    Transcript-Hash(Messages), Hash.length)
```
其中的label和context属于变长字段(使用<floor..ceiling>指定的vector), 编码时需要添加长度前缀, 例如下面例子
```python
from struct import pack

label = b"tls13 " + b"quic iv"
context = b"\x01\x02\x03\x04\x05\x06"
length = 32

hkdf_label = pack(">H", length) \
          + pack("B", len(label)) + label \
          + pack("B", len(context)) + context
print(hkdf_label)
```

### octet VS octal
- octet: 就是一个字节的意思, 因为byte在某些场景不一定指定8位一组, 有些场景引起混淆的地方就使用octet更严谨, 比如[TLS1.3 RFC](https://datatracker.ietf.org/doc/html/rfc8446)
- octal: 代表八进制

### hexdump, xxd
1. KB and K(KiB)  
hexdump可以使用K或者KiB代表1024字节, KB代表1000字节
2. Format and Color in HEXDUMP
format string格式: `-e 'iterator_count/byte_count "format"'`, 其中iterator_count, byte_count其中只要有一个存在, 那 `/` 是必须的。`format` 必须使用双引号, `format`以`%`开头, 类似`printf`。常见的`format`有:<br>
`_a` 每次开始递归迭代时执行, 比如 `-e '"%08.8_ax"'` <br>
`_A` 所有迭代完成后执行, 一般最后输出所有长度, 比如: `-e '"%08.8_Ax"'` <br>
`_p` 按照当前字符集输出字符, 不能打印使用`.`代替<br>
`_L` 添加颜色<br>
`x`  16进制转化

```shell
# 执行完所有转换添加cyan颜色的地址标识, 然后换行;
# 每次开始递归迭代时添加cyan颜色的起始地址标识, 空格两个
# 每次迭代八次, 每次取两个字节, 如果开头两个字节是0x6f72则使用绿色显示, 否则使用红色, 其他使用默认颜色
# 每次迭代十六次, 使用默认字符集显示对应字节的字符, 并且前后使用 "|" 分割, 最后换行
hexdump -v -e '"%08_Ax_L[cyan]\n"' -e '"%08_ax_L[cyan]  " 8/2 "%04x_L[green:0x6f72@0-1,!red:0x6f72@0-1] " "  |"' -e '16/1 "%_p" "|" "\n"' -n 64 /etc/passwd
# -v 不省略重复字节, 默认会使用 * 省略重复字节
# -e 提供format, 可以有多个, 多个的递归迭代从当前开头开始
# -f 提供format文件
# -n 使用前64个字节
```
3. xxd和hexdump分场景使用, hexdump支持定制, 功能更丰富, 但是简单场景xxd似乎更适合点 :)
```shell
echo -en "tls13 $label" | hexdump -v -e '/1 "%02x"'
echo -en "tls13 $label" | xxd -p
```

### [fprintf format string](https://cplusplus.com/reference/cstdio/fprintf/)
Format String: `%[flags][minimum_field_width][.precision][length_modifier]conversion_specifier`<br>
不想写解释了, 直接看`man 3 printf`, 里面描述的很清晰
```shell
# # 标识添加各进制的前缀, 比如十六进制的0x等
# 0 padding zero
# - left justiment, 默认右对齐
# + 显式显示正负号
# ' 显示thousands separator, BASH的printf支持, GCC版本貌似不支持
flags: [+-0#']

# Minimum Field Width 
标识整个字段的最小宽度, 如果超过, 不会截断

# Precision 
对于d, i, o, u, x, X的conversion specifier, 表示最小出现的数字个数; 而对于a, A, f, F, e, E, 表示小数点后数字个数; 对于g, G, 表示最大有效位数; 对于s, S, 表示最大现实字符个数

# minimum_field_width和precision可以使用后面的argument参数作为值, 使用 '*' 标识, 比如 
int width = 3;
int num = 2;
printf("%*d\n", width, num);
printf("%2$%*1$d\n");
# 打印出 __2
# 以上两种方式一样, 第一种使用*占位一个参数作为minimum_field_width, 第二种更加隐晦, 她使用 '$m$' 格式引用后面的参数, 然后使用这种形式引用第一个参数作为minimum_field_width。

# Length Modifier
A length modifier is used to exactly specify the type of the matching argument.
在printf中一般不使用, 标识被匹配参数的类型或者叫做长度, 比如
printf("%hhd\n", 257)
打印 1, 因为 'hh' 表示后面的参数是一个字节, 最大0xff, 超过就wrap

# Conversion Specifier
d, i, u, x, X, o, O, f, F, e, E, g, G, c, s, % etc

# 当conversion specifier为x时, 有pricision场景, flag 0省略, 所以前面5位空格
printf "%08.3x" 7  -> _____007 
printf "%-08.3x" 7 -> 007_____

flags: 0 表示不足长度8使用0填充
width: 8 表示最长长度为8
precision: 3 使用x时, precision表示最短长度
specifier: x 表示使用16进制表示
```

## 2023-09-14
### [Sock5协议](https://datatracker.ietf.org/doc/html/rfc1928)
1. [支持IPv6 and IPv4 dual stack](https://stackoverflow.com/questions/1618240/how-to-support-both-ipv4-and-ipv6-connections)
The best approach is to create an IPv6 server socket that can also accept IPv4 connections. To do so, create a regular IPv6 socket, turn off the socket option IPV6_V6ONLY, bind it to the "any" address, and start receiving. IPv4 addresses will be presented as IPv6 addresses, in the IPv4-mapped format.  
The major difference across systems is whether IPV6_V6ONLY is a) available, and b) turned on or off by default. It is turned off by default on Linux (i.e. allowing dual-stack sockets without setsockopt), and is turned on on most other systems.  
In addition, the IPv6 stack on Windows XP doesn't support that option. In these cases, you will need to create two separate server sockets, and place them into select or into multiple threads.
```python
addr = (host, port)
if socket.has_dualstack_ipv6():
     s = socket.create_server(addr, family=AF_INET6, dualstack_ipv6=True)
else:
     s = socket.create_server(addr)
server = await loop.create_server(Socks5Protocol, sock=s, ssl=ssl_ctx, reuse_address=True, reuse_port=True)
```
2. CLOSE_WAIT状态连接
```sudo lsof -i:1080```, 原因时被动关闭方(server), 发送完fin, 应用程序没有正确检测socket关闭状态导致, 需要合适的时候关闭socket
3. 解析域名时, 需要判断下客户端是否是域名, 还是IPv4/IPv6, chrome中的某个插件直接将IPv4/6地址当作域名发送
4. wireshark会根据端口显示协议, 比如使用1080端口, 即使不是Socks5协议, 也会显示该Socks协议
5. [IPv6中"::"和"::1"的区别](https://superuser.com/questions/1727006/what-is-the-difference-between-ipv6-addresses-and-1)
::1相当于localhost, ::相当于0.0.0.0

实现的[Socks5 server](./socks5_server.py), 监听1080, client使用chrome的某插件, 配置服务的地址, 如果本地测试udp代理, 使用如下文件和工具:  
- [client](./socks5_client.py), 监听1081
- [udp echo server](./udp_echo_server.py) 监听9000
- 启动nc模拟client发送消息到[Socks5 client](./socks5_client.py)   
```shell
nc -v -4 -t localhost 1081
# hello
# hello
```
发送消息后, 能看到nc收到echo消息, **Scoks5 client代码里面写死了目的地**
## 2023-09-11
### Message Digest
1. Message digest also known as **cryptographic hashes**
2. avalanche(雪崩) effect: any change to the message, big or small, must result in an extensive change to the digest  
3. SHA-2 family, SHA256 is currently the default hash function that's used in the TLS protocol, as well as the default signing function for X.509 and SSH keys.  
### MAC and HMAC(Hash-based Message Authentication Code)
1. MAC_function(message, secret_key)  
2. 相比于Message Digest仅提供完整性(integrity), MAC还提供了不可伪造保护, 因为需要密钥(authenticity). 相对于Digital Signature, 数字签名还提供了不可否认性, 因为使用私钥签名, 私钥只在一个人手中  
### KDF(Key Derivation Function), 代表有PBKDF2, scrypt, HKDF(HMAC-based KDF)等
1. encryption key和password区别
Encryption key用于对称加密算法中, 一般来说, 需要固定长度位数, 可读性差; password则相反
2. KDF takes the following parameters
IKM(Input Key Material), Salt, Info(Application-specific information), PRF(Pseudorandom Function), Function-specific params(interation count or others(scrypt使用参数, N=65535, r=8, p=1)), OKM(Output Key Material) length
### Asymmetric Encryption and Decryption
1. a private key and a public key form a **keypair**
2. Man in the Middle attac(中间人攻击), 提起非对称加密就要提及中间人攻击, 密钥运送问题
3. 非对称加密算法(asymmetric crypto algorithm)有RSA, DSA, ECDSA, DH, ECDH等算法
### Certificates and TLS
```shell
openssl genpkey -algorithm ED448 -out root_keypair.pem
openssl pkey -pubout -in root_keypair.pem -noout -text
openssl req -new -subj "/CN=Root CA" -addext "basicConstraints=critical,CA:TRUE" -key root_keypair.pem -out root_csr.pem
openssl x509 -req -in root_csr.pem -copy_extensions copyall -key root_keypair.pem -days 3650 -out root_cert.pem
openssl genpkey -algorithm ED448 -out intermediate_keypair.pem
openssl req -new -subj "/CN=Root CA" -addext "basicConstraints=critical,CA:TRUE" -key intermediate_keypair.pem -out intermediate_csr.pem
openssl x509 -req -in intermediate_csr.pem -copy_extensions copyall -CA root_cert.pem -CAkey root_keypair.pem -days 3650 -out intermediate_cert.pem
openssl verify -verbose -show_chain -trusted root_cert.pem intermediate_cert.pem
```
## 2023-09-04
```python
# bytes to int
version = b"\x03\x03"
int.from_bytes(version, "big")
# bytes to ascii
raw_data = b"hello"
plain_text = raw_data.decode()
assert plain_text.encode() == raw_data
```
## 2023-08-30
计算handshake相关密钥, 使用的hash包括client hello, server hello, 不包括各自的recored header(5 bytes)
Tls1.3中计算application相关密钥时候, 需要使用header hash, 内容包括client hello, server hello, encrypted extension, Certificate, Certificate Verify, Finished, 假设没有CertificateRequest, 不包括各自的record header(5 bytes)
## 2023-08-29
1. Python和C互相调用, 场景虽然用到不多, 但是考虑性能的代码却要使用, 比如crypto相关的AEAD, head protection代码使用C代码重写  
**需要注意的是, windows和linux平台import时的模块后缀有不同, 网上大多举例windows平台, 在linux平台可能会报模块没找到问题**
```python
# 判断当前平台的支持导入后缀
import importlib
print(importlib.machinery.all_suffixes())
# window: ['.py', '.pyw', '.pyc', '.cp311-win_amd64.pyd', '.pyd']
# linux: ['.py', '.pyc', '.cpython-310-x86_64-linux-gnu.so', '.abi3.so', '.so']
# python导入的路径
import sys
print(sys.path)
```
## 2023-08-28
### python
1. ```bytes.fromhex("0003") -> b'\x00\x03'```
2. ```int.from_bytes(b"\x00\x03", byteorder="big") -> '0x3'```
3. [from contextlib import contextmanager](https://docs.python.org/3/library/contextlib.html)
代码中大量应用, 比如在解析TLS协议时候, 新申请空间, yeild, 最后做些校验或者释放资源
```python
from contextlib import contextmanager

@contextmanager
def managed_resource(*args, **kwds):
    # Code to acquire resource, e.g.:
    resource = acquire_resource(*args, **kwds)
    try:
        yield resource
    finally:
        # Code to release resource, e.g.:
        release_resource(resource)

with managed_resource(timeout=3600) as resource:
    # Resource is released at the end of this block,
    # even if code in the block raises an exception
```
### [tls1.3](https://www.gabriel.urdhr.fr/2022/02/26/tls1.3-intro/)
- TLS1.3有三种握手类型
1. (EC)DHE
2. PSK-only
3. PSK with (EC)DHE
- 各个过程密钥生成过程  
**hello_hash是不含有record header的, 即不包括记录的前5个字节**
```python
# early key生成过程
early_secret = HKDF_Extract(length=32, key=psk, salt=b"\x00")
binder_key = HKDF_Expand(length=32, label="tls13 res binder", hash=SHA256(b""), key=early_secret)
client_early_traffic_secret = HKDF_Expand(lenght=32, label="tls13 c e traffic", hash=client_hello_hash, key=early_secret)
early_exporter_master_secret = HKDF_Exapnd(length=32, label="tls13 e exp master", hash=client_hello_hash, key=early_secret)
# 握手密钥生成过程
shared_secret = X25519.exchange(peer_pub_key, local_private_key)
if resumption_keys:
     early_secret = resumption_keys.early_secret
else:
     early_secret = HKDF_Extract(length=32, key=b"\x00"*32, salt=b"\x00")
derived_secret = HKDF_Exapnd(length=32, label=b"tls13 derived", hash=SHA256(b""), key=early_secret)
handshake_secret = HKDF_Extract(length=32, key=shared_secret, salt=derived_secret)
client_handshake_traffic_secret = HKDF_Expand(length=32, label="tls13 c hs traffic", hash=hello_hash, key=handshake_secret)
server_handshake_traffic_secret = HKDF_Expand(length=32, label="tls13 s hs traffic", hash=hello_hash, key=handshake_secret)
client_handshake_key = HKDF_Expand(length=16, label="tls13 key", hash=b"", key=client_handshake_traffic_secret)
client_handshake_key = HKDF_Expand(length=12, label="tls13 iv", hash=b"", key=client_handshake_traffic_secret)
server_handshake_key = HKDF_Expand(length=16, label="tls13 key", hash=b"", key=server_handshake_traffic_secret)
server_handshake_key = HKDF_Expand(length=12, label="tls13 iv", hash=b"", key=server_handshake_traffic_secret)
# 应用密钥生成过程
derived_secret = HKDF_Expand(length=32, label="tls13 derived", hash=SHA256(b""), key=handshake_secret)
master_secret = HKDF_Extract(length=32, key=b"\x00"*32, salt=derived_secret)
client_application_traffic_secret = HKDF_Expand(length=32, label="tls13 c ap traffic", hash=handshake_hash, key=master_secret)
client_application_key = HKDF_Expand(length=16, label="tsl13 key", hash=b"", key=client_application_traffic_secret)
client_application_iv = HKDF_Expand(length=12, label="tsl13 iv", hash=b"", key=client_application_traffic_secret)
server_application_traffic_secret = HKDF_Expand(length=32, label="tls13 s ap traffic", hash=handshake_hash)
server_application_key = HKDF_Expand(length=16, label="tsl13 key", hash=b"", key=server_application_traffic_secret)
server_application_iv = HKDF_Expand(length=12, label="tsl13 iv", hash=b"", key=server_application_traffic_secret)
```
## 2023-08-25
### 阅读[Demystifying cryptography with OpenSSL 3.0](https://download.bibis.ir/Books/Security/IT-Security/Cryptography/2022/Demystifying-Cryptography-with-OpenSSL-3.0-Discover-the-best-techniques-to-enhance-your-network-security-with-OpenSSL-3.0-(Khlebnikov,-AlexeiAdolfsen,-Jarle)_bibis.ir.pdf)
1. an encryption key is not the same as a password, but an encryption key can be derived from a password
2. It is important to know that when a message is signed, usually, the digital signature algorithm is not applied to the message itself. Instead, the signature algorithm is applied to the message digest, which is produced by some cryptographic hash functions, such as SHA-256. 
3. asymmetric encryption每次最多加密自己的key长度的plain text, 这就是为什么RSA要使用加密session key(symmetric encrpytion)的方式, 说白了, 非对称加密是为了解决对称密钥传送的问题
4. DSA(Digital Signature Algorithm)使用非对加密的private key加密信息的**hash**, private_key_sign(sha(message))
## 2023-08-24
1. long header packet需要加密第一个自己的后4位, short header packet是第一个自己的后5位
```
Initial Packet {
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2) = 0,
     Reserved Bits (2),         # Protected
     Packet Number Length (2),  # Protected
     Version (32),
     DCID Len (8),
     Destination Connection ID (0..160),
     SCID Len (8),
     Source Connection ID (0..160),
     Token Length (i),
     Token (..),
     Length (i),
     Packet Number (8..32),     # Protected
     Protected Payload (0..24), # Skipped Part
     Protected Payload (128),   # Sampled Part
     Protected Payload (..)     # Remainder
}

   1-RTT Packet {
     Header Form (1) = 0,
     Fixed Bit (1) = 1,
     Spin Bit (1),
     Reserved Bits (2),         # Protected
     Key Phase (1),             # Protected
     Packet Number Length (2),  # Protected
     Destination Connection ID (0..160),
     Packet Number (8..32),     # Protected
     Protected Payload (0..24), # Skipped Part
     Protected Payload (128),   # Sampled Part
     Protected Payload (..),    # Remainder
}
```
2. 使用包加密后, 再使用头部加密
3. 头部加密使用头保护密钥和packet payload中的密文采样。因为packet number length是不定的, 最大4 bytes, 采样的起始offset使用4减去实际的packet number length
4. aioquic中header_length是payload之前的内容长度, 截至packet number的尾部, 例如, initial packet中长度是开始至packet number结尾; packet header中的rest length = packet nuber length + paylaod length + 16(AEAD tag)
5. short header packet首字节中第6位表示key phase, 用于提醒对端需要更新密钥, 处理过程详见[此处](./src/aioquic/quic/crypto.py#L82)
6. TLS1.3中, 使用密钥推导算法[HKDF](https://suntus.github.io/2019/05/09/HKDF%E7%AE%97%E6%B3%95/)计算密钥
```python
# protect client initial packet
initial_salt = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
initial_secret = hkdf_extract(initial_salt, cid)
client_initial_secret = hkdf_expand_label(initial_secret, "client in", "", 32)
algorithm = hashes.SHA256()
key = hkdf_expand_label(algorithm, client_initial_secret, "quic key", "", 16)
iv  = hkdf_expand_label(algorithm, client_initial_secret, "quic iv", "", 12)
hp  = hkdf_expand_label(algorithm, client_initial_secret, "quic hp", "", 16)
hp_cipher_name, payload_cipher_name = (b"aes-128-ecb", b"aes-128-gcm")
nonce = iv xor pn
protected_payload = AEAD("aes-128-gcm", key, nonce).update(plain_head).update(plain_payload) # 包括16 bytes tag
sample_offset = MAX_PN_SIZE - pn_size
sample = protected_payload[sample_offset : sample_offset+16]
mask = AEAD("aes-128-ecb", hp).update(sample) # 16 bytes mask
header[0] ^= mask[0] & 0x0f
header[pn_offset..pn_offset+pn_size] ^= mask[1..pn_size]
protected_content = header + protected_payload
```
**Server initial packet protection like client, 需要注意的是cid还是使用client initial packet中的source destination id**, 具体实现参考[代码](./protection.py), 或者[C实现](./protection.c)  

7. [aioquic中receiver支持decode packet number, 但是sender固定packet number length 为2](https://github.com/aiortc/aioquic/issues/200)
8. python中需要注意的两种字节表示
```python
raw = b'1234' # 内存中表示为31323334
hex_str = b'\x01\x02\x03\04' # 内存中表示为01020304

binascii.hexlify(raw) # b'31323334'
binascii.unhexlify(raw) # b'\x124'
binascii.a2b_hex(hex_str) # 01020304

# 首先将raw转化为内存形式0x31323334, 然后取2个字节3132转化为整数
struct.unpack('HH', raw) # (12849, 13363) -> (0x3231, 0x3433)
struct.unpack('HH', hex_str) # (513, 1027) -> (0x201, 0x403)
struct.unpack('>HH', hex_str) # (258, 1027) -> (0x102, 0x304)
```
8. **解密大致跟加密步骤差不多, 有一点需要注意, short packet中有key phase(first_byte & 4), key phase是变更时, header protection remove还是使用原先的密钥(hp), payload解密使用新生成的密钥, 原因是只有拿到里header才能确认key phase是否变更了:)**
9. Openssl command line encryption
```shell
# 使用HKDF算法获取client key
# key(cid): 8394c8f03e515708
# salt: 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
# label(encode('tls client in')): 00200f746c73313320636c69656e7420696e00
openssl kdf -keylen 32 -kdfopt digest:SHA2-256 -kdfopt hexkey:8394c8f03e515708 -kdfopt hexsalt:38762cf7f55934b34d179ae6a4c80cadccbb7f0a -kdfopt hexinfo:00200f746c73313320636c69656e7420696e00 HKDF
# 根据protected payload内容获取sample, 然后使用AES-128-ECB算法获取mask
echo -e -n "\\xd1\\xb1\\xc9\\x8d\\xd7\\x68\\x9f\\xb8\\xec\\x11\\xd2\\x42\\xb1\\x23\\xdc\\x9b" > sample.txt
openssl enc -aes-128-ecb -v -p -e -nosalt -K 9f50449e04a0e810283a1e9933adedd2 -in sample.txt -out sample.aes
```