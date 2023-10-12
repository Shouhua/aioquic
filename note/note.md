## 2023-10-12
### 查看标准C库头文件的man page，安装manpage-posix-dev
```shell
sudo apt install manpage-posix-dev
man sys_time.h # sys/time.h
man time.h
```
### libc datetime
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
     int tm_iddst; // daylight savings flags, 据说linux平台一直为0(没有)(-1不知道，1使用)
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
// 这个有个前提，如果使用localtime_r或者gmtime_r需要手动调用tzset()要设置下, 无论什么都可以先调用下
// 2. 还可以通过标准库中全局变量获取, [man tzset](https://man7.org/linux/man-pages/man3/tzset.3.html)
extern long timezone;
extern char *tzname[2];
extern int daylight;
tzset();
printf("The time zone is '%ld's\n", timezone);
printf("The time zone is '%s'\n", *tzname);
printf("The daylight is '%d'\n", daylight);
```
## 2023-10-11
### [locale](https://wiki.archlinuxcn.org/wiki/Locale)
locate categories: LC_COLLATE, LC_TIME, LC_MESSAGES, LC_NAME<br>
locale keys: name_fmt<br>
```shell
locale # 查看所有locale categores和LC_ALL, LANG, LANGUAGE
# locale -k [category|key]
locale -k LC_NAME
locale -k name_fmt
```
1. LC_ALL一般不设置，用于在命令行中临时设置控制程序行为，比如用于使用原生C类型排序时，`LC_ALL=C sort file.txt`
2. env环境变量中都是有值的键值对，LC_*, LANGUAGE, LANG如果没有被设置，env没有相应的变量；尽管使用`locale`命令都会显示出来，特别是LC_*(LC_ALL除外)，有个规则
如果LC_\*不存在，则使用LANG的值填充，这就是为什么命令`locale`结果中LC_\*有的值没有对应环境变量，[如果LANG也没有值，则值为"POSIX"](https://unix.stackexchange.com/questions/449318/how-does-the-locale-program-work) and [here](https://unix.stackexchange.com/questions/449318/how-does-the-locale-program-work)
```shell
LANG= locale | grep 'POSIX'
```
3. **如果env中不存在值，那就被设置为局部变量，比如：假设LC_COLLATE不存在env中，那就无法被子shell继承，并且无法对使用改环境变量的命令产生影响**
```shell
env | grep LC_COLLATE # 空 LC_COLLATE不存在
locale | grep LC_COLLCATE # LC_COLLCATE="en_US.UTF-8" 因为LANG="en_US.UTF-8" 
LC_COLLATE="zh_CN.UTF-8" ; locale | grep LC_COLLATE # LC_COLLATE="en_US.UTF-8", 因为LC_COLLATE不存在env中，设置只是局部变量，无法影响全局
env | grep LC_COLLATE # 空 LC_COLLATE不存在

env | grep LC_NAME # LC_NAME=en_US.UTF-8
locale | grep LC_NAME # LC_NAME="en_US.UTF-8"
LC_NAME="zh_CN.UTF-8" ; locale | grep LC_NAME # LC_NAME="zh_CN.UTF-8", 因为LC_NAME存在env中，设置改变了当前shell全局
env | grep LC_NAME # LC_NAME="zh_CN.UTF-8" 当前shell全局变量已经在上一步改变了
```
4. [类型C或者POSIX会使用ascii char set, 都转化成127字节进行操作，机器可读](https://askubuntu.com/questions/801933/what-does-c-in-lc-all-c-mean) and [here](https://unix.stackexchange.com/questions/87745/what-does-lc-all-c-do)，还有[sort manual中描述](https://man7.org/linux/man-pages/man1/sort.1.html)
```shell
*** WARNING *** The locale specified by the environment affects sort order. Set LC_ALL=C to get the traditional sort order that uses native byte values.
```
### shell中有趣的问题
```shell
A="hello" echo $A # 空
A="hello"; echo $A # hello
# 原因是第一行中因为bash运行前先展开变量，使用 ; 表示语句分隔符
A="hello" bash -c 'echo $A' # hello 使用单引号，不会在运行前展开变量, 并且A会临时加入到env环境变量中，当前语句执行结束会一处，这个时候bash -c新开进程会继承A环境变量，只要执行不展开就ok
A="hello" bash -c "echo $A" # 空
A="hello"; bash -c 'echo $A' # 空, bash -c会新建进程执行，这个时候不会继承A变量, 除非A是全局环境变量

# 假设当前环境变量LC_NAME=zh_CN.UTF-8
LC_NAME=en_US.UTF-8 env | grep LC_NAME # LC_NAME=en_US.UTF-8 设置LC_NAME到当前的环境变量，不对其他任何环境产生影响
env | grep LC_NAME # LC_NAME=zh_CN.UTF-8
LC_NAME=en_US.UTF-8; env | grep LC_NAME # LC_NAME=en_US.UTF-8 设置当前环境变量LC_NAME, 
env | grep LC_NAME # LC_NAME=en_US.UTF-8
LC_NAME=zh_CN.UTF-8 # 还原
LC_NAME=C && locale | grep 'LC_NAME' # LC_NAME=en_US.UTF-8 效果跟上面一样，但是意义不同，首先修改环境变量，成功后在执行后面语句
```
1. **bash -c会新建进程处理，pipe符号 `|` 也有类似流程**
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
1. sort默认根据LC_COLLATE比较, 比如en_US，根据字符比较，看起来像不区分大小写字符比较，但是**C会转化为字节后比较**
2. 其中shell中`<<<`代表[here string](https://www.gnu.org/software/bash/manual/bash.html#Here-Strings)，`<<`表示here document<br>
3. [\$'\x31' vs \$"\x31"](https://unix.stackexchange.com/questions/48106/what-does-it-mean-to-have-a-dollarsign-prefixed-string-in-a-script) \$'str'转义字符串，类似echo -e；$"str"用于根据locale翻译str

### [datetime fromat](https://man7.org/linux/man-pages/man3/strftime.3.html)
1. 文档中提及的[`broken-down time`](https://www.gnu.org/software/libc/manual/html_node/Broken_002ddown-Time.html), 表示将年月日等信息单独出来的二进制，人类友好可阅读，使用 `struct tm` 表示; 机器使用[time_t](https://www.gnu.org/software/libc/manual/html_node/Time-Types.html)表示，表示距离1970-1-1 00:00:00 UTC的秒数
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
其中format转义字符大部分其他语言都遵守这个规则，比如python，使用python调试这些更方便
```python
from datetime import datetime
now = datetime.now()
now.strftime("%Y-%m-%e") # 2023-10-11
datetime.strptime("2020-10-11", "%Y-%m-%d") # datetime.datetime(2020, 10, 11, 0, 0)
```
## 2023-10-09
### [BRE and ERE](https://www.gnu.org/software/sed/manual/sed.html#BRE-vs-ERE)
Basic and extended regular expressions are two variations on the syntax of the specified pattern. Basic Regular Expression (BRE) syntax is the default in sed (and similarly in grep). Use the POSIX-specified -E option (-r, --regexp-extended) to enable Extended Regular Expression (ERE) syntax.

In GNU sed, the only difference between basic and extended regular expressions is in the behavior of a few special characters: ‘?’, ‘+’, parentheses, braces (‘{}’), and ‘|’.

With basic (BRE) syntax, these characters do not have special meaning unless prefixed with a backslash (‘\’); While with extended (ERE) syntax it is reversed: these characters are special unless they are prefixed with backslash (‘\’).

| Desired pattern | Basic (BRE) Syntax | Extended (ERE) Syntax |
| -- | ---- | ---- |
|literal ‘+’ (plus sign)|```$ echo 'a+b=c' > foo <br/>```<br>```$ sed -n '/a+b/p' foo a+b=c```| ```$ echo 'a+b=c' > foo```<br>```$ sed -E -n '/a\+b/p' foo a+b=c```|
|One or more ‘a’ characters followed by ‘b’ (plus sign as special meta-character)| ```$ echo aab > foo```<br>```$ sed -n '/a\+b/p' foo aab```|```$ echo aab > foo```<br>```$ sed -E -n '/a+b/p' foo aab```|
### man 1 printf
`printf "%s\n" abode bad bed bit bid byte body` 会将后面的arguments执行7次，得到结果: `abode\nbad\nbed\nbit\nbid\nbyte\nbody\n`
### [awk redirect](https://www.gnu.org/software/gawk/manual/gawk.html#Redirection)
`netstat -t | awk 'NR != 1 && NR != 2 { print > $6 }'`<br>
这里的 **>** 与shell种的redirect行为不同，这里是append，详见上面链接文档
### sed有趣的指令
- [pattern space and hold space](https://www.gnu.org/software/sed/manual/sed.html#advanced-sed)
- n 跳过当前行, 类似awk中的`next`命令
- `N` `pattern_space += '\n' + next_line`
- `l n` 打印pattern space，可以打印不可见字符, n表示多少字符后换行
```shell
# | 的优先级(precedence)比 ; 高
# \u00b7 middle dot
# basic regular expression ? + () {} | 需要转移
# [[:alpha:]] [[:alnum:]] [[:digit:]] [0-9]
(echo "hello";seq 10 | awk 'BEGIN { ORS = "" } { print }';echo -ne "\nwo\u00b7ld123\n") | sed -n '/[[:digit:]]\+$/l 3'
```

## 2023-09-29
### quic加解密用到的cid
1. **计算密钥时要用到的cid，如果没有retry packet的话，使用client发送的最初initial packetd中的destination cid。如果发生retry，则在下次client initial packet中使用这个scid作为dcid，并且server和client都以此作为加解密使用的cid。** retry packet中的source cid必须是自己选择的，不能与前面的client initial packet中的destination cid相同，这个跟version negotiation不同
2. [version negotiation destination cid和source cid必须跟client initial packet中的source cid和destination cid保持一致](https://github.com/alibaba/xquic/blob/main/docs/translation/rfc9000-transport-zh.md#1721-%E7%89%88%E6%9C%AC%E5%8D%8F%E5%95%86%E5%8C%85version-negotiation-packet)
## 2023-09-27
### [TLS1.3变长字段编码](https://datatracker.ietf.org/doc/html/rfc8446#section-3.4)
在使用HKDF计算时，其中的label需要按照[文档](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)编码，很容易错误是对于变长字段不添加长度前缀，这个在文档的3.4章有提及，太隐晦○|￣|_
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
- octet: 就是一个字节的意思，因为byte在某些场景不一定指定8位一组，有些场景引起混淆的地方就使用octet更严谨，比如[TLS1.3 RFC](https://datatracker.ietf.org/doc/html/rfc8446)
- octal: 代表八进制
### hexdump, xxd
1. KB and K(KiB)  
hexdump可以使用K或者KiB代表1024字节，K代表1000字节
2. Format and Color in HEXDUMP
```shell
hexdump -e '"%08_Ax_L[cyan]\n"' -e '"%08_ax_L[cyan]  " 8/2 "%04x_L[green:0x6f72@0-1,!red:0x6f72@0-1] " "  |"' -e '16/1 "%_p" "|" "\n"' -n 64 /etc/passwd
```
3. xxd和hexdump分场景使用，hexdump支持定制，功能更丰富，但是简单场景xxd似乎更适合点 :)
```shell
echo -en "tls13 $label" | hexdump -v -e '/1 %02x'
echo -en "tls13 $label" | xxd -p
```
### [fprintf format string](https://cplusplus.com/reference/cstdio/fprintf/)
```
%[flags][width][.precision][length]specifier
flags: + - 0 #(0x, 0前缀)

printf "%08.3x" 7  -> _____007
printf "%-08.3x" 7 -> 007_____

flags: 0 表示不足长度8使用0填充
width: 8 表示最长长度为8
precision: 3 使用x时，precision表示最短长度
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
```sudo lsof -i:1080```, 原因时被动关闭方(server)，发送完fin，应用程序没有正确检测socket关闭状态导致, 需要合适的时候关闭socket
3. 解析域名时，需要判断下客户端是否是域名，还是IPv4/IPv6，chrome中的某个插件直接将IPv4/6地址当作域名发送
4. wireshark会根据端口显示协议，比如使用1080端口，即使不是Socks5协议，也会显示该Socks协议
5. [IPv6中"::"和"::1"的区别](https://superuser.com/questions/1727006/what-is-the-difference-between-ipv6-addresses-and-1)
::1相当于localhost，::相当于0.0.0.0

实现的[Socks5 server](./socks5_server.py), 监听1080, client使用chrome的某插件，配置服务的地址, 如果本地测试udp代理，使用如下文件和工具:  
- [client](./socks5_client.py), 监听1081
- [udp echo server](./udp_echo_server.py) 监听9000
- 启动nc模拟client发送消息到[Socks5 client](./socks5_client.py)   
```shell
nc -v -4 -t localhost 1081
# hello
# hello
```
发送消息后，能看到nc收到echo消息, **Scoks5 client代码里面写死了目的地**
## 2023-09-11
### Message Digest
1. Message digest also known as **cryptographic hashes**
2. avalanche(雪崩) effect: any change to the message, big or small, must result in an extensive change to the digest  
3. SHA-2 family, SHA256 is currently the default hash function that's used in the TLS protocol, as well as the default signing function for X.509 and SSH keys.  
### MAC and HMAC(Hash-based Message Authentication Code)
1. MAC_function(message, secret_key)  
2. 相比于Message Digest仅提供完整性(integrity), MAC还提供了不可伪造保护，因为需要密钥(authenticity). 相对于Digital Signature，数字签名还提供了不可否认性，因为使用私钥签名，私钥只在一个人手中  
### KDF(Key Derivation Function), 代表有PBKDF2, scrypt, HKDF(HMAC-based KDF)等
1. encryption key和password区别
Encryption key用于对称加密算法中，一般来说，需要固定长度位数，可读性差; password则相反
2. KDF takes the following parameters
IKM(Input Key Material), Salt, Info(Application-specific information), PRF(Pseudorandom Function), Function-specific params(interation count or others(scrypt使用参数)), OKM(Output Key Material) length
### Asymmetric Encryption and Decryption
1. a private key and a public key form a **keypair**
2. Man in the Middle attac(中间人攻击)，提起非对称加密就要提及中间人攻击，密钥运送问题
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
计算handshake相关密钥，使用的hash包括client hello, server hello, 不包括各自的recored header(5 bytes)
Tls1.3中计算application相关密钥时候，需要使用header hash，内容包括client hello, server hello, encrypted extension, Certificate, Certificate Verify, Finished, 假设没有CertificateRequest, 不包括各自的record header(5 bytes)
## 2023-08-29
1. Python和C互相调用, 场景虽然用到不多，但是考虑性能的代码却要使用，比如crypto相关的AEAD，head protection代码使用C代码重写  
**需要注意的是，windows和linux平台import时的模块后缀有不同，网上大多举例windows平台，在linux平台可能会报模块没找到问题**
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
代码中大量应用，比如在解析TLS协议时候，新申请空间，yeild，最后做些校验或者释放资源
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
**hello_hash是不含有record header的，即不包括记录的前5个字节**
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
3. asymmetric encryption每次最多加密自己的key长度的plain text，这就是为什么RSA要使用加密session key(symmetric encrpytion)的方式, 说白了，非对称加密是为了解决对称密钥传送的问题
4. DSA(Digital Signature Algorithm)使用非对加密的private key加密信息的**hash**，private_key_sign(sha(message))
## 2023-08-24
1. long header packet需要加密第一个自己的后4位，short header packet是第一个自己的后5位
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
2. 使用包加密后，再使用头部加密
3. 头部加密使用头保护密钥和packet payload中的密文采样。因为packet number length是不定的，最大4 bytes，采样的起始offset使用4减去实际的packet number length
4. aioquic中header_length是payload之前的内容长度, 截至packet number的尾部，例如，initial packet中长度是开始至packet number结尾; packet header中的rest length = packet nuber length + paylaod length + 16(AEAD tag)
5. short header packet首字节中第6位表示key phase，用于提醒对端需要更新密钥, 处理过程详见[此处](./src/aioquic/quic/crypto.py#L82)
6. TLS1.3中，使用密钥推导算法[HKDF](https://suntus.github.io/2019/05/09/HKDF%E7%AE%97%E6%B3%95/)计算密钥
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
**Server initial packet protection like client, 需要注意的是cid还是使用client initial packet中的source destination id**, 具体实现参考[代码](./protection.py)，或者[C实现](./protection.c)  

7. [aioquic中receiver支持decode packet number，但是sender固定packet number length 为2](https://github.com/aiortc/aioquic/issues/200)
8. python中需要注意的两种字节表示
```python
raw = b'1234' # 内存中表示为31323334
hex_str = b'\x01\x02\x03\04' # 内存中表示为01020304

binascii.hexlify(raw) # b'31323334'
binascii.unhexlify(raw) # b'\x124'
binascii.a2b_hex(hex_str) # 01020304

# 首先将raw转化为内存形式0x31323334，然后取2个字节3132转化为整数
struct.unpack('HH', raw) # (12849, 13363) -> (0x3231, 0x3433)
struct.unpack('HH', hex_str) # (513, 1027) -> (0x201, 0x403)
struct.unpack('>HH', hex_str) # (258, 1027) -> (0x102, 0x304)
```
8. **解密大致跟加密步骤差不多，有一点需要注意，short packet中有key phase(first_byte & 4)，key phase是变更时，header protection remove还是使用原先的密钥(hp)，payload解密使用新生成的密钥，原因是只有拿到里header才能确认key phase是否变更了:)**
9. Openssl command line encryption
```shell
# 使用HKDF算法获取client key
# key(cid): 8394c8f03e515708
# salt: 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
# label(encode('tls client in')): 00200f746c73313320636c69656e7420696e00
openssl kdf -keylen 32 -kdfopt digest:SHA2-256 -kdfopt hexkey:8394c8f03e515708 -kdfopt hexsalt:38762cf7f55934b34d179ae6a4c80cadccbb7f0a -kdfopt hexinfo:00200f746c73313320636c69656e7420696e00 HKDF
# 根据protected payload内容获取sample，然后使用AES-128-ECB算法获取mask
echo -e -n "\\xd1\\xb1\\xc9\\x8d\\xd7\\x68\\x9f\\xb8\\xec\\x11\\xd2\\x42\\xb1\\x23\\xdc\\x9b" > sample.txt
openssl enc -aes-128-ecb -v -p -e -nosalt -K 9f50449e04a0e810283a1e9933adedd2 -in sample.txt -out sample.aes
```