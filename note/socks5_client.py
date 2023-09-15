import asyncio, ssl, logging, struct, ipaddress
from asyncio import BaseTransport, Transport, Future, BaseEventLoop
from enum import IntEnum, Enum
from typing import Tuple, cast
from dataclasses import dataclass
from socket import socket, gethostbyname
import signal

host = "0.0.0.0"
port = 1081

server_host = "127.0.0.1"
server_port = 1080
# server_port = 8000

open_ssl = False
proxy_ssl = False

user = "lily"
pwd = "lily123"

VERSION = 0x05
SUB_VERSION = 0x01
RESVERVE = 0x00

class Phase(Enum):
    Handshake = 0
    Auth = 1
    Request = 2
    Application = 3

class AuthMethod(IntEnum):
    NO_AUTH_REQUIRED = 0x00
    USER_PASSWORD = 0x02
    NO_ACCEPTABLE = 0xFF

class Command(IntEnum):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03

class AddrType(IntEnum):
    IPV4 = 0x01
    DOMINNAME = 0x03
    IPV6 = 0x04

@dataclass
class SockAddr():
    """
    用于装载客户端发送过来的地址信息，有IPv4, IPv6, Domain name
    """
    addr_type: AddrType
    data: bytes

    def _check_domain(self, domain: str) -> str:
        try:
            return AddrType.IPV4 if type(ipaddress.ip_address(domain)) is ipaddress.IPv4Address else AddrType.IPV6
        except ValueError:
            return AddrType.DOMINNAME

    @property
    def port(self):
        return int.from_bytes(self.data[-2:], byteorder="big")

    @property
    def ip(self):
        if self.addr_type == AddrType.IPV4:
            return ipaddress.IPv4Address(self.data[0:4])
        elif self.addr_type == AddrType.IPV6:
            return ipaddress.IPv6Address(self.data[0:16])
        elif self.addr_type == AddrType.DOMINNAME: # 除了domain name，还有可能是ip4/6地址
            domain = self.data[1:-2].decode()
            domain_type = self._check_domain(domain)
            if domain_type == AddrType.DOMINNAME:
                # TODO: 支持ipv6
                # try:
                #     logger.info(f"开始解析域名getaddrinfo: {domain}, {self.port}")
                #     sockinfo = getaddrinfo(domain, self.port, AF_INET6, SOCK_STREAM, IPPROTO_TCP)
                #     logger.info(f"解析域名成功getaddrinfo: {domain}, {self.port}, {sockinfo[0][-1][0]}")
                #     return ipaddress.IPv6Address(sockinfo[0][-1][0])
                # except Exception as e:
                #     logger.error(f"解析域名出问题, 尝试使用ipv4(gethostbyname): {e}")
                try:
                    ip = gethostbyname(domain)
                    logger.info(f"解析域名成功: {domain}, {ip}, {self.port}")
                    return ipaddress.IPv4Address(ip)
                except Exception as e:
                    logger.error(f"无法解析域名'{domain}': {e}")
                    raise Exception(f"解析域名出问题: {e}")
            else:
                return ipaddress.IPv4Address(domain) if domain_type == AddrType.IPV4 else ipaddress.IPv6Address(domain)
        else:
            raise Exception(f"不支持的address type: {self.addr_type}")

class Socks5ClientProtocol(asyncio.Protocol):
    phase: Phase = Phase.Handshake

    def connect(self, client: socket):
        client.send(self.handshake()) 
        client.recv(512)
        client.send(self.auth(user, pwd))
        client.recv(512)
        # client.send(self.request(Command.UDP_ASSOCIATE, AddrType.DOMINNAME, "www.google.com", 80))
        # TODO: 解析用户request，填入相应的信息
        client.send(self.request(Command.UDP_ASSOCIATE, AddrType.IPV4, "127.0.0.1", 9000))
        client.recv(512)

    def handshake(self) -> bytes:
        """
        客户端支持user/passworld、无密码模式 
        """
        return b"\x05\x02\x00\x02"
    def auth(self, user_name, password) -> bytes:
        user_len = len(user_name)
        password_len = len(password)
        return b"\x01"+user_len.to_bytes(1, byteorder="big")+user_name.encode()+password_len.to_bytes(1, byteorder="big")+password.encode()
    def request(self, command: Command, atyp: AddrType, addr: str, port: int) -> bytes:
        addr_len = 4
        addr_data = None
        if atyp == AddrType.IPV4:
            addr_data = ipaddress.IPv4Address(addr).packed
        elif atyp == AddrType.IPV6:
            addr_len = 6
            addr_data = ipaddress.IPv6Address(addr).packed
        else:
            addr_len = len(addr)
            addr_data = addr.encode()
        return struct.pack("!BBBBB", VERSION, command, 0, atyp, addr_len) + addr_data + struct.pack("!H", port)
    def check(self, data: bytes):
        if self.phase == Phase.Handshake:
            assert len(data) == 2, "握手阶段返回数据长度必须为2"
            version, selected_method = struct.unpack("!BB", bytes(data[0:2]))
            assert version == VERSION
            if selected_method == AuthMethod.USER_PASSWORD:
                self.phase == Phase.Auth
            else:
                self.phase == Phase.Request
            return (False if selected_method == 0xFF else True, selected_method)
        elif self.phase == Phase.Auth:
            assert len(data) == 2,  "验证阶段返回数据长度必须为2"
            sub_version, state = struct.unpack("!BB", bytes(data[0:2]))
            assert sub_version == SUB_VERSION
            self.phase == Phase.Request
            return (True if state == 0x0 else False, state)
        elif self.phase == Phase.Request:
            version, state, rsv, atyp = struct.unpack("!BBBB", bytes(data[0:4])) 
            assert version == VERSION and rsv == RESVERVE
            self.phase == Phase.Application
            if state != 0x0:
                return (False, state)
            else:
                return (True, SockAddr(addr_type=atyp, data=data[4:]))
        else:
            return (True, "DONE")

class Socks5Client(asyncio.Protocol):
    transport: Transport
    proxy: socket
    socks_ready: Future
    loop: BaseEventLoop
    protocol: Socks5ClientProtocol
    phase: Phase = Phase.Handshake

    def _init_socks5(self, host, port):
        self.protocol = Socks5ClientProtocol()
        sock = socket()
        if proxy_ssl:
            ssl_context = ssl.create_default_context(cafile="ssl_cert_with_chain.pem")
            ssl_context.check_hostname = False
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
            self.proxy = ssl_context.wrap_socket(sock)
        else:
            self.proxy = sock
        
        self.proxy.connect((host, port))
        loop = asyncio.get_running_loop()
        loop.add_reader(self.proxy, self.handle_proxy_data)
        logger.info(f"socket信息是: {self.proxy.getsockname()}")
        self.protocol.connect(self.proxy)

    def _handle_server(self):
        data = self.proxy.recv(512)
        if not data or len(data) == 0:
            self.proxy.close()
            self.transport.close()
        else:
            # state, _ = self.protocol.check(data)
            # if state is not True:
            #     self.proxy.close()
            #     self.transport.close()
            #     self.socks_ready.set_exception(Exception(state))
            #     return
            if self.phase == Phase.Handshake:
                self.proxy.send(self.protocol.auth(user, pwd))
                self.phase = Phase.Auth
            elif self.phase == Phase.Auth:
                self.proxy.send(self.protocol.request(Command.CONNECT, AddrType.DOMINNAME, "www.baidu.com", 443))
                self.phase = Phase.Request
            elif self.phase == Phase.Request:
                self.socks_ready.set_result(True)
                self.phase = Phase.Application
            else:
                self.transport.write(data)

    def connection_made(self, transport: BaseTransport) -> None:
        self.transport = cast(Transport, transport)
        self.loop = asyncio.get_running_loop()
        peer = self.transport.get_extra_info("peername")
        logger.info(f"收到来自{peer}的连接")
        self._init_socks5(server_host, server_port)        
    
    def handle_proxy_data(self):
        res = self.proxy.recv(4096)
        print(f"收到socks5服务器数据: {res.decode()}")

    def data_received(self, data: bytes) -> None:
        """
        客户端到socks5 client -> socks5 server
        """
        if not data or len(data) == 0:
            self.proxy.close()
            self.transport.close()
            logger.info("关闭连接")
        else:
            # self.proxy.send("GET / HTTP/1.1\nHost: www.google.com\n\n".encode())
            self.proxy.send(data)

async def main():
    loop = asyncio.get_running_loop()
    ssl_ctx = None
    if open_ssl:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        # ssl_ctx.load_verify_locations(cafile="server_ca.pem")

    server = await loop.create_server(Socks5Client, host, port, ssl=ssl_ctx)
    print(f"socks5服务器监听: {host}:{port}")
    if open_ssl:
        print(f"开启TLS1.3模式")
    await server.serve_forever()

def handle_signal_int(sig_num, _):
    logger.info(f"CTRL-C({sig_num})退出了")
    exit(-1)

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO
    )
    logger = logging.getLogger('socks5_client')
    signal.signal(signal.SIGINT, handle_signal_int)
    asyncio.run(main())