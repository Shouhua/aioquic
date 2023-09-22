"""
主要实现了Socks5服务端Connect(TCP), UDP代理方式, 支持Sock5 Over TLS1.3
"""

import asyncio
from asyncio import BaseTransport, Protocol
from enum import Enum, IntEnum
import struct
import logging
from ipaddress import ip_address
from dataclasses import dataclass
from typing import Dict, Callable, cast
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, getaddrinfo, gaierror, AddressFamily, SocketKind, has_dualstack_ipv6, create_server, AF_INET6
# from socket import AF_INET6, IPPROTO_IPV6, IPV6_V6ONLY
import ssl
import signal

host = "::"
port = 1080
user = "lily"
pwd = "lily123"
open_ssl = False

logger = logging.getLogger('socks5')

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
class SockWrapper():
    sock: socket = None
    ip: str = None
    port: int = None

    @property
    def adddress(self) -> (str, int):
        if self.ip and self.port:
            return (self.ip, self.port)
        # 支持IPv6, IPv6返回(ip, port, flowid, scopeid), ipv4返回(ip, port)
        sock_info = self.sock.getsockname()
        self.ip = sock_info[0]
        self.port = sock_info[1]
        return (self.ip, self.port)

    @property
    def packed(self) -> bytes:
        i, p = self.adddress
        return  ip_address(i).packed + p.to_bytes(2, byteorder="big")

@dataclass
class SockAddr():
    """
    用于装载客户端发送过来的地址信息，有IPv4, IPv6, Domain name
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
    ATYP 0x01 IPv4 0x03 DOMAINNAME 0x04 IPv6
    """
    data: bytes
    family: AddressFamily = 0
    sock_type: SocketKind = 0

    @property
    def addr_type(self):
        return self.data[0]

    @property
    def port(self):
        return int.from_bytes(self.data[-2:], byteorder="big")

    @property
    def address(self):
        ip = self.data[2:-2]
        try:
            # format: bytes -> IPv4/IPv6/domain string
            if self.addr_type == AddrType.DOMINNAME:
                ip = ip.decode()
            else:
                ip = ip_address(ip).compressed
            sockinfo = getaddrinfo(ip, self.port, self.family, self.sock_type)
            selected_addr = sockinfo[0][-1]
            logger.debug(f"解析域名成功getaddrinfo: {ip} -> {selected_addr}")
            # 如果网络支持IPv6，直接将IPv4的地址转化成IPv6
            # if len(selected_addr) == 2:
            #     return ("::ffff:"+selected_addr[0], selected_addr[1], 0, 0)
            return selected_addr
        except gaierror as e:
            logger.error(f"解析域名getaddrinfo出问题, domain: {ip}, errno: {e.errno}, strerror: {e.strerror}")
            raise e
        except Exception as e:
            logger.error(f"解析域名出问题: {e}")
            raise e
    
    def __str__(self) -> str:
        return f"{self.address}"

class Socks5Protocol(Protocol):
    auth_method: AuthMethod
    target: SockAddr
    handlers: Dict[Phase, Callable]
    command: Command
    proxy: socket = None
    proxy_wrapper: SockWrapper
    phase: Phase = Phase.Handshake

    def __init__(self) -> None:
        self.handlers = {
            Phase.Handshake: self._handle_handshake,
            Phase.Auth: self._handle_auth,
            Phase.Request: self._handle_request,
            Phase.Application: self._handle_application_to_server
        }
        super().__init__()

    def connection_made(self, transport: BaseTransport) -> None:
        self.transport = cast(asyncio.Transport, transport)
        peer = self.transport.get_extra_info("peername")
        logger.info(f"收到来自{peer}的连接")

    def data_received(self, data: bytes) -> None:
        handler = self.handlers[self.phase]
        handler(data)

    def _handle_handshake(self, data):
        """
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
        """
        assert len(data) < 257 and len(data) > 2
        version, nmethods = struct.unpack("!BB", bytes(data[0:2]))
        assert version == VERSION and nmethods > 0
        auth_methods = data[2:] 
        assert len(auth_methods) == nmethods
        if AuthMethod.USER_PASSWORD in auth_methods:
            self.auth_method = AuthMethod.USER_PASSWORD
            self.phase = Phase.Auth
        elif AuthMethod.NO_AUTH_REQUIRED in auth_methods:
            self.auth_method = AuthMethod.NO_AUTH_REQUIRED
            self.phase = Phase.Request
        else:
            logger.warning(f"没有支持的验证方式: {auth_methods}")
            self.transport.write(b"\x05\xFF")
            self.transport.close()
            return
        self.transport.write(struct.pack("!BB", VERSION, self.auth_method))

    def _handle_auth(self, data):
        """
        使用user/password方式验证
        """
        assert len(data) > 2
        sub_version, username_len = struct.unpack("!BB", bytes(data[0:2]))
        assert sub_version == SUB_VERSION
        username = data[2 : 2 + username_len].decode()
        password_len, = struct.unpack("!B", data[2 + username_len: 3 + username_len])
        password_off = 3 + username_len
        password_end_off = 3 + username_len + password_len
        password = data[password_off : password_end_off].decode()
        logger.debug(f"校验信息: {username}, {password}")
        if username == user and password == pwd:
            self.transport.write(b"\x01\x00")
            self.phase = Phase.Request
        else:
            logger.warning(f"验证失败: {username}")
            self.transport.write(b"\x01\x01")
            self.transport.close()

    def _handle_request(self, data):
        """
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        """
        assert len(data) > 4, "request阶段需要更多数据"
        version, command, rsv = struct.unpack("!BBB", bytes(data[0:3])) 
        self.command = command
        assert version == VERSION and rsv == RESVERVE
        self.target = SockAddr(data[3:])
        if self.command == Command.CONNECT or self.command == Command.UDP_ASSOCIATE:
            sock_type = (SOCK_STREAM, "TCP") if self.command == Command.CONNECT else (SOCK_DGRAM, "UDP")
            try:
                # self.proxy = socket(AF_INET6, sock_type[0])
                # self.proxy.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
                self.proxy = socket(AF_INET, sock_type[0])
                logger.debug(f"成功使用{sock_type[1]}模式新建socket，目标服务器地址: {self.target.address}")
            except gaierror as e:
                logger.error(f"解析出抛出问题了: {e}")
                self.proxy.close()
                self.transport.write(b"\x05\x08\x00\x01" + b"\x00"*6)
                self.transport.close()
                return
            except Exception as e:
                logger.error(f"新建proxy sockes发生错误: {e}")
                self.transport.write(b"\x05\x01\x00\x01" + b"\x00"*6)
                self.transport.close()
                return
            
            try:
                if sock_type[0] == SOCK_STREAM:
                    logger.debug(f"开始connect目的地{self.target.address}")
                    self.proxy.connect(self.target.address)
                    self.proxy_wrapper = SockWrapper(sock=self.proxy)
                    logger.debug(f"connect成功，本地地址为: {self.proxy_wrapper.adddress} <-> {self.target.address}")
                else: # UDP返回解析后的地址填充 BND.ADDR | BND.PORT
                    self.proxy_wrapper = SockWrapper(ip = self.target.address[0], port= self.target.address[1])
            except Exception as e: 
                logger.error(f"proxy sockes连接target{self.target.address}发生错误: {e}")
                self.transport.write(b"\x05\x03\x00\x01" + b"\x00"*6)
                self.proxy.close()
                self.transport.close()
                return
        else:
            logger.error(f"不支持的方法: {self.command}")
            self.transport.write(b"\x05\x07\x00\x01" + b"\x00"*6)
            self.transport.close()
            return

        loop = asyncio.get_running_loop()
        loop.add_reader(self.proxy, self._handle_application_from_target)           

        logger.debug(f"request返回的ip地址(BND.ADDR, BND.PORT)为: {self.proxy_wrapper.adddress}")
        self.transport.write(b"\x05\x00\x00\x01" + self.proxy_wrapper.packed)
        self.phase = Phase.Application

    def _handle_application_from_target(self):
        """
        处理从target来的数据，需要copy到client 
        """
        try:
            data = self.proxy.recv(4096)
            if not data or len(data) == 0:
                logger.debug("对方关闭socket，关闭proxy socket")
                loop = asyncio.get_running_loop()
                loop.remove_reader(self.proxy)
                self.proxy.close()
                self.transport.close()
                return
            logger.debug(f"收到target数据{len(data)}")
            self.transport.write(data)
        except Exception as e:
            logger.error(f"获取target数据时发生错误: {e}")
            self.proxy.close()
            self.transport.close()

    def _handle_application_to_server(self, data):
        """
        处理来自client的数据，直接copy到target
        """
        try:
            if self.command == Command.CONNECT:
                count = self.proxy.send(data)
            elif self.command == Command.UDP_ASSOCIATE:
                count = self.proxy.sendto(data, self.target.address) 
            else:
                logger.warning(f"不可能存在的方式: {self.command}")
                raise TypeError(f"不可能存在的方式: {self.command}")
            logger.debug(f"发送{count}数据到目标")
        except Exception as e:
            logger.error(f"发送服务器发生错误: {e}")
            self.proxy.close()
            self.transport.close()

async def main():
    loop = asyncio.get_running_loop()
    ssl_ctx = None
    if open_ssl:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_ctx.load_cert_chain("ssl_cert.pem", keyfile="ssl_key.pem")

    # create_server默认支持IPv4和IPv6
    try:
        addr = (host, port)
        if has_dualstack_ipv6():
            s = create_server(addr, family=AF_INET6, dualstack_ipv6=True)
        else:
            s = create_server(addr)
        server = await loop.create_server(Socks5Protocol, sock=s, ssl=ssl_ctx, reuse_address=True, reuse_port=True)
    except Exception as e:
        logger.error(f"新建server出问题: {e}")
        exit(-1)
    logger.info(f"socks5服务器监听: ({host}, {port})")
    if open_ssl:
        logger.info(f"开启TLS1.3传输")
    await server.serve_forever()

def handle_signal_int(_, __):
    logger.info(f"CTRL-C退出了")
    exit(-1)

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG
    )
    signal.signal(signal.SIGINT, handle_signal_int)
    asyncio.run(main())