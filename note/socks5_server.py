"""
主要实现了Socks5服务端Connect(TCP), UDP代理方式, 支持tls1.3
"""

import asyncio
from asyncio import BaseTransport, Protocol
from enum import Enum, IntEnum
import struct
import logging
import ipaddress
from dataclasses import dataclass
from typing import Dict, Callable, cast
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, gethostbyname
import ssl
import signal

host = "0.0.0.0"
port = 1080
# port = 8000
user = "lily"
pwd = "lily123"
open_ssl = False

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
    sock: socket
    ip: str = None
    port: int = None

    @property
    def adddress(self) -> (str, int):
        if self.ip and self.port:
            return (self.ip, self.port)
        i, p = self.sock.getsockname()
        self.ip = i
        self.port = p
        return (i, p)

    @property
    def packed(self) -> bytes:
        i, p = self.adddress
        return ipaddress.IPv4Address(i).packed + p.to_bytes(2, byteorder="big") # TODO IPv6支持
    
    def __str__(self) -> str:
        return self.address


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
            return ipaddress.IPv4Address(self.data[1:5])
        elif self.addr_type == AddrType.IPV6:
            return ipaddress.IPv6Address(self.data[1:17])
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
    
    @property
    def address(self):
        return (self.ip.compressed, self.port)

    @property
    def packed(self):
        return self.ip.packed + self.port.to_bytes(2, byteorder="big")
    
    def __str__(self) -> str:
        return f"({self.ip.compressed}, {self.port})"

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
        if handler is None:
            logger.error(f"没有找到相应的处理函数: {self.phase}")
            self.transport.close()
            return
        handler(data)

    def _handle_handshake(self, data):
        """
        VERSION | NMETHODS | METHODS
        1       | 1        | 1 to 255
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
        logger.info(f"校验信息: {username}, {password}")
        if username == user and password == pwd:
            self.transport.write(b"\x01\x00")
            self.phase = Phase.Request
        else:
            self.transport.write(b"\x01\x01")
            logger.warning(f"验证失败: {username}")
            self.transport.close()

    def _handle_request(self, data):
        """
        商量target host信息 
        """
        assert len(data) > 4, "request阶段需要更多数据"
        version, command, rsv, atyp = struct.unpack("!BBBB", bytes(data[0:4])) 
        self.command = command
        assert version == VERSION and rsv == RESVERVE
        self.target = SockAddr(atyp, data[4:])
        if self.command == Command.CONNECT or self.command == Command.UDP_ASSOCIATE:
            sock_type = (SOCK_STREAM, "TCP") if self.command == Command.CONNECT else (SOCK_DGRAM, "UDP")
            try:
                self.proxy = socket(AF_INET, sock_type[0]) # TODO: 支持IPv6
                self.proxy_wrapper = SockWrapper(self.proxy)
                logger.info(f"使用{sock_type[1]}模式，目标服务器地址: {self.target.address}")
            except Exception as e:
                logger.error(f"新建proxy sockes发生错误: {e}")
                self.transport.write(b"\x05\x01\x00\x01" + b"\x00"*6)
                self.transport.close()
                return
            
            try:
                if sock_type[0] == SOCK_STREAM:
                    self.proxy.connect(self.target.address)
            except Exception as e: # TODO: 更加精细化错误，给Socks5客户端更精确的错误原因
                logger.error(f"proxy sockes连接target({self.target.address})发生错误: {e}")
                self.transport.write(b"\x05\xFF\x00\x01" + self.proxy_wrapper.packed)
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

        self.transport.write(b"\x05\x00\x00\x01" + self.proxy_wrapper.packed)
        self.phase = Phase.Application

    def _handle_application_from_target(self):
        """
        处理从target来的数据，需要copy到client 
        """
        try:
            if self.command == Command.CONNECT:
                data = self.proxy.recv(4096)
                if not data or len(data) == 0:
                    logger.info("关闭proxy socket")
                    loop = asyncio.get_running_loop()
                    loop.remove_reader(self.proxy)
                    self.proxy.close()
                    self.proxy = None
                    self.transport.close()
            elif self.command == Command.UDP_ASSOCIATE:
                data = self.proxy.recv(4096)
            else:
                logger.warning(f"taret发来数据，但是发现不支持的command: {self.command}")
                raise Exception(f"taret发来数据，但是发现不支持的command: {self.command}")
            logger.info(f"收到target数据{len(data)}")
            self.transport.write(data)
        except Exception as e:
            self.proxy.close()
            self.proxy = None
            self.transport.close()
            logger.error(f"获取target数据时发生错误: {e}")

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
                raise Exception(f"不可能存在的方式: {self.command}")
            logger.info(f"发送{count}数据到目标")
        except Exception as e:
            self.proxy.close()
            self.proxy = None
            self.transport.close()
            logger.error(f"发送服务器发生错误: {e}")

async def main():
    loop = asyncio.get_running_loop()
    ssl_ctx = None
    if open_ssl:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_ctx.load_cert_chain("ssl_cert.pem", keyfile="ssl_key.pem")

    server = await loop.create_server(Socks5Protocol, host, port, ssl=ssl_ctx)
    print(f"socks5服务器监听: {host}:{port}")
    if open_ssl:
        print(f"开启TLS1.3传输")
    await server.serve_forever()

def handle_signal_int(sig_num, _):
    logger.info(f"CTRL-C({sig_num})退出了")
    exit(-1)

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO
    )
    logger = logging.getLogger('socks5')
    signal.signal(signal.SIGINT, handle_signal_int)
    asyncio.run(main())