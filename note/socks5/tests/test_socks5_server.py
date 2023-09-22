from ..socks5_server import SockAddr, AddrType
from unittest import TestCase
from socket import gaierror, AF_INET6
from ipaddress import IPv4Address, IPv6Address, ip_address

class SockAddrTest(TestCase):
    def setup_domain(self):
        self.addr_type = AddrType.DOMINNAME
        domain_name = "www.google.com"
        self.ipv4 = "142.251.43.4"
        self.port = 443
        data = self.addr_type.to_bytes(1, byteorder="big") + b"\x0E" + domain_name.encode() + self.port.to_bytes(2, byteorder="big")
        self.sock_addr = SockAddr(data)

    def setup_not_exist_domain(self):
        self.addr_type = AddrType.DOMINNAME
        not_exist_domain_name = "www.ladfjlsfjsasl.com"
        self.port = 443
        not_exist_data = self.addr_type.to_bytes(1, byteorder="big") + b"\x15" + not_exist_domain_name.encode() + self.port.to_bytes(2, byteorder="big")
        self.not_exit_sock_addr = SockAddr(not_exist_data)
    
    def setup_ipv4(self):
        self.addr_type = AddrType.IPV4
        self.ipv4 = "127.0.0.1"
        self.port = 1080
        ipv4_data = self.addr_type.to_bytes(1, byteorder="big") + b"\x04" + IPv4Address(self.ipv4).packed + self.port.to_bytes(2, byteorder="big")
        self.sock_addr = SockAddr(ipv4_data)
    def setup_ipv6(self):
        self.addr_type = AddrType.IPV6
        self.ipv6 = "::ff:127.0.0.1"
        self.port = 1080
        ipv6_data = self.addr_type.to_bytes(1, byteorder="big") + b"\x10" + IPv6Address(self.ipv6).packed + self.port.to_bytes(2, byteorder="big")
        self.sock_addr = SockAddr(ipv6_data, AF_INET6)

    def test_domian(self):
        self.setup_domain()
        self.assertEqual(self.sock_addr.addr_type, self.addr_type)
        self.assertEqual(self.sock_addr.port, self.port)
        self.assertEqual(self.sock_addr.address, (self.ipv4, self.port))
        self.assertEqual(str(self.sock_addr), f"{self.sock_addr}")
    
    # 测试不存在的域名解析
    # 测试属性address
    def test_not_exist_address(self):
        self.setup_not_exist_domain()
        self.assertRaises(gaierror, getattr, self.not_exit_sock_addr, "address")

    def test_ipv4(self):
        self.setup_ipv4()
        self.assertEqual(self.sock_addr.port, self.port)
        self.assertEqual(self.sock_addr.address, (self.ipv4, self.port))
        self.assertEqual(str(self.sock_addr), f"{self.sock_addr}")

    def test_ipv6(self):
        self.setup_ipv6()
        self.assertEqual(self.sock_addr.port, self.port)
        self.assertEqual(self.sock_addr.address, (ip_address(self.ipv6).compressed, self.port, 0, 0))
        self.assertEqual(str(self.sock_addr), f"{self.sock_addr}")