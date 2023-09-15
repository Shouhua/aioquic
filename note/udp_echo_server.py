# nc -v -t -4 localhost 1081
import asyncio
import signal

class MyDatagramProtocol(asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport
    
    def connection_made(self, transport: asyncio.Transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        print(f"收到来自{addr}的消息{data}")
        self.transport.sendto(data, addr)

async def main():
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(MyDatagramProtocol, ("0.0.0.0", 9000))
    print("Start UDP echo server on: (0.0.0.0, 9000)")
    await loop.create_future()

if __name__ == "__main__":
  signal.signal(signal.SIGINT, lambda _, __: exit(-1))
  asyncio.run(main())

# import socket

# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# server_address = '0.0.0.0'
# server_port = 9000

# server = (server_address, server_port)
# sock.bind(server)
# print("Listening on ", server_address, ":", str(server_port), flush=True)

# while True:
#   payload, client_address = sock.recvfrom(1000)
#   print("Echoing data back to ", str(client_address), ": ", payload)
#   sent = sock.sendto(payload, client_address)
#   print("Sent results: ", str(sent), flush=True)