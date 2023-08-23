import asyncio
from typing import Any

async def udp_handler(local_addr, remote_addr):
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DemoProtocol(),
        local_addr
    )
    protocol.send_data(b"Hello, world!\n", remote_addr)
    # await asyncio.sleep(1)
    await asyncio.Future()
    # transport.close()


class DemoProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        super().__init__()
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        print(f"Received data: {data.decode()}, from {addr}")
    def send_data(self, data, addr):
        self.transport.sendto(data, addr)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    local_address = ('localhost', 8888)
    remote_address = ('localhost', 2115)

    # loop.run_until_complete(udp_handler(local_address, remote_address))
    asyncio.run(udp_handler(local_address, remote_address))

    loop.close()