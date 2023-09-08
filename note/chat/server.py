import asyncio
import socket

def handle_recv(ls: socket.socket):
    try:
        if data := ls.recv(1024):
            print(f"received: {data.decode()}")
            ls.send(data)
    except socket.error as e:
        print(f"error: {e}")

def handle_conn(ls: socket.socket, loop: asyncio.BaseEventLoop):
    rs, addr_info = ls.accept()
    print(f"{addr_info} connected")
    loop.add_reader(rs, handle_recv, rs)

async def main():
    loop = asyncio.get_running_loop()
    
    ls = socket.create_server(('127.0.0.1', 8888))
    loop.add_reader(ls, handle_conn, ls, loop)

    f = loop.create_future()
    await f

if __name__ == "__main__":
    asyncio.run(main())

