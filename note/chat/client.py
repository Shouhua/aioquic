import asyncio
import socket
import sys

def handle_recv(local_socket: socket.socket):
    if recv_str := local_socket.recv(1024):
        if recv_str:
            print(f"received: {recv_str.decode()}")

def handle_input(ls: socket.socket):
    input_str = sys.stdin.readline().strip("\n")
    count = ls.send(input_str.encode())
    print(f"send {count} message: {input_str}")

async def main():
    loop = asyncio.get_running_loop()
    
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.connect(("127.0.0.1", 8888))
    loop.add_reader(ls, handle_recv, ls)
    loop.add_reader(sys.stdin, handle_input, ls)

    f = loop.create_future()
    await f

if __name__ == "__main__":
    asyncio.run(main())
        