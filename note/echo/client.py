import argparse
import asyncio
import logging
import pickle
import ssl
from typing import Optional, cast
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    QuicEvent,
    StreamDataReceived,
    PingAcknowledged,
    ConnectionTerminated,
)
from aioquic.quic.logger import QuicFileLogger

logger = logging.getLogger("client")


class EchoClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[str]] = None
        self.send_ping_timer = None
        self.timer_hander = None

    def echo(self, stream_id, data: str) -> None:
        # stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id, data.encode(), end_stream=False)
        # waiter = self._loop.create_future()
        # self._ack_waiter = waiter
        self.transmit()

        # return await asyncio.shield(waiter)

    def quic_event_received(self, event: QuicEvent) -> None:
        # if self._ack_waiter is not None:
        if isinstance(event, StreamDataReceived):
            logger.info(f"收到StreamDataReceived, {event.data.decode()}")
            # waiter = self._ack_waiter
            # self._ack_waiter = None
            # waiter.set_result(event.data)
            loop = asyncio.get_running_loop()
            # print("looptime::::", self._loop.time())
            self.send_ping_timer = self._quic.get_timer()
            self.timer_hander = loop.call_at(self.send_ping_timer + 30, self.send_ping)
        elif isinstance(event, PingAcknowledged):
            logger.info("ping返回了")
        elif isinstance(event, ConnectionTerminated):
            logger.info("server发送ConnectionTerminated")
            self.close()
            exit(-1)

    def send_ping(self):
        print("准备send ping")
        self._quic.send_ping(8888)
        self.transmit()
        loop = asyncio.get_running_loop()
        self.send_ping_timer = self._loop.time() + 30
        self.timer_hander = loop.call_at(self.send_ping_timer, self.send_ping)


def save_session_ticket(ticket):
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


class MyProtocol(asyncio.Protocol):
    def __init__(self, client: EchoClientProtocol) -> None:
        self.client = client
        super().__init__()

    def connection_made(self, transport):
        print("pipe opened", file=sys.stderr, flush=True)
        super(MyProtocol, self).connection_made(transport=transport)

    def data_received(self, data):
        # print("received: {!r}".format(data), file=sys.stderr, flush=True)
        # print(data.decode(), file=sys.stderr, flush=True)
        if data.decode().find("exit") != -1:
            self.client.close()
            exit(0)

        stream_id = self.client._quic.get_next_available_stream_id()
        self.client.echo(stream_id, data.decode())
        super(MyProtocol, self).data_received(data)

    def connection_lost(self, exc):
        print("pipe closed", file=sys.stderr, flush=True)
        super(MyProtocol, self).connection_lost(exc)


def create_my_protocol(client: EchoClientProtocol):
    return MyProtocol(client)


async def main(
    configuration: QuicConfiguration,
    host: str,
    port: int,
) -> None:
    with open("/dev/stdin", "rb", buffering=0) as stdin:
        logger.debug(f"Connecting to {host}:{port}")
        async with connect(
            host,
            port,
            configuration=configuration,
            session_ticket_handler=save_session_ticket,
            create_protocol=EchoClientProtocol,
        ) as client:
            client = cast(EchoClientProtocol, client)
            # asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            loop = asyncio.get_event_loop()
            stdin_pipe_reader = await loop.connect_read_pipe(
                lambda: create_my_protocol(client), stdin
            )
            await asyncio.Future()

        # data_stream_id = client._quic.get_next_available_stream_id()
        # while True:
        #     await asyncio.sleep(3)
        #     data = input("input something: ")
        #     if data == "exit":
        #         break
        #     res = await client.echo(data_stream_id, data)
        #     logger.info(f"Received echo answer {res}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="echo client")
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="The remote peer's host name or IP address",
    )
    parser.add_argument(
        "--port", type=int, default=4433, help="The remote peer's port number"
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    configuration = QuicConfiguration(is_client=True)
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            logger.debug(f"Unable to read {args.session_ticket}")
            pass
    else:
        logger.debug("No session ticket defined...")

    asyncio.run(
        main(
            configuration=configuration,
            host=args.host,
            port=args.port,
        )
    )
