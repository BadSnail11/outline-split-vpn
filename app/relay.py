import asyncio
import threading
import time

from app.errors import AppError


class PrefixRelay:
    """Write the Outline stream prefix, then pass the Shadowsocks bytes through.

    Outline puts the prefix on TCP only. UDP datagrams are forwarded unchanged.
    """

    def __init__(self, listen: tuple[str, int], upstream: tuple[str, int], prefix: bytes):
        self.listen = listen
        self.upstream = upstream
        self.prefix = prefix
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._stop: asyncio.Event | None = None
        self._peers: dict = {}
        self._udp = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="prefix-relay", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5):
            self.stop()
            raise AppError("Prefix relay did not start")
        if self._error is not None:
            self.stop()
            raise AppError(f"Prefix relay failed: {self._error}")

    def stop(self) -> None:
        loop = self._loop
        event = self._stop
        if loop is not None and event is not None and loop.is_running():
            loop.call_soon_threadsafe(event.set)
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._main())
        except Exception as exc:
            self._error = exc
            self._ready.set()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    async def _main(self) -> None:
        self._stop = asyncio.Event()
        server = await asyncio.start_server(self._on_tcp, self.listen[0], self.listen[1])
        transport, _protocol = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: _ClientUdp(self),
            local_addr=self.listen,
        )
        self._udp = transport
        sweeper = asyncio.create_task(self._sweep())
        self._ready.set()
        await self._stop.wait()
        sweeper.cancel()
        server.close()
        await server.wait_closed()
        transport.close()
        for peer in list(self._peers.values()):
            peer.transport.close()
        self._peers.clear()

    async def _on_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        remote_writer = None
        try:
            _remote_reader, remote_writer = await asyncio.open_connection(self.upstream[0], self.upstream[1])
            if self.prefix:
                remote_writer.write(self.prefix)
                await remote_writer.drain()
            await asyncio.gather(
                _pipe(reader, remote_writer),
                _pipe(_remote_reader, writer),
            )
        except Exception as exc:
            print(f"tcp relay to {self.upstream[0]}:{self.upstream[1]} failed: {exc}", flush=True)
        finally:
            for stream in (writer, remote_writer):
                if stream is None:
                    continue
                try:
                    stream.close()
                except Exception:
                    pass

    async def _forward_udp(self, client, data: bytes, addr: tuple) -> None:
        peer = self._peers.get(addr)
        if peer is None:
            try:
                peer = await self._open_peer(client, addr)
            except OSError as exc:
                print(f"udp relay to {self.upstream[0]}:{self.upstream[1]} failed: {exc}", flush=True)
                return
            self._peers[addr] = peer
        peer.last = time.monotonic()
        try:
            peer.transport.sendto(data)
        except OSError:
            self._drop_peer(addr)

    async def _open_peer(self, client, addr: tuple):
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _UpstreamUdp(client, addr),
            remote_addr=self.upstream,
        )
        protocol.transport = transport
        return protocol

    def _drop_peer(self, addr: tuple) -> None:
        peer = self._peers.pop(addr, None)
        if peer is not None:
            peer.transport.close()

    async def _sweep(self) -> None:
        assert self._stop is not None
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=30)
            except asyncio.TimeoutError:
                now = time.monotonic()
                for addr, peer in list(self._peers.items()):
                    if now - peer.last > 60:
                        self._drop_peer(addr)


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class _ClientUdp(asyncio.DatagramProtocol):
    def __init__(self, relay: PrefixRelay):
        self.relay = relay
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        asyncio.get_running_loop().create_task(self.relay._forward_udp(self.transport, data, addr))


class _UpstreamUdp(asyncio.DatagramProtocol):
    def __init__(self, client, client_addr: tuple):
        self.client = client
        self.client_addr = client_addr
        self.transport = None
        self.last = time.monotonic()

    def datagram_received(self, data: bytes, addr) -> None:
        self.last = time.monotonic()
        if self.client is not None:
            self.client.sendto(data, self.client_addr)

    def error_received(self, exc: Exception) -> None:
        return
