"""Throwaway echo backend for testing the relay (listens on 9100)."""
import asyncio


async def handle(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"[backend] connection from {addr}")
    while True:
        data = await reader.read(65536)
        if not data:
            break
        print(f"[backend] echoing {len(data)} bytes: {data!r}")
        writer.write(data)
        await writer.drain()
    writer.close()
    print(f"[backend] {addr} disconnected")


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 9100)
    print("[backend] echo server on 127.0.0.1:9100")
    await server.serve_forever()


asyncio.run(main())
