import asyncio, sys
sys.path.insert(0, "src")
from proxy.http_parser import read_request

async def main():
    raw = (b"GET /api/data HTTP/1.1\r\n"
           b"Host: 127.0.0.1:5000\r\n"
           b"Authorization: Bearer abc.def.ghi\r\n"
           b"User-Agent: curl/8.0\r\n\r\n")
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    req = await read_request(reader)
    print("method   :", req.method)
    print("path     :", req.path)
    print("version  :", req.version)
    print("auth hdr :", req.header("Authorization"))
    print("host hdr :", req.header("host"))

asyncio.run(main())
