"""BL6-04 — Performance benchmark against the live proxy, full pipeline active.

Sends N concurrent requests as an authenticated admin (the heaviest
identity path: LDAP + RBAC + rate limit + WAF all evaluated), and
reports throughput and latency.
"""
import asyncio
import base64
import ssl
import statistics
import time

import aiohttp

CA, CRT, KEY = "certs/ca.crt", "certs/client.crt", "certs/client.key"
URL = "https://127.0.0.1:8443/api/data"
CAROL = base64.b64encode(b"carol:carol_pw_123").decode()

TOTAL_REQUESTS = 200
CONCURRENCY = 20  # simultaneous in-flight requests


def build_ssl_context():
    ctx = ssl.create_default_context(cafile=CA)
    ctx.load_cert_chain(certfile=CRT, keyfile=KEY)
    return ctx


async def one_request(session, sem):
    async with sem:
        start = time.monotonic()
        try:
            async with session.get(
                URL, headers={}
            ) as resp:
                await resp.read()
                elapsed = (time.monotonic() - start) * 1000
                return elapsed, resp.status
        except Exception as exc:
            return None, str(exc)


async def main():
    ssl_ctx = build_ssl_context()
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=CONCURRENCY)
    sem = asyncio.Semaphore(CONCURRENCY)

    async with aiohttp.ClientSession(connector=connector) as session:
        print(f"Sending {TOTAL_REQUESTS} requests, {CONCURRENCY} concurrent, "
              f"full pipeline active (auth + RBAC + rate limit + WAF)...")
        start = time.monotonic()
        results = await asyncio.gather(
            *[one_request(session, sem) for _ in range(TOTAL_REQUESTS)])
        total_time = time.monotonic() - start

    latencies = [r[0] for r in results if r[0] is not None]
    statuses = [r[1] for r in results]
    errors = [r for r in results if r[0] is None]

    print(f"\n=== Results ===")
    print(f"Total time:        {total_time:.2f} s")
    print(f"Successful:        {len(latencies)}/{TOTAL_REQUESTS}")
    print(f"Throughput:        {len(latencies)/total_time:.1f} req/s")
    if latencies:
        print(f"Latency  avg:      {statistics.mean(latencies):.1f} ms")
        print(f"Latency  median:   {statistics.median(latencies):.1f} ms")
        print(f"Latency  p95:      {sorted(latencies)[int(len(latencies)*0.95)]:.1f} ms")
        print(f"Latency  min/max:  {min(latencies):.1f} / {max(latencies):.1f} ms")
    if errors:
        print(f"Errors:            {len(errors)} (e.g. {errors[0][1]})")
    from collections import Counter
    print(f"Status codes:      {dict(Counter(statuses))}")


asyncio.run(main())
