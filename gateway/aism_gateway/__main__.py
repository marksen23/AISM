"""Run public and internal apps in one process: python -m aism_gateway"""
import asyncio
import logging
import os

import uvicorn

from .main import internal, public


def _split(v: str, default_port: int):
    host, _, port = v.rpartition(":")
    return host or "0.0.0.0", int(port or default_port)


async def _main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    ph, pp = _split(os.environ.get("LISTEN_PUBLIC", "0.0.0.0:8000"), 8000)
    ih, ip = _split(os.environ.get("LISTEN_INTERNAL", "0.0.0.0:8001"), 8001)
    servers = [uvicorn.Server(uvicorn.Config(public, host=ph, port=pp, log_level="warning", access_log=False)),
               uvicorn.Server(uvicorn.Config(internal, host=ih, port=ip, log_level="warning", access_log=False))]
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(_main())
