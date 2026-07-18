from __future__ import annotations

import json

import nats
from nats.js import JetStreamContext

STREAM = "ARGUS_SCANS"
SUBJECTS = ["argus.scans.>"]
CONSUMER = "nuclei-worker"


async def connect(url: str) -> tuple:
    nc = await nats.connect(url)
    js = nc.jetstream()
    try:
        await js.find_stream(name=STREAM)
    except Exception:
        await js.add_stream(name=STREAM, subjects=SUBJECTS)
    return nc, js


async def subscribe(js: JetStreamContext, handler):
    await js.subscribe(
        "argus.scans.created",
        durable=CONSUMER,
        stream=STREAM,
        cb=handler,
        manual_ack=True,
    )


def decode(data: bytes) -> dict:
    return json.loads(data.decode())
