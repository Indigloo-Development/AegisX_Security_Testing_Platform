from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Protocol


class TransportError(RuntimeError):
    pass


class MessageTransport(Protocol):
    def publish(self, queue: str, message: dict) -> str: ...
    def consume(self, queue: str, timeout: float = 1.0) -> dict | None: ...
    def ack(self, receipt: str) -> None: ...
    def nack(self, receipt: str, requeue: bool = True) -> None: ...
    def stats(self, queue: str) -> dict: ...


@dataclass
class Envelope:
    receipt: str
    payload: dict
    created_at: float


class InMemoryTransport:
    def __init__(self):
        self._queues: dict[str, list[Envelope]] = {}
        self._inflight: dict[str, Envelope] = {}
        self._seq = 0

    def publish(self, queue: str, message: dict) -> str:
        self._seq += 1
        receipt = f"mem-{self._seq}"
        self._queues.setdefault(queue, []).append(Envelope(receipt, message, time.time()))
        return receipt

    def consume(self, queue: str, timeout: float = 1.0) -> dict | None:
        deadline = time.time() + max(0.0, timeout)
        first = True
        while first or time.time() <= deadline:
            first = False
            items = self._queues.get(queue, [])
            if items:
                env = items.pop(0)
                self._inflight[env.receipt] = env
                return {"receipt": env.receipt, "payload": env.payload}
            time.sleep(0.01)
        return None

    def ack(self, receipt: str) -> None:
        self._inflight.pop(receipt, None)

    def nack(self, receipt: str, requeue: bool = True) -> None:
        env = self._inflight.pop(receipt, None)
        if env and requeue:
            queue = next((q for q, items in self._queues.items() if any(e.receipt == receipt for e in items)), None)
            self._queues.setdefault(queue or "default", []).insert(0, env)

    def stats(self, queue: str) -> dict:
        return {"backend": "memory", "queue": queue, "queued": len(self._queues.get(queue, [])), "inflight": sum(1 for e in self._inflight.values())}


class RedisTransport:
    """Optional Redis Streams transport. Requires redis-py at runtime."""
    def __init__(self, url: str):
        try:
            import redis  # type: ignore
        except ImportError as exc:
            raise TransportError("Redis transport requires the 'redis' package") from exc
        self.client = redis.Redis.from_url(url, decode_responses=True)

    def publish(self, queue: str, message: dict) -> str:
        entries = self.client.xadd(queue, {"payload": json.dumps(message)}, maxlen=100_000, approximate=True)
        return str(entries)

    def consume(self, queue: str, timeout: float = 1.0) -> dict | None:
        rows = self.client.xread({queue: "$"}, count=1, block=max(1, int(timeout * 1000)))
        if not rows:
            return None
        stream, entries = rows[0]
        receipt, data = entries[0]
        return {"receipt": receipt, "payload": json.loads(data["payload"])}

    def ack(self, receipt: str) -> None:
        return None

    def nack(self, receipt: str, requeue: bool = True) -> None:
        return None

    def stats(self, queue: str) -> dict:
        try:
            length = int(self.client.xlen(queue))
        except Exception:
            length = 0
        return {"backend": "redis-streams", "queue": queue, "queued": length}


class RabbitMQTransport:
    """Optional RabbitMQ transport. Requires pika at runtime."""
    def __init__(self, url: str):
        try:
            import pika  # type: ignore
        except ImportError as exc:
            raise TransportError("RabbitMQ transport requires the 'pika' package") from exc
        self.pika = pika
        self.params = pika.URLParameters(url)
        self.connection = pika.BlockingConnection(self.params)
        self.channel = self.connection.channel()

    def publish(self, queue: str, message: dict) -> str:
        self.channel.queue_declare(queue=queue, durable=True)
        self.channel.basic_publish(exchange="", routing_key=queue, body=json.dumps(message).encode(), properties=self.pika.BasicProperties(delivery_mode=2))
        return f"rabbit-{time.time_ns()}"

    def consume(self, queue: str, timeout: float = 1.0) -> dict | None:
        self.channel.queue_declare(queue=queue, durable=True)
        method, _props, body = self.channel.basic_get(queue=queue, auto_ack=False)
        if method is None:
            return None
        return {"receipt": str(method.delivery_tag), "payload": json.loads(body.decode())}

    def ack(self, receipt: str) -> None:
        self.channel.basic_ack(delivery_tag=int(receipt))

    def nack(self, receipt: str, requeue: bool = True) -> None:
        self.channel.basic_nack(delivery_tag=int(receipt), requeue=requeue)

    def stats(self, queue: str) -> dict:
        self.channel.queue_declare(queue=queue, durable=True)
        return {"backend": "rabbitmq", "queue": queue}


def build_transport(backend: str, url: str | None = None) -> MessageTransport:
    name = backend.strip().lower()
    if name == "redis":
        if not url:
            raise TransportError("Redis transport requires a URL")
        return RedisTransport(url)
    if name in {"rabbitmq", "amqp"}:
        if not url:
            raise TransportError("RabbitMQ transport requires a URL")
        return RabbitMQTransport(url)
    if name == "memory":
        return InMemoryTransport()
    raise TransportError(f"Unsupported transport backend: {backend}")
