from app.transport_v32 import InMemoryTransport, build_transport, TransportError


def test_memory_transport_publish_consume_ack():
    t = InMemoryTransport()
    receipt = t.publish("q", {"hello": "world"})
    msg = t.consume("q", timeout=0)
    assert msg and msg["receipt"] == receipt
    assert msg["payload"]["hello"] == "world"
    t.ack(receipt)
    assert t.stats("q")["queued"] == 0


def test_build_memory_transport():
    assert isinstance(build_transport("memory"), InMemoryTransport)


def test_invalid_backend():
    try:
        build_transport("unknown")
    except TransportError:
        return
    assert False, "expected TransportError"
