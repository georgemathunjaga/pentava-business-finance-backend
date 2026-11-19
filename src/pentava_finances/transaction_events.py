"""In-process dashboard invalidations for the single-worker backend."""
import asyncio

from fastapi.responses import StreamingResponse

_subscribers: dict[str, set[asyncio.Event]] = {}


def notify_transaction_received(business_id: str) -> None:
    for subscriber in _subscribers.get(business_id, ()):
        subscriber.set()


def transaction_event_stream(business_id: str) -> StreamingResponse:
    async def events():
        signal = asyncio.Event()
        subscribers = _subscribers.setdefault(business_id, set())
        subscribers.add(signal)
        try:
            yield "event: ready\ndata: {}\n\n"
            # Reconnect periodically so the request revalidates the web session.
            for _ in range(20):
                try:
                    await asyncio.wait_for(signal.wait(), timeout=15)
                except TimeoutError:
                    yield ": heartbeat\n\n"
                else:
                    signal.clear()
                    yield "event: transaction_received\ndata: {}\n\n"
        finally:
            subscribers.discard(signal)
            if not subscribers:
                _subscribers.pop(business_id, None)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store"},
    )
