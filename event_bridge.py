import asyncio


event_loop = None
broadcast_function = None


def setup_event_bridge(loop, broadcast):
    global event_loop
    global broadcast_function

    event_loop = loop
    broadcast_function = broadcast


def send_event(event):

    if event_loop is None:
        return

    if broadcast_function is None:
        return

    asyncio.run_coroutine_threadsafe(
        broadcast_function(event),
        event_loop
    )
