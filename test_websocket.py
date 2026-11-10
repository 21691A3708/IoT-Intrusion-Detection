
import asyncio
import websockets

async def test_connection():
    uri = "ws://127.0.0.1:8000/ws/predictions"

    try:
        async with websockets.connect(uri) as websocket:
            print("SUCCESS: WebSocket connected!")
            print("Connection is active.")

    except Exception as error:
        print("WebSocket connection failed:", error)

asyncio.run(test_connection())
