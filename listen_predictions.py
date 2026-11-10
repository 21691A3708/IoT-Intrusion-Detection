
import asyncio
import json
import websockets


async def listen_for_predictions():
    uri = "ws://127.0.0.1:8000/ws/predictions"

    print("Connecting to WebSocket...")

    try:
        async with websockets.connect(uri) as websocket:
            print("SUCCESS: Connected to prediction WebSocket!")
            print("Waiting for new predictions...\n")

            while True:
                message = await websocket.recv()
                data = json.loads(message)

                print("=" * 50)
                print("NEW WEBSOCKET EVENT")
                print("=" * 50)
                print(json.dumps(data, indent=4))

    except websockets.exceptions.ConnectionClosed:
        print("WebSocket connection closed.")

    except Exception as error:
        print("Error:", error)


asyncio.run(listen_for_predictions())
