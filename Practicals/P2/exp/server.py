# Server
import asyncio

import websockets


async def server(websocket, path):
    async for message in websocket:
        await websocket.send(message)


async def main():
    async with websockets.serve(server, "localhost", 8765):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
