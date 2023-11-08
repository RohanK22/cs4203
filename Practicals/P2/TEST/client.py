import asyncio
import json

import websockets


async def send_message():
    async with websockets.connect("ws://localhost:8765") as websocket:
        while True:
            action = input(
                "Enter action (create_group, join_group, send_message, exit): "
            )
            if action == "exit":
                break

            if action == "create_group":
                group_name = input("Enter group name: ")
                await websocket.send(
                    json.dumps({"action": "create_group", "group_name": group_name})
                )
            elif action == "join_group":
                group_name = input("Enter group name: ")
                username = input("Enter your username: ")
                await websocket.send(
                    json.dumps(
                        {
                            "action": "join_group",
                            "group_name": group_name,
                            "username": username,
                        }
                    )
                )
            elif action == "send_message":
                group_name = input("Enter group name: ")
                message = input("Enter message: ")
                await websocket.send(
                    json.dumps(
                        {
                            "action": "send_message",
                            "group_name": group_name,
                            "message": message,
                        }
                    )
                )
            else:
                print("Invalid action")

            response = await websocket.recv()
            print(f"Response from server: {response}")


asyncio.get_event_loop().run_until_complete(send_message())
