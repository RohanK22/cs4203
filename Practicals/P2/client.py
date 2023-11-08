import asyncio
import json

import websockets

username = input("Enter your username: ")


async def start_client():
    async with websockets.connect(
        "ws://localhost:8765", ping_interval=None
    ) as websocket:
        while True:
            action = input(
                "Enter action (create_thread, join_thread, leave_thread, send_message, read_message, exit)"
            )

            if action == "exit":
                break

            if action == "1":
                thread_id = input("Enter thread id: ")
                await websocket.send(
                    json.dumps(
                        {
                            "action": "create_thread",
                            "thread_id": thread_id,
                            "username": username,
                        }
                    )
                )
                response = await websocket.recv()
                print(f"Response from server: {response})")
            elif action == "2":
                thread_id = input("Enter thread id: ")
                await websocket.send(
                    json.dumps(
                        {
                            "action": "join_thread",
                            "thread_id": thread_id,
                            "username": username,
                        }
                    )
                )
                response = await websocket.recv()
                print(f"Response from server: {response})")
            elif action == "3":
                thread_id = input("Enter thread id: ")
                await websocket.send(
                    json.dumps(
                        {
                            "action": "leave_thread",
                            "thread_id": thread_id,
                            "username": username,
                        }
                    )
                )
                response = await websocket.recv()
                print(f"Response from server: {response})")
            elif action == "4":
                thread_id = input("Enter thread id: ")
                message = input("Enter message: ")

                await websocket.send(
                    json.dumps(
                        {
                            "action": "send_message",
                            "thread_id": thread_id,
                            "username": username,
                            "message": message,
                        }
                    )
                )
                response = await websocket.recv()
                print(f"Response from server: {response})")
            elif action == "5":
                thread_id = input("Enter thread id: ")

                await websocket.send(
                    json.dumps(
                        {
                            "action": "read_message",
                            "thread_id": thread_id,
                            "username": username,
                        }
                    )
                )

                response = await websocket.recv()
                print(f"Response from server: {response})")
                response = json.loads(response)

                for sender, message in response["thread_messages"]:
                    print(f"{sender}: {message}")
            else:
                print("Invalid action")


if __name__ == "__main__":
    asyncio.run(start_client())
