import asyncio
import json

import websockets


class ChatServer:
    def __init__(self):
        self.groups = {}

    async def handle_message(self, websocket, path):
        async for message in websocket:
            data = json.loads(message)
            if data["action"] == "create_group":
                group_name = data["group_name"]
                self.groups[group_name] = set()
                await websocket.send(
                    json.dumps({"status": "Group created successfully."})
                )
            elif data["action"] == "join_group":
                group_name = data["group_name"]
                username = data["username"]
                self.groups[group_name].add(username)
                await websocket.send(
                    json.dumps(
                        {"status": f"User {username} joined group {group_name}."}
                    )
                )
            elif data["action"] == "send_message":
                group_name = data["group_name"]
                message_data = data["message"]
                for member in self.groups[group_name]:
                    # await self.send_message_to_member(member, group_name, message_data)
                    await websocket.send(
                        json.dumps({"sender": member, "message": message})
                    )

    # async def send_message_to_member(self, username, group_name, message):
    #     for websocket in self.websockets:
    #         if (
    #             websocket.path == f"/{group_name}"
    #             and username in self.groups[group_name]
    #         ):
    #             await websocket.send(
    #                 json.dumps({"sender": username, "message": message})
    #             )

    async def start_server(self, host, port):
        self.websockets = set()
        server = await websockets.serve(self.handle_message, host, port)

        await server.wait_closed()


if __name__ == "__main__":
    chat_server = ChatServer()
    asyncio.get_event_loop().run_until_complete(
        chat_server.start_server("localhost", 8765)
    )
    asyncio.get_event_loop().run_forever()
