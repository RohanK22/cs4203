import json
from enum import Enum

class MessageType(Enum):
    REGISTER = "REGISTER"
    CREATE_THREAD = "CREATE_THREAD"
    JOIN_THREAD = "JOIN_THREAD"
    LEAVE_THREAD = "LEAVE_THREAD"
    SEND_MESSAGE = "SEND_MESSAGE"
    GET_MESSAGES = "GET_MESSAGES"
    GET_THREADS = "GET_THREADS"

class Message:
    def __init__(self, message_type, data):
        self.message_type = message_type
        self.data = data

    def __str__(self):
        return f"Message(message_type={self.message_type}, data={self.data})"

    def __repr__(self):
        return str(self)

    def to_json(self):
        return {
            "message_type": MessageType(self.message_type).name,
            "data": self.data,
        }

    @classmethod
    def from_json(cls, json):
        return cls(MessageType[json["message_type"]], json["data"])


def encode_json(message: Message) -> str:
    return json.dumps(message.to_json())


def decode_json(json_string: str) -> Message:
    return Message.from_json(json.loads(json_string))
