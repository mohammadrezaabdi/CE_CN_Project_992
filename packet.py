import constants as const

from enum import IntEnum


class PacketType(IntEnum):
    MESSAGE = 0
    ROUTING_REQUEST = 10
    ROUTING_RESPONSE = 11
    PARENT_ADVERTISE = 20
    ADVERTISE = 21
    DESTINATION_NOT_FOUND = 31
    CONNECTION_REQUEST = 41
    CONNECTION_RESPONSE = 42


class Packet:
    def __init__(self, p_type: int, src_id: int, dest_id: int, data: str):
        self.p_type = p_type
        self.src_id = src_id
        self.dest_id = dest_id
        self.data = data
