from enum import IntEnum
import logging
import socket
import time

logger = logging.getLogger("packet")


class PacketType(IntEnum):
    MESSAGE = 0
    ROUTING_REQUEST = 10
    ROUTING_RESPONSE = 11
    PARENT_ADVERTISE = 20
    ADVERTISE = 21
    DESTINATION_NOT_FOUND = 31
    CONNECTION_REQUEST = 41
    CONNECTION_RESPONSE = 42
    ALL = -1


class Packet:
    def __init__(self, p_type: int, src_id: int, dest_id: int, data: str = ""):
        self.p_type = p_type
        self.src_id = src_id
        self.dest_id = dest_id
        self.data = data

    def send(self, ip: str, port: int):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            while True:
                try:
                    s.connect((ip, port))
                    logger.info("connected to server successfully!")
                    s.sendall(str(self.__dict__).encode("ascii"))
                    break
                except:
                    time.sleep(1)
                    logger.exception("waiting for server...")
