import socket
import logging
from server import Server
import constants

logger = logging.getLogger('node')


class IdTable:
    pass


def handler(conn: socket.socket):
    pass


class Node:
    def __init__(self, ID, port):
        self.id = ID
        self.port = port
        self.id_table = IdTable()
        self.server_socket = Server(constants.DEFAULT_IP, port, handler, logger)
#         todo firewall


