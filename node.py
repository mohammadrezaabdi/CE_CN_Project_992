import socket
import logging
from server import Server
import constants as consts

logger = logging.getLogger("node")


class IdTable:
    pass


def handler(conn: socket.socket):
    pass


class Node:
    def __init__(self, ID, port):
        self.id = ID
        self.port = port
        self.id_table = IdTable()
        self.parent = None
        self.left_child = None
        self.right_child = None
        self.server_socket = Server(consts.DEFAULT_IP, port, handler, logger)


#         todo firewall


def main():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((consts.DEFAULT_IP, consts.MANAGER_PORT))
        cmd = input()
        [(id, port)] = consts.CONNECT_REGEX.findall(cmd)
        request = consts.CONNECT_REQUEST.format(id=id, port=port)
        s.sendall(request.encode("ascii"))
        recv = s.recv(consts.BUFFER_SIZE)
        print(recv)


if __name__ == "__main__":
    main()
