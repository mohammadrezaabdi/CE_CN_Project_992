import socket
import logging
from server import Server
import constants as consts
from packet import Packet, PacketType
import ast

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


def listener_handler(conn):
    pass


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((consts.DEFAULT_IP, consts.MANAGER_PORT))
        cmd = input()
        [(id, port)] = consts.CONNECT_REGEX.findall(cmd)

        request = consts.CONNECT_REQUEST.format(id=id, port=port)
        packet = Packet(
            p_type=consts.packet_type[consts.CONNECTION_REQUEST],
            src_id=id,
            dest_id=-1,
            data=request,
        )

        packet_dict = str(packet.__dict__)

        s.sendall(packet_dict.encode("ascii"))
        recv = s.recv(consts.BUFFER_SIZE).decode("ascii")
        print(recv)
        recv = ast.literal_eval(recv)
        recv_packet = Packet(**recv)
        print(recv_packet.__dict__)


if __name__ == "__main__":
    main()
