import socket
import logging

import packet
from server import Server
import constants as consts
from packet import Packet, PacketType
import client
import ast

logger = logging.getLogger("node")


class IdTable:
    pass


class Node:
    def __init__(self, ID, port):
        self.id = ID
        self.port = port
        self.id_table = IdTable()
        self.parent = None
        self.left_child = None
        self.right_child = None
        self.server_socket = Server(consts.DEFAULT_IP, port, self.handler, logger)

    def handler(self, conn: socket.socket):
        logger.debug("handling new client")
        with conn:
            try:
                data = conn.recv(consts.BUFFER_SIZE).decode("ascii")
                if not data:
                    return
                data = ast.literal_eval(data)
                logger.debug(f"received message is:{data}")
                packet = Packet(**data)

                if packet.p_type == PacketType.CONNECTION_REQUEST:
                    self.connection_request_handle(packet)
                elif packet.p_type == PacketType.CONNECTION_RESPONSE:
                    pass
                elif packet.p_type == PacketType.MESSAGE:
                    pass
                elif packet.p_type == PacketType.ROUTING_REQUEST:
                    pass
                elif packet.p_type == PacketType.ROUTING_RESPONSE:
                    pass
                elif packet.p_type == PacketType.PARENT_ADVERTISE:
                    pass
                elif packet.p_type == PacketType.DESTINATION_NOT_FOUND:
                    pass

                # response = consts.CONNECT_ACCEPT.format(
                #     id_parent=parent_id, port_parent=parent_port
                # )
                # send_packet = Packet(
                #     p_type=PacketType.CONNECTION_RESPONSE,
                #     src_id=-1,
                #     dest_id=id,
                #     data=response,
                # )
                # conn.sendall(str(send_packet.__dict__).encode("ascii"))

            except Exception as e:
                raise Exception(e)

    def connection_request_handle(self, p: Packet):
        # from new child
        if self.left_child:
            self.right_child = (p.src_id, int(p.data))
        else:
            self.left_child = (p.src_id, int(p.data))


#         todo firewall


def network_init(id, port) -> packet.Packet:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((consts.DEFAULT_IP, consts.MANAGER_PORT))

        request = consts.CONNECT_REQUEST.format(id=id, port=port)
        packet = Packet(
            p_type=PacketType.CONNECTION_REQUEST.value,
            src_id=id,
            dest_id=-1,
            data=request,
        )
        packet_dict = str(packet.__dict__)
        s.sendall(packet_dict.encode("ascii"))

        response = s.recv(consts.BUFFER_SIZE).decode("ascii")
        response = ast.literal_eval(response)
        return Packet(**response)


def family_meeting(myid: int, myport: int, pid: int, pport: int):
    if pid == -1:
        return
    p = Packet(PacketType.CONNECTION_REQUEST, myid, pid, str(myport))
    client.send(consts.DEFAULT_IP, pport, p)


def main():
    cmd = input()
    [(id, port)] = consts.CONNECT_REGEX.findall(cmd)
    p = network_init(id, port)
    [(pid, pport)] = consts.CONNECT_ACCEPT_REGEX.findall(p.data)
    family_meeting(int(id), int(port), int(pid), int(pport))

    node = Node(id, port)
    node.server_socket.listen()


if __name__ == "__main__":
    main()
