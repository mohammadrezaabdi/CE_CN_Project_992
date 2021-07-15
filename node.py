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
    def get_next_hop(self, dest_id):
        pass


class Node:
    def __init__(self, ID, port):
        self.id = ID
        self.port = port
        self.id_table = IdTable()
        self.parent = None
        self.left_child = None
        self.right_child = None
        self.left_tree = []
        self.right_tree = []
        self.server_socket = Server(consts.DEFAULT_IP, port, self.handler, logger)

    def handler(self, conn: socket.socket):
        logger.debug("handling new client")
        with conn:
            try:
                data = conn.recv(consts.BUFFER_SIZE).decode("ascii")
                if not data:
                    print("not data")
                    return
                data = ast.literal_eval(data)
                logger.debug(f"received message is:{data}")
                packet = Packet(**data)

                if packet.p_type == PacketType.CONNECTION_REQUEST:
                    self.connection_request_handle(packet)
                    self.advertise_parent(packet.src_id)
                elif packet.p_type == PacketType.CONNECTION_RESPONSE:
                    pass
                elif packet.p_type == PacketType.MESSAGE:
                    pass
                elif packet.p_type == PacketType.ROUTING_REQUEST:
                    self.routing_request_handle(packet)
                elif packet.p_type == PacketType.ROUTING_RESPONSE:
                    pass
                elif packet.p_type == PacketType.PARENT_ADVERTISE:
                    self.advertise_parent_handle(packet)
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
            self.right_child = (int(p.src_id), int(p.data))
            self.right_tree.append(int(p.src_id))
        else:
            self.left_child = (int(p.src_id), int(p.data))
            self.left_tree.append(int(p.src_id))

    def routing_request_handle(self, p: Packet):
        dest_id, dest_port = self.id_table.get_next_hop(p.dest_id)
        if p.dest_id == self.id:
            sent_packet = Packet(PacketType.ROUTING_RESPONSE.value, self.id, p.src_id, f"{self.id}")
            _, dest_port = self.id_table.get_next_hop(p.src_id)
        elif dest_id == consts.NEXT_HOP_NOT_FOUND:
            sent_packet = Packet(PacketType.DESTINATION_NOT_FOUND.value, self.id, p.src_id,
                                 consts.DEST_NOT_FOUND.format(id_dest=p.dest_id))
            _, dest_port = self.id_table.get_next_hop(p.src_id)
        else:
            sent_packet = p
        client.send(consts.DEFAULT_IP, int(dest_port), sent_packet)

    def advertise_parent(self, src_id: int):
        if self.parent[0] == consts.ROOT_PARENT_PORT:
            return
        advertise_parent_packet = Packet(PacketType.PARENT_ADVERTISE.value, self.id, self.parent[0], f"{src_id}")
        client.send(consts.DEFAULT_IP, int(self.parent[1]), advertise_parent_packet)

    def advertise_parent_handle(self, p: Packet):
        if p.src_id == self.left_child[0]:
            self.left_tree.append(int(p.data))
        elif p.src_id == self.right_child[0]:
            self.right_tree.append(int(p.data))
        # send packet to parent
        if self.parent[0] == consts.ROOT_PARENT_ID:
            return
        advertise_parent_packet = Packet(PacketType.PARENT_ADVERTISE.value, self.id, self.parent[0], f"{p.data}")
        client.send(consts.DEFAULT_IP, int(self.parent[1]), advertise_parent_packet)


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
    if pid == consts.ROOT_PARENT_ID:
        return
    p = Packet(PacketType.CONNECTION_REQUEST.value, myid, pid, str(myport))
    client.send(consts.DEFAULT_IP, pport, p)


def main():
    cmd = input()
    [(id, port)] = consts.CONNECT_REGEX.findall(cmd)
    p = network_init(id, port)
    [(pid, pport)] = consts.CONNECT_ACCEPT_REGEX.findall(p.data)
    node = Node(int(id), int(port))
    if int(pid) == -1 and int(pport) == -1:
        node.parent = (consts.ROOT_PARENT_ID, consts.ROOT_PARENT_PORT)
    else:
        node.parent = (int(pid), int(pport))

    family_meeting(node.id, node.port, int(node.parent[0]), int(node.parent[1]))

    node.server_socket.listen()


if __name__ == "__main__":
    main()
