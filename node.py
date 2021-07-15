import socket
import threading
import logging

import packet
from server import Server
import constants as consts
from packet import Packet, PacketType
import client
import ast

logger = logging.getLogger("node")


class IdTable:
    def __init__(self):
        self.table: dict[int, tuple[int, int]] = {}

    def get_next_hop(self, dest_id: int):
        if dest_id not in self.table:
            return consts.NEXT_HOP_NOT_FOUND
        return self.table[dest_id]

    def add_entry(self, dest_id: int, next_hop: (int, int)):
        if dest_id in self.table and self.table[dest_id] != next_hop:
            raise Exception("there is a loop")
        self.table[dest_id] = next_hop


class Node:
    def __init__(self, ID, port):
        self.id = ID
        self.port = port
        self.id_table = IdTable()
        self.left_child = None
        self.right_child = None
        self.parent = None
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
                    self.routing_response_handle(packet, False)
                elif packet.p_type == PacketType.PARENT_ADVERTISE:
                    self.advertise_parent_handle(packet)
                elif packet.p_type == PacketType.DESTINATION_NOT_FOUND:
                    self.routing_response_handle(packet, True)

            except Exception as e:
                raise Exception(e)

    def connection_request_handle(self, p: Packet):
        # from new child
        if self.left_child:
            self.right_child = (int(p.src_id), int(p.data))
            self.id_table.add_entry(int(self.right_child[0]), self.right_child)
        else:
            self.left_child = (int(p.src_id), int(p.data))
            self.id_table.add_entry(int(self.left_child[0]), self.left_child)

    def routing_request_handle(self, p: Packet):
        if p.dest_id == self.id:
            sent_packet = Packet(PacketType.ROUTING_RESPONSE.value, self.id, p.src_id, f"{self.id}")
            _, dest_port = self.id_table.get_next_hop(int(p.src_id))
        else:
            dest_id, dest_port = self.id_table.get_next_hop(p.dest_id)
            if dest_id == consts.NEXT_HOP_NOT_FOUND:
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
            self.id_table.add_entry(int(p.data), self.left_child)
        elif p.src_id == self.right_child[0]:
            self.id_table.add_entry(int(p.data), self.right_child)
        # send packet to parent
        if self.parent[0] == consts.ROOT_PARENT_ID:
            return
        advertise_parent_packet = Packet(PacketType.PARENT_ADVERTISE.value, self.id, self.parent[0], f"{p.data}")
        client.send(consts.DEFAULT_IP, int(self.parent[1]), advertise_parent_packet)

    def routing_response_handle(self, p: Packet, is_not_found=False):
        data = p.data
        if not is_not_found:
            if p.src_id == self.parent[0]:
                data = str(self.id) + ' <- ' + data
            else:
                data = str(self.id) + ' -> ' + data
        if p.dest_id == self.id:
            print(data)
            return
        route_packet = Packet(PacketType.ROUTING_RESPONSE, self.id, p.dest_id, data)
        client.send(consts.DEFAULT_IP, int(self.id_table.get_next_hop(p.dest_id)[1]), route_packet)


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
        node.id_table.add_entry(int(node.parent[0]), node.parent)

    family_meeting(node.id, node.port, int(node.parent[0]), int(node.parent[1]))

    t = threading.Thread(target=client.handle_user_commands, args=(node,))
    t.start()

    node.server_socket.listen()


if __name__ == "__main__":
    main()
