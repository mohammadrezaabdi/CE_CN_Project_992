import socket
import threading
import logging
from typing import Any

import packet
from server import Server
import constants as consts
from packet import Packet, PacketType
import client
import ast
from enum import Enum

logger = logging.getLogger("node")


class FWState(Enum):
    ACCEPT = 0
    DROP = 1


class IdRoute:
    def __init__(self, dest: int, next_hop: tuple[int, int], state: FWState = FWState.ACCEPT):
        self.dest = dest
        self.next_hop = next_hop
        self.state = state


class IdTable:
    def __init__(self):
        self.table: list[IdRoute] = []
        self.fw_table: list[tuple[Any, Any, FWState]] = []

    def get_next_hop(self, dest_id: int):
        results = [route for route in self.table if route.dest == dest_id and route.state == FWState.ACCEPT]
        if results:
            return results[0].next_hop

        return consts.NEXT_HOP_NOT_FOUND

    def add_entry(self, dest_id: int, next_hop: (int, int)):
        results = [route.next_hop for route in self.table if route.dest == dest_id]
        if next_hop in results:
            raise Exception("there is a loop")

        self.table.append(IdRoute(dest_id, next_hop))

    def set_state(self, dest_id: int, state: FWState):
        for route in self.table:
            if route.dest == dest_id:
                route.state = state

    def fw_allows(self, p: Packet) -> bool:
        src = p.src_id
        dst = p.dest_id

        # both dst and src are valid ids
        rules = [rule for rule in self.fw_table if rule[0] == src and rule[1] == dst]
        if rules:
            return (True, False)[rules[0][2] == FWState.DROP]

        # src is match all
        rules = [rule for rule in self.fw_table if not rule[0] and rule[1] == dst]
        if rules:
            return (True, False)[rules[0][2] == FWState.DROP]

        # dst is match all
        rules = [rule for rule in self.fw_table if not rule[1] and rule[0] == src]
        if rules:
            return (True, False)[rules[0][2] == FWState.DROP]

        # dst and src are both match all
        rules = [rule for rule in self.fw_table if not rule[1] and not rule[0]]
        if rules:
            return (True, False)[rules[0][2] == FWState.DROP]
        return True


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

                if not self.id_table.fw_allows(packet):
                    return

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
        else:
            dest_id, _ = self.id_table.get_next_hop(p.dest_id)
            if dest_id == consts.NEXT_HOP_NOT_FOUND:
                sent_packet = Packet(PacketType.DESTINATION_NOT_FOUND.value, self.id, p.src_id,
                                     consts.DEST_NOT_FOUND.format(id_dest=p.dest_id))
            else:
                sent_packet = p
        self.send(sent_packet)

    def advertise_parent(self, src_id: int):
        if self.parent[0] == consts.ROOT_PARENT_ID:
            return
        advertise_parent_packet = Packet(PacketType.PARENT_ADVERTISE.value, self.id, self.parent[0], f"{src_id}")
        self.send(advertise_parent_packet, port=int(self.parent[1]))

    def advertise_parent_handle(self, p: Packet):
        if p.src_id == self.left_child[0]:
            self.id_table.add_entry(int(p.data), self.left_child)
        elif p.src_id == self.right_child[0]:
            self.id_table.add_entry(int(p.data), self.right_child)
        # send packet to parent
        if self.parent[0] == consts.ROOT_PARENT_ID:
            return
        advertise_parent_packet = Packet(PacketType.PARENT_ADVERTISE.value, self.id, self.parent[0], f"{p.data}")
        self.send(advertise_parent_packet, port=int(self.parent[1]))

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
        self.send(route_packet)

    def fw_drop(self, dest_id):
        self.id_table.set_state(dest_id, FWState.DROP)

    def fw_accept(self, dest_id):
        self.id_table.set_state(dest_id, FWState.ACCEPT)

    def set_fw_rule(self, dir, src, dst, action):
        if dir == "INPUT":
            self.id_table.fw_table.append((src, self.id, FWState[action]))
        elif dir == "OUTPUT":
            self.id_table.fw_table.append((self.id, dst, FWState[action]))
        elif dir == "FORWARD":
            self.id_table.fw_table.append((src, dst, FWState[action]))

    def send(self, p: Packet, port=None):
        if not self.id_table.fw_allows(p):
            return
        if not port:
            port = self.id_table.get_next_hop(p.dest_id)
        client.send(consts.DEFAULT_IP, port, p)


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


def family_meeting(my_id: int, my_port: int, pid: int, pport: int):
    if pid == consts.ROOT_PARENT_ID:
        return
    p = Packet(PacketType.CONNECTION_REQUEST.value, my_id, pid, str(my_port))
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
