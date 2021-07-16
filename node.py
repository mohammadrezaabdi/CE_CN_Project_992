import ast
import logging
import socket
import threading
from enum import Enum
from typing import Any

import client
import constants as consts
import log
import packet
from packet import Packet, PacketType
from server import Server

log.init()
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
        # todo known chat
        self.default_gateway: tuple[int, int] = tuple()
        self.routing_table: list[IdRoute] = []  # todo dict
        self.known_hosts: set[int] = set()
        self.fw_table: list[tuple[Any, Any, FWState]] = []

    def get_next_hop(self, dest_id: int):
        if dest_id not in self.known_hosts:
            return consts.NEXT_HOP_NOT_FOUND
        results = [route for route in self.routing_table if route.dest == dest_id and route.state == FWState.ACCEPT]
        if results:
            return results[0].next_hop
        return self.default_gateway

    def add_entry(self, dest_id: int, next_hop: (int, int)):
        results = [route.next_hop for route in self.routing_table if route.dest == dest_id]
        if next_hop in results:
            raise Exception("there is a loop")
        self.routing_table.append(IdRoute(dest_id, next_hop))
        self.known_hosts.add(dest_id)

    def set_state(self, dest_id: int, state: FWState):
        for route in self.routing_table:
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
        self.id_table.add_entry(ID, (ID, port))

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
                elif packet.p_type == PacketType.ADVERTISE:
                    self.advertise_handle(packet)

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
            self.id_table.known_hosts.add(p.src_id)
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
        prev_hop_id = int(self.id_table.get_next_hop(p.src_id)[0])
        if not (is_not_found or int(self.id) == int(p.dest_id) == prev_hop_id):
            if prev_hop_id == self.parent[0]:
                data = str(self.id) + ' <- ' + data
            else:
                data = str(self.id) + ' -> ' + data
        if int(p.dest_id) == int(self.id):
            print(data)
            return
        p.data = data
        self.send(p)

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

    def set_parent(self, pid: int, pport: int):
        id, port = int(pid), int(pport)
        self.parent = (id, port)
        self.id_table.add_entry(id, self.parent)
        self.id_table.default_gateway = (id, port)

    def send(self, p: Packet, port=None):
        if not self.id_table.fw_allows(p):
            return
        if not port:
            try:
                port = int(self.id_table.get_next_hop(p.dest_id)[1])
            except Exception as e:
                print(consts.DEST_NOT_FOUND.format(id_dest=p.dest_id))

                p = Packet(PacketType.DESTINATION_NOT_FOUND.value, self.id, p.src_id,
                           consts.DEST_NOT_FOUND.format(id_dest=p.dest_id))
                port = int(self.id_table.get_next_hop(p.dest_id)[1])
        client.send(consts.DEFAULT_IP, port, p)

    def send_packet(self, p_type: PacketType, dest_id: int, data: str = ""):
        sent_packet = Packet(p_type.value, self.id, int(dest_id), data)
        if dest_id == consts.SEND_ALL:
            hops = set([route.next_hop for route in self.id_table.routing_table])
            for hop in hops:
                self.send(sent_packet, port=int(hop[1]))
            return

        self.send(sent_packet)

    def advertise_handle(self, p: Packet):
        if p.dest_id == self.id or p.src_id == self.id:
            self.id_table.known_hosts.add(p.src_id)
            return

        if p.dest_id == consts.SEND_ALL:
            self.id_table.known_hosts.add(p.src_id)
            hops = set([route.next_hop for route in self.id_table.routing_table])
            hops.remove(self.id_table.get_next_hop(p.src_id))
            hops.remove((self.id, self.port))
            for hop in hops:
                self.send(p, port=hop[1])
            return

        self.send(p)


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
    try:
        [(id, port)] = consts.CONNECT_REGEX.findall(cmd)
    except Exception as e:
        [(id)] = consts.CONNECT_PORT_LESS_REGEX.findall(cmd)
        port = 10000 + int(id) * 10

    p = network_init(id, port)
    [(pid, pport)] = consts.CONNECT_ACCEPT_REGEX.findall(p.data)
    node = Node(int(id), int(port))
    if int(pid) == -1 and int(pport) == -1:
        node.parent = (consts.ROOT_PARENT_ID, consts.ROOT_PARENT_PORT)
    else:
        node.set_parent(pid, pport)

    family_meeting(node.id, node.port, int(node.parent[0]), int(node.parent[1]))

    t = threading.Thread(target=client.handle_user_commands, args=(node,))
    t.start()

    node.server_socket.listen()


if __name__ == "__main__":
    main()
