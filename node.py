import ast
import logging
import socket
import threading
from dataclasses import dataclass
from enum import Enum, IntEnum
from threading import Lock

import client
import constants as consts
import log
import packet
from packet import Packet, PacketType
from server import Server

log.init()
logger = logging.getLogger("node")


class FWAction(Enum):
    ACCEPT = 0
    DROP = 1


@dataclass
class IdRoute:
    def __init__(self, dest: int, next_hop: tuple[int, int], state: FWAction = FWAction.ACCEPT):
        self.dest = dest
        self.next_hop = next_hop
        self.state = state


@dataclass
class FWRule:
    def __init__(self, src=consts.SEND_ALL, dst=consts.SEND_ALL, p_type=PacketType.ALL,
                 action: FWAction = FWAction.DROP):
        self.src = src
        self.dst = dst
        self.p_type = p_type
        self.action = action


class IdTable:
    def __init__(self):
        self.default_gateway: tuple[int, int] = tuple()
        self.routing_table: list[IdRoute] = []
        self.known_hosts: set[int] = set()
        self.fw_rules: list[FWRule] = []

    def get_next_hop(self, dest_id: int):  # todo Mahdi ghaznavi??
        if dest_id not in self.known_hosts:
            return consts.NEXT_HOP_NOT_FOUND
        results = [route for route in self.routing_table if route.dest == dest_id and route.state == FWAction.ACCEPT]
        if results:
            return results[0].next_hop
        return self.default_gateway

    def add_entry(self, dest_id: int, next_hop: (int, int)):
        results = [route.next_hop for route in self.routing_table if route.dest == dest_id]
        if next_hop in results:
            raise Exception("there is a loop")
        self.routing_table.append(IdRoute(dest_id, next_hop))
        self.known_hosts.add(dest_id)

    def set_state(self, dest_id: int, state: FWAction):
        for route in self.routing_table:
            if route.dest == dest_id:
                route.state = state

    def fw_allows(self, p: Packet) -> bool:
        src = p.src_id
        dst = p.dest_id
        p_type = p.p_type
        # the & are for handling * in rules
        rules = [rule for rule in self.fw_rules if
                 rule.src & src == src and rule.dst & dst == dst and rule.p_type & p_type == p_type]
        if rules:
            return (True, False)[rules[-1].action == FWAction.DROP]
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
        self.chat: Chat = Chat(self)

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

                # firewall check
                if not self.id_table.fw_allows(packet):
                    return

                if self.id == packet.dest_id or packet.dest_id == consts.SEND_ALL:
                    self.id_table.known_hosts.add(packet.src_id)

                if packet.p_type == PacketType.CONNECTION_REQUEST:
                    self.connection_request_handle(packet)
                    self.advertise_parent(packet.src_id)
                elif packet.p_type == PacketType.MESSAGE:
                    self.message_handle(packet)
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

    def set_fw_rule(self, dir, src, dst, action, p_type=PacketType.ALL):
        src = int(src)
        dst = int(dst)
        if dir == "INPUT":
            dst = self.id
        elif dir == "OUTPUT":
            src = self.id
        self.id_table.fw_rules.append(FWRule(src=src, dst=dst, p_type=p_type, action=FWAction[action]))

    def set_parent(self, pid: int, pport: int):
        id, port = int(pid), int(pport)
        self.parent = (id, port)
        self.id_table.add_entry(id, self.parent)
        self.id_table.default_gateway = (id, port)

    def send(self, p: Packet, port=None):
        # firewall check
        if not self.id_table.fw_allows(p):
            return
        if not port:
            try:
                port = int(self.id_table.get_next_hop(p.dest_id)[1])
            except Exception as e:
                print(consts.UNKNOWN_DEST.format(id_dest=p.dest_id))

                p = Packet(PacketType.DESTINATION_NOT_FOUND.value, self.id, p.src_id,
                           consts.DEST_NOT_FOUND.format(id_dest=p.dest_id))
                port = int(self.id_table.get_next_hop(p.dest_id)[1])
        client.send(consts.DEFAULT_IP, port, p)

    def send_packet_util(self, p_type: PacketType, dest_id: int, data: str = ""):
        sent_packet = Packet(p_type.value, self.id, int(dest_id), data)
        self.send_packet(sent_packet)

    def send_packet(self, p: Packet):
        if int(p.dest_id) == consts.SEND_ALL:
            hops = set([route.next_hop for route in self.id_table.routing_table])
            hops.discard(self.id_table.get_next_hop(p.src_id))
            hops.discard((self.id, self.port))
            for hop in hops:
                self.send(p, port=int(hop[1]))
            return
        self.send(p)

    def advertise_handle(self, p: Packet):
        if p.dest_id == self.id or p.src_id == self.id:
            return
        self.send_packet(p)

    def message_handle(self, p: Packet):
        if p.dest_id == consts.SEND_ALL:
            self.send_packet(p)
        if p.dest_id == self.id or p.dest_id == consts.SEND_ALL:
            if consts.SALAM_RAW_REGEX.match(p.data):
                print(consts.SALAM, f"from {p.src_id}")
                p = Packet(PacketType.MESSAGE.value, self.id, p.src_id, consts.SALAM_RESPONSE)
            elif consts.SALAM_RESPONSE_REGEX.match(p.data):
                print(consts.SALAM_RESPONSE, f"from {p.src_id}")
                return
            elif consts.REQ_FOR_CHAT_REGEX.match(p.data):
                if self.chat.state != ChatState.INACTIVE:
                    return
                elems = consts.REQ_FOR_CHAT_REGEX.findall(p.data)
                ids = ast.literal_eval(f"[{elems[0][1]}]")
                self.chat.start_chat(elems[0][0], ids)
                return
            elif consts.SET_NAME_REGEX.match(p.data) and self.chat.state != ChatState.INACTIVE:
                if not self.chat.is_in_your_chat(p, when_start=True):  # check if this packet belongs to your chat
                    return
                elems = consts.SET_NAME_REGEX.findall(p.data)
                self.chat.chat_list[int(elems[0][0])] = elems[0][1]
                print(consts.JOINED_CHAT.format(chat_name=elems[0][1], id=elems[0][0]))
                return
            elif consts.EXIT_CHAT_REGEX.match(p.data) and self.chat.state != ChatState.INACTIVE:
                if not self.chat.is_in_your_chat(p):  # check if this packet belongs to your chat
                    return
                id = int(consts.EXIT_CHAT_REGEX.findall(p.data)[0][0])
                name = self.chat.chat_list.pop(id)
                print(consts.LEFT_CHAT.format(chat_name=name, id=id))
                return
            elif consts.SHOW_MSG_REGEX.match(p.data) and self.chat.state == ChatState.ACTIVE:
                if not self.chat.is_in_your_chat(p):  # check if this packet belongs to your chat
                    return
                raw = consts.SHOW_MSG_REGEX.findall(p.data)[0]
                src_name = self.chat.chat_list[int(p.src_id)]
                print(consts.SHOW_MSG.format(chat_name=src_name, message=raw))
                return
            else:
                return
        self.send_packet(p)


class ChatState(IntEnum):
    INACTIVE = 0
    PENDING = 1
    ACTIVE = 2
    DISABLE = 3


class Chat:
    def __init__(self, node: Node):
        self.state: ChatState = ChatState.INACTIVE
        self.owner_name = ""
        self.name = ""
        self.node = node
        self.chat_list: dict[int, str] = {}

    def init_chat(self, owner_name: str, ids: list):
        self.owner_name = owner_name
        self.name = owner_name
        self.state = ChatState.ACTIVE
        self.chat_list[self.node.id] = owner_name
        for id in ids[1:]:
            self.chat_list[int(id)] = ""
        self.send_to_chat_list(consts.REQ_FOR_CHAT.format(name=owner_name, ids=(", ".join(map(str, ids))).strip()))

    def start_chat(self, owner_name: str, ids: list):
        self.owner_name = owner_name
        self.state = ChatState.PENDING
        self.chat_list[ids[0]] = owner_name

        for id in ids[1:]:
            _id = int(id)
            self.chat_list[_id] = ""
            self.node.id_table.known_hosts.add(_id)

        while True:
            print(consts.ASK_JOIN_CHAT.format(chat_name=owner_name, id=ids[0]))
            client.cmd_sema.acquire()
            is_join = client.chat_input
            if consts.YES_REGEX.match(is_join):
                print(consts.CHOOSE_NAME_MSG)
                client.cmd_sema.acquire()
                name = client.chat_input
                self.name = name
                self.chat_list[self.node.id] = name
                self.state = ChatState.ACTIVE
                self.send_to_chat_list(consts.SET_NAME.format(id=self.node.id, chat_name=name))
                return
            elif consts.NO_REGEX.match(is_join):
                self.clear_chat()
                return

    def send_to_chat_list(self, data: str, is_broadcast: bool = True):
        if self.state == ChatState.INACTIVE:
            return
        for id, name in self.chat_list.items():
            if int(id) == self.node.id or (not is_broadcast and name == ""):
                continue
            p = Packet(PacketType.MESSAGE.value, self.node.id, id, data)
            self.node.send_packet(p)

    def clear_chat(self):
        self.state = ChatState.INACTIVE
        self.owner_name = ""
        self.name = ""
        self.chat_list.clear()

    def is_in_your_chat(self, p: Packet, when_start: bool = False):
        return int(p.src_id) in self.chat_list.keys() and (when_start or self.chat_list[int(p.src_id)] != "")


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
