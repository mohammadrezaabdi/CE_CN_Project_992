import ast
import logging
import re
import socket

import constants as consts
import globals
from chat import Chat, ChatState
from constants import print_green, print_bold
from firewall import FWAction, FWRule
from packet import Packet, PacketType
from server import Server
from table import IdTable

logger = logging.getLogger("node")


class Node:
    def __init__(self, ID, port):
        self.id = int(ID)
        self.port = port
        self.id_table = IdTable(self.id)
        self.left_child = None
        self.right_child = None
        self.parent = None
        self.server_socket = Server(consts.DEFAULT_IP, port, self.packet_receive_handler, logger)
        self.id_table.add_entry(ID, (ID, port))
        self.chat: Chat = Chat()

    def set_parent(self, pid: int, pport: int):
        id, port = int(pid), int(pport)
        self.parent = (id, port)
        self.id_table.add_entry(id, self.parent)
        self.id_table.default_gateway = (id, port)

    def packet_receive_handler(self, conn: socket.socket):
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

                print_green(
                    consts.LOG_TEMPLATE.format(type=packet.p_type, id_src=packet.src_id, id_dest=packet.dest_id))
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
        self.__send(sent_packet)

    def advertise_handle(self, p: Packet):
        if p.dest_id == self.id or p.src_id == self.id:
            return
        self.send_packet(p)

    def advertise_parent(self, src_id: int):
        if self.parent[0] == consts.ROOT_PARENT_ID:
            return
        advertise_parent_packet = Packet(PacketType.PARENT_ADVERTISE.value, self.id, self.parent[0], f"{src_id}")
        self.__send(advertise_parent_packet, port=int(self.parent[1]))

    def advertise_parent_handle(self, p: Packet):
        if p.src_id == self.left_child[0]:
            self.id_table.add_entry(int(p.data), self.left_child)
        elif p.src_id == self.right_child[0]:
            self.id_table.add_entry(int(p.data), self.right_child)
        # send packet to parent
        if self.parent[0] == consts.ROOT_PARENT_ID:
            return
        advertise_parent_packet = Packet(PacketType.PARENT_ADVERTISE.value, self.id, self.parent[0], f"{p.data}")
        self.__send(advertise_parent_packet, port=int(self.parent[1]))

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
        self.__send(p)

    def message_handle(self, p: Packet):
        if p.dest_id == consts.SEND_ALL:
            self.send_packet(p)
        if p.dest_id == self.id or p.dest_id == consts.SEND_ALL:
            if consts.SALAM_RAW_REGEX.match(p.data):
                print_bold(consts.SALAM)
                p = Packet(PacketType.MESSAGE.value, self.id, p.src_id, consts.SALAM_RESPONSE)
            elif consts.SALAM_RESPONSE_REGEX.match(p.data):
                print_bold(consts.SALAM_RESPONSE)
                return
            elif consts.REQ_FOR_CHAT_REGEX.match(p.data):
                if self.chat.state != ChatState.INACTIVE:
                    return
                elems = consts.REQ_FOR_CHAT_REGEX.findall(p.data)
                ids = ast.literal_eval(f"[{elems[0][1]}]")
                self.id_table.known_hosts.update(ids)
                id_ports = [(id, self.id_table.get_next_hop(id)[1]) for id in ids if
                            self.id_table.get_next_hop(id, src_id=self.id) != consts.NEXT_HOP_NOT_FOUND]

                self.chat.start_chat(elems[0][0], self.id, id_ports)
                return
            elif consts.SET_NAME_REGEX.match(p.data) and self.chat.state != ChatState.INACTIVE:
                if not self.chat.is_in_your_chat(p, when_start=True):  # check if this packet belongs to your chat
                    return
                elems = consts.SET_NAME_REGEX.findall(p.data)
                self.chat.chat_list[int(elems[0][0])] = elems[0][1]
                if self.chat.state == ChatState.ACTIVE:
                    print(consts.JOINED_CHAT.format(chat_name=elems[0][1], id=elems[0][0]))
                return
            elif consts.EXIT_CHAT_REGEX.match(p.data) and self.chat.state != ChatState.INACTIVE:
                if not self.chat.is_in_your_chat(p):  # check if this packet belongs to your chat
                    return
                id = int((consts.EXIT_CHAT_REGEX.findall(p.data)[0],)[0])
                name = self.chat.chat_list.pop(id)
                if self.chat.state == ChatState.ACTIVE:
                    print(consts.LEFT_CHAT.format(chat_name=name, id=id))
                return
            elif consts.SHOW_MSG_REGEX.match(p.data) and self.chat.state == ChatState.ACTIVE:
                if not self.chat.is_in_your_chat(p):  # check if this packet belongs to your chat
                    return
                raw = consts.SHOW_MSG_REGEX.findall(p.data)[0]
                src_name = self.chat.chat_list[int(p.src_id)]
                print_bold(consts.SHOW_MSG.format(chat_name=src_name, message=raw))
                return
            else:
                return
        self.send_packet(p)

    def set_fw_rule(self, dir: str, src: int, dst: int, action: FWAction, p_type: PacketType = PacketType.ALL):
        src = int(src)
        dst = int(dst)
        if dir == "INPUT":
            dst = self.id
        elif dir == "OUTPUT":
            src = self.id
        self.id_table.fw_rules.append(FWRule(src=src, dst=dst, p_type=p_type, action=FWAction[action]))

    def send_packet(self, p: Packet):
        if int(p.dest_id) == consts.SEND_ALL:
            hops = set([route.next_hop for route in self.id_table.routing_table])
            hops.discard(self.id_table.get_next_hop(p.src_id))
            hops.discard((self.id, self.port))
            for hop in hops:
                self.__send(p, port=int(hop[1]))
            return
        self.__send(p)

    def __send(self, p: Packet, port=None):
        # firewall check
        if not self.id_table.fw_allows(p):
            return
        if not port:
            try:
                port = int(self.id_table.get_next_hop(p.dest_id, src_id=p.src_id)[1])
            except Exception as e:
                if self.id != p.src_id:
                    port = self.id_table.default_gateway[1]
                else:
                    print(consts.UNKNOWN_DEST.format(id_dest=p.dest_id))
                    p = Packet(PacketType.DESTINATION_NOT_FOUND.value, self.id, p.src_id,
                               consts.DEST_NOT_FOUND.format(id_dest=p.dest_id))
                    port = int(self.id_table.get_next_hop(p.dest_id)[1])

        p.send(consts.DEFAULT_IP, port)

    def command_handler(self):
        while True:
            cmd = input().strip()
            if self.chat.state == ChatState.PENDING:
                globals.chat_input = cmd
                globals.cmd_sema.release()
                continue

            if self.chat.state == ChatState.ACTIVE:
                if consts.EXIT_CHAT_MSG_REGEX.match(cmd):
                    self.chat.send_to_chat_list(consts.EXIT_CHAT.format(id=self.id))
                    self.chat.clear_chat()
                else:
                    self.chat.send_to_chat_list(consts.CHAT + cmd, is_broadcast=False)

            elif consts.ROUTE_REGEX.match(cmd):
                self.send_packet(
                    Packet(PacketType.ROUTING_REQUEST.value, self.id, int(re.findall(consts.ROUTE_REGEX, cmd)[0])))

            elif consts.ADVERTISE_REGEX.match(cmd):
                self.send_packet(
                    Packet(PacketType.ADVERTISE.value, self.id, int(consts.ADVERTISE_REGEX.findall(cmd)[0])))

            elif consts.ADVERTISE_ALL_REGEX.match(cmd):
                self.send_packet(Packet(PacketType.ADVERTISE.value, self.id, consts.SEND_ALL))

            elif consts.SALAM_REGEX.match(cmd):
                self.send_packet(
                    Packet(PacketType.MESSAGE.value, self.id, int(consts.SALAM_REGEX.findall(cmd)[0]), consts.SALAM))

            elif consts.START_CHAT_REGEX.match(cmd):
                if self.chat.state == ChatState.DISABLE:
                    print(consts.CHAT_IS_DISABLE)
                    break
                elems = consts.START_CHAT_REGEX.findall(cmd)
                ids = ast.literal_eval(f"[{elems[0][1]}]")
                id_ports = [(id, self.id_table.get_next_hop(id)[1]) for id in ids if
                            self.id_table.get_next_hop(id, src_id=self.id) != consts.NEXT_HOP_NOT_FOUND]

                self.chat.init_chat(elems[0][0], id_ports)

            elif consts.FILTER_REGEX.match(cmd):
                [(dir, src, dst, p_type, action)] = consts.FILTER_REGEX.findall(cmd)
                if src == "*":
                    src = consts.SEND_ALL
                if dst == "*":
                    dst = consts.SEND_ALL
                self.set_fw_rule(dir, src, dst, action, p_type=PacketType(int(p_type)))

            elif consts.FW_CHAT_REGEX.match(cmd):
                [(action)] = consts.FW_CHAT_REGEX.findall(cmd)
                if FWAction[action] == FWAction.DROP:
                    self.chat.state = ChatState.DISABLE
                elif FWAction[action] == FWAction.ACCEPT:
                    self.chat.state = ChatState.INACTIVE
                self.set_fw_rule('FORWARD', consts.SEND_ALL, self.id, action, p_type=PacketType.MESSAGE)
                self.set_fw_rule('FORWARD', self.id, consts.SEND_ALL, action, p_type=PacketType.MESSAGE)

            elif consts.SHOW_KNOWN_CLIENTS_REGEX.match(cmd):
                print(self.id_table.known_hosts)
