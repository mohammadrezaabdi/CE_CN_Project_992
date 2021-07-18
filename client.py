import ast
import logging
import re
import socket
import threading
import time

import constants as consts
from node import Node, ChatState, FWAction
from packet import *

logger = logging.getLogger("client")
cmd_sema = threading.Semaphore(0)
chat_input = ""


def send(ip: str, port: int, packet: Packet):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        while True:
            try:
                s.connect((ip, port))
                logger.info("connected to server successfully!")
                s.sendall(str(packet.__dict__).encode("ascii"))
                break
            except:
                time.sleep(1)
                logger.exception("waiting for server...")


def handle_user_commands(node: Node):
    global chat_input
    while True:
        cmd = input().strip().upper()  # todo not upper case
        if node.chat.state == ChatState.PENDING:
            cmd_sema.release()
            chat_input = cmd
            continue
        if consts.ROUTE_REGEX.match(cmd):
            node.send_packet_util(PacketType.ROUTING_REQUEST, int(re.findall(consts.ROUTE_REGEX, cmd)[0]))
        elif consts.ADVERTISE_REGEX.match(cmd):
            node.send_packet_util(PacketType.ADVERTISE, int(consts.ADVERTISE_REGEX.findall(cmd)[0]))
        elif consts.ADVERTISE_ALL_REGEX.match(cmd):
            node.send_packet_util(PacketType.ADVERTISE, consts.SEND_ALL)
        elif consts.SALAM_REGEX.match(cmd):
            node.send_packet_util(PacketType.MESSAGE, int(consts.SALAM_REGEX.findall(cmd)[0]), consts.SALAM)
        elif consts.START_CHAT_REGEX.match(cmd):
            if node.chat.state == ChatState.DISABLE:
                print(consts.CHAT_IS_DISABLE)
                break
            elems = consts.START_CHAT_REGEX.findall(cmd)
            ids = ast.literal_eval(f"[{elems[0][1]}]")
            id_ports = [(id, node.id_table.get_next_hop(id)[1]) for id in ids]
            node.chat.init_chat(elems[0][0], id_ports)
        elif consts.EXIT_CHAT_MSG_REGEX.match(cmd):
            node.chat.send_to_chat_list(consts.EXIT_CHAT.format(id=node.id))
            node.chat.clear_chat()
        elif consts.FILTER_REGEX.match(cmd):
            [(dir, src, dst, action)] = consts.FILTER_REGEX.findall(cmd)
            if src == "*":
                src = consts.SEND_ALL
            if dst == "*":
                dst = consts.SEND_ALL
            node.set_fw_rule(dir, src, dst, action)
        elif consts.FW_CHAT_REGEX.match(cmd):
            [(action)] = consts.FW_CHAT_REGEX.findall(cmd)
            if FWAction[action] == FWAction.DROP:
                node.chat.state = ChatState.DISABLE
            elif FWAction[action] == FWAction.ACCEPT:
                node.chat.state = ChatState.INACTIVE

            node.set_fw_rule('FORWARD', consts.SEND_ALL, consts.SEND_ALL, action, p_type=PacketType.MESSAGE)
        elif consts.SHOW_KNOWN_CLIENTS_REGEX.match(cmd):
            print(node.id_table.known_hosts)
        elif node.chat.state == ChatState.ACTIVE:
            node.chat.send_to_chat_list(consts.CHAT + cmd, is_broadcast=False)
