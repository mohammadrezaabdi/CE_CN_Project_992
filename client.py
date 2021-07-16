import ast
import logging
import re
import socket
import time
import constants as consts
from node import Node
from packet import *

logger = logging.getLogger("client")


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
    while True:
        cmd = input().strip().upper()
        if consts.ROUTE_REGEX.match(cmd):
            node.send_packet_util(PacketType.ROUTING_REQUEST, int(re.findall(consts.ROUTE_REGEX, cmd)[0]))
        elif consts.ADVERTISE_REGEX.match(cmd):
            node.send_packet_util(PacketType.ADVERTISE, int(consts.ADVERTISE_REGEX.findall(cmd)[0]))
        elif consts.ADVERTISE_ALL_REGEX.match(cmd):
            node.send_packet_util(PacketType.ADVERTISE, consts.SEND_ALL)
        elif consts.SALAM_REGEX.match(cmd):
            node.send_packet_util(PacketType.MESSAGE, int(consts.SALAM_REGEX.findall(cmd)[0]), consts.SALAM)
        elif consts.START_CHAT_REGEX.match(cmd):
            elems = consts.START_CHAT_REGEX.findall(cmd)
            ids = ast.literal_eval(f"[{elems[0][1]}]")
            node.chat.init_chat(elems[0][0], ids)
        elif consts.ASK_JOIN_CHAT_REGEX.match(cmd):
            pass
        elif consts.YES_REGEX.match(cmd):
            pass
        elif consts.SET_NAME_REGEX.match(cmd):
            pass
        elif consts.EXIT_CHAT_REGEX.match(cmd):
            pass
        elif consts.FILTER_REGEX.match(cmd):
            [(dir, src, dst, action)] = consts.FILTER_REGEX.findall(cmd)
            if src == "*":
                src = consts.SEND_ALL
            if dst == "*":
                dst = consts.SEND_ALL
            node.set_fw_rule(dir, src, dst, action)
        elif consts.FW_CHAT_REGEX.match(cmd):
            pass
        elif consts.SHOW_KNOWN_CLIENTS_REGEX.match(cmd):
            print(node.id_table.known_hosts)
