import logging
import socket
import time
import re
from node import Node
import constants as consts
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


def send_route_message(dest_id: int, node: Node):
    sent_packet = Packet(PacketType.ROUTING_REQUEST.value, node.id, int(dest_id), f"")
    send(consts.DEFAULT_IP, node.id_table.get_next_hop(dest_id)[1], sent_packet)


def handle_user_commands(node: Node):
    while True:
        cmd = input().strip()
        if consts.ROUTE_REGEX.match(cmd):
            send_route_message(int(re.findall(consts.ROUTE_REGEX, cmd)[0]), node)
        if consts.ADVERTISE_REGEX.match(cmd):
            pass
        if consts.SALAM_REGEX.match(cmd):
            pass
        if consts.CHAT_REGEX.match(cmd):
            pass
        if consts.START_CHAT_REGEX.match(cmd):
            pass
        if consts.REQ_FOR_CHAT_REGEX.match(cmd):
            pass
        if consts.ASK_JOIN_CHAT_REGEX.match(cmd):
            pass
        if consts.YES_REGEX.match(cmd):
            pass
        if consts.SET_NAME_REGEX.match(cmd):
            pass
        if consts.EXIT_CHAT_REGEX.match(cmd):
            pass
        if consts.FILTER_REGEX.match(cmd):
            dir, src, dst, action = consts.FILTER_REGEX.findall(cmd)
            if src == "*":
                src = None
            if dst == "*":
                dst = None
            node.set_fw_rule(dir, src, dst, action)
        if consts.FW_CHAT_REGEX.match(cmd):
            pass
