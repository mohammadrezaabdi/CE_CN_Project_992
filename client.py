import logging
import socket
import threading
import time
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


def handle_user_commands():
    while True:
        cmd = input().strip()
        if consts.ROUTE_REGEX.match(cmd):
            pass
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
            pass
        if consts.FW_CHAT_REGEX.match(cmd):
            pass
