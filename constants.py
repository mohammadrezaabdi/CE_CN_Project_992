import re

MESSAGE = "MESSAGE"
ROUTING_REQUEST = "ROUTING_REQUEST"
ROUTING_RESPOSE = "ROUTING_RESPOSE"
PARENT_ADEVRTISE = "PARENT_ADEVRTISE"
ADVERTISE = "ADVERTISE"
DESTINATION_NOT_FOUND = "DESTINATION_NOT_FOUND"
CONNECTION_REQUEST = "CONNECTION_REQUEST"
CONNECTION_RESPONE = "CONNECTION_RESPONE"

packet_type = {
    MESSAGE: 0,
    ROUTING_REQUEST: 10,
    ROUTING_RESPOSE: 11,
    PARENT_ADEVRTISE: 20,
    ADVERTISE: 21,
    DESTINATION_NOT_FOUND: 31,
    CONNECTION_REQUEST: 41,
    CONNECTION_RESPONE: 42,
}

# usage --> CONNECT.format(id = 10 , port = 20)
CONNECT = "CONNECT AS {id} ON PORT {port}"
CONNECT_REGEX = re.compile(r"^CONNECT AS (\d+) ON PORT (\d+)$")

CONNECT_REQUEST = "{id} REQUESTS FOR CONNECTING TO NETWORK ON PORT {port}"
CONNECT_REQUEST_REGEX = re.compile(
    r"^(\d+) REQUESTS FOR CONNECTING TO NETWORK ON PORT (\d+)$"
)

CONNECT_ACCEPT = "CONNECT TO {id_parent} WITH PORT {port_parent}"
CONNECT_ACCEPT_REGEX = re.compile(r"^CONNECT TO (-?\d+) WITH PORT (-?\d+)$")

SHOW_KNOWN_CLIENTS = "SHOW KNOWN CLIENTS"
SHOW_KNOWN_CLIENTS_REGEX = re.compile(r"^SHOW KNOWN CLIENTS$")

UNKNOWN_DEST = "Unknown destination {id_dest}"

DEST_NOT_FOUND = "DESTINATION {id_dest} NOT FOUND"
DEST_NOT_FOUND_REGEX = re.compile(r"^DESTINATION (-?\d+) NOT FOUND$")

ROUTE = "ROUTE {id}"
ROUTE_REGEX = re.compile(r"^ROUTE (-?\d+)$")

ADVERTISE = "Advertise {id}"
ADVERTISE_REGEX = re.compile(r"^ADVERTISE (-?\d+)$")

SALAM = "Salam Salam Sad Ta Salam"
SALAM_REGEX = re.compile(r"^Salam Salam Sad Ta Salam$")

SALAM_RESPONSE = "Hezaro Sisad Ta Salam"
SALAM_RESPONSE_REGEX = re.compile(r"^Hezaro Sisad Ta Salam$")

CHAT_REGEX = re.compile(r"^CHAT: $")

# START_CHAT.format(name="chat1", ids=", ".join(map(str,[3, 2, 5])))
START_CHAT = "START CHAT {name}: {ids}"
START_CHAT_REGEX = re.compile(r"^START CHAT (\w+): (.+)$")

REQ_FOR_CHAT = "REQUESTS FOR STARTING CHAT WITH {name}: {ids}"
REQ_FOR_CHAT_REGEX = re.compile(r"^REQUESTS FOR STARTING CHAT WITH (\w+): (.+)$")

ASK_JOIN_CHAT = (
    "{chat_name} with id {id} has asked you to join a chat. Would you like to join?"
)
ASK_JOIN_CHAT_REGEX = re.compile(
    r"^(\w+) with id (-?\d+) has asked you to join a chat. Would you like to join?$"
)

YES = "Y"
YES_REGEX = re.compile(r"^Y$")

YES = "N"
YES_REGEX = re.compile(r"^N$")

CHOOSE_NAME_MSG = "Choose a name for yourself"

SET_NAME = "{id} :{chat_name}"
SET_NAME_REGEX = re.compile(r"(-?\d+) :(\w+)$")

JOINED_CHAT = "{chat_name}({id}) was joind to the chat."

SHOW_MSG = "{chat_name}: {message}"
SHOW_MSG_REGEX = re.compile(r"^(\w+): (.*)$")

EXIT_CHAT_MSG = "EXIT CHAT"

EXIT_CHAT = "EXIT CHAT {id}"
EXIT_CHAT_REGEX = re.compile(r"^EXIT CHAT (-?\d+)$")

LEFT_CHAT = "{chat_name}({id}) left the chat."
LEFT_CHAT_REGEX = re.compile(r"^(\w+)((-?\d+)) left the chat.$")

FILTER = "FILTER {direction} {src_id} {dest_id} {type} {action}"
FILTER_REGEX = re.compile(
    r"^FILTER (INPUT|OUTPUT|FORWARD) ([-?\d+|*]) ([-?\d+|*]) (ACCEPT|DROP)$"
)

FW_CHAT = "FW CHAT {action}"
FW_CHAT_REGEX = re.compile(r"^FW CHAT (ACCEPT|DROP)$")

INPUT = "INPUT"
OUTPUT = "OUTPUT"
FORWARD = "FORWARD"

ACCEPT = "ACCEPT"
DROP = "DROP"

CHAT_IS_DISABLE = "Chat is disabled. Make sure the firewall allows you to chat."

LOG_TEMPLATE = "{type} Packet from {id_src} to {id_dest}"

MANAGER_IP = "127.0.0.1"
MANAGER_PORT = 8559
DEFAULT_IP = MANAGER_IP

BUFFER_SIZE = 1024

ROOT_PARENT_ID = -2
ROOT_PARENT_PORT = -2

NEXT_HOP_NOT_FOUND = -3

SEND_ALL = -1
