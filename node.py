class IdTable:
    pass


class Node:
    def __init__(self, id, port):
        self.id = id
        self.port = port
        self.id_table = IdTable()

