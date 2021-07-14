
class Packet:

    def __init__(self, type: int, src_id: int, dest_id: int, data: str):
        self.type = type
        self.src_id = src_id
        self.dest_id = dest_id
        self.data = data
