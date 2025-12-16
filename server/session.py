import time

class Session:
    def __init__(self, sid, addr):
        self.sid = sid
        self.addr = addr
        self.last_seen = time.time()
        self.last_seq = -1

    def touch(self):
        self.last_seen = time.time()

    def valid_seq(self, seq):
        if seq <= self.last_seq:
            return False
        self.last_seq = seq
        return True

    def expired(self, timeout):
        return time.time() - self.last_seen > timeout

    def migrate(self, addr):
        self.addr = addr
