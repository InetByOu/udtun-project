import select, time, random
from tun import Tun
from udp import UDP
from crypto import crypt
from protocol import pack, unpack
from session import Session
from router import ip_dst
from config import *

sessions = {}
ip_map = {}

tun = Tun(TUN_NAME)
udp = UDP(SERVER_PORT)

while True:
    r,_,_ = select.select([tun, udp], [], [], 1)

    for s in r:
        if s == udp:
            data, addr = udp.recv()
            res = unpack(data)
            if not res:
                continue
            sid, seq, payload = res
            payload = crypt(payload, seq)

            sess = sessions.get(sid)
            if not sess:
                sess = Session(sid, addr)
                sessions[sid] = sess

            if not sess.valid_seq(seq):
                continue

            sess.migrate(addr)
            sess.touch()
            tun.write(payload)

        elif s == tun:
            pkt = tun.read()
            dst = ip_dst(pkt)
            if dst in ip_map:
                sess = ip_map[dst]
                sess.last_seq += 1
                enc = crypt(pkt, sess.last_seq)
                udp.send(pack(sess.sid, sess.last_seq, enc), sess.addr)

    for sid in list(sessions):
        if sessions[sid].expired(SESSION_TIMEOUT):
            del sessions[sid]
