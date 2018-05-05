#!/usr/bin/env python
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <src_ip> -j DROP

from scapy.all import *
import logging, time
from threading import Thread, Event

logger = logging.getLogger(__name__)

class TcpHandshake(threading.Thread):

    def __init__(self, target):
        self.seq = 0
        self.seq_next = 0
        self.target = target
        self.dst = iter(Net(target[0])).next()
        self.dport = target[1]
        self.sport = random.randrange(1024,2**16)
        self.ipid = random.randrange(0,2**16)
        self.l4 = IP(dst=target[0],id=self.ipid)/TCP(sport=self.sport, dport=self.dport, flags=0,
                                        seq=random.randrange(0,2**32),options=[('MSS',1460),('NOP',0),('NOP',0),('Timestamp',(0,0))])
        self.src = self.l4.src
        self.swin = self.l4[TCP].window
        self.dwin=1
        self.fullpayload=0

        self.ThreeWHS_Event=threading.Event()
        logger.debug("init: %s"%repr(target))

    def start(self):
        logger.debug("start")
        self.send_syn()

    def stopSniffing(self,pkt):
        if (pkt[TCP].flags & 0x3f == 0x11):
           return True

    def _sniff(self):
        def handle_recv(pkt):
            if pkt and pkt.haslayer(IP) and pkt.haslayer(TCP):
               if pkt[TCP].flags & 0x3f == 0x12:   	# SYN+ACK
                  logger.debug("RCV: SYN+ACK")
                  self.send_synack_ack(pkt)
                  self.ThreeWHS_Event.set()
               elif  pkt[TCP].flags & 4 != 0:      	# RST
                  logger.debug("RCV: RST")
                  raise Exception("RST")
               elif pkt[TCP].flags & 0x3f ==0x01:     	# FIN
                  logger.debug("RCV: FIN")
                  self.send_finack(pkt)
               elif pkt[TCP].flags & 0x3f == 0x11: 	# FIN+ACK
                  logger.debug("RCV: FIN+ACK")
                  self.send_finack(pkt)
               elif (pkt[TCP].flags & 0x3f == 0x18) or (pkt[TCP].flags & 0x3f == 0x19) or (pkt[TCP].flags & 0x3f == 0x10):
                  if pkt[TCP].flags & 0x3f == 0x19:
                     logger.debug("RCV: FIN+PSH+ACK")
                  elif pkt[TCP].flags & 0x3f == 0x10:
                     logger.debug("RCV: ACK")
                  else:
                     logger.debug("RCV: PSH+ACK")

                  self.l4[IP].id=self.ipid + 1
                  self.ipid = self.l4[IP].id
                  if pkt[TCP].flags & 0x3f == 0x19:
                     self.l4[TCP].flags = "FA"
                     self.l4[TCP].ack = pkt[TCP].seq + len(pkt[TCP].payload) + 1
                     self.l4[TCP].seq = pkt[TCP].ack
                     send(self.l4)
                     logger.debug("SND: FIN+ACK")

                  else:
                     self.l4[TCP].flags = "A"
                     self.l4[TCP].ack = pkt[TCP].seq + len(pkt[TCP].payload)
                     self.l4[TCP].seq = pkt[TCP].ack
                     send(self.l4)
                     logger.debug("SND: ACK")

        sniff(filter="src host %s and tcp src port %s"%(self.target[0],self.target[1]),prn=handle_recv,stop_filter=self.stopSniffing)

    def send_syn(self):
        logger.debug("SND: SYN")
        self.l4[TCP].flags = "S"
        self.seq_next = self.l4[TCP].seq + 1
        send(self.l4)
        self.l4[TCP].seq += 1

    def send_synack_ack(self, pkt):
        logger.debug("SND: SYN+ACK -> ACK")
        self.l4[IP].id=self.ipid + 1
        self.ipid = self.l4[IP].id
        self.l4[TCP].window=pkt[TCP].window
        self.l4[TCP].ack = pkt[TCP].seq+1
        self.l4[TCP].flags = "A"
        send(self.l4)

    def send_data(self, d):
        logger.debug("SND: DATA")
        self.l4[IP].id=self.ipid + 1
        self.ipid = self.l4[IP].id
        self.l4[TCP].flags = "PA"
        send(self.l4/d)
        self.l4[TCP].seq += len(d)

    def send_fin(self):
        logger.debug("SND: FIN")
        self.l4[IP].id=self.ipid + 1
        self.ipid = self.l4[IP].id
        self.l4[TCP].flags = "F"
        send(self.l4)
        self.l4[TCP].seq += 1

    def send_finack(self, pkt):
        logger.debug("SND: FIN+ACK")
        self.l4[IP].id=self.ipid + 1
        self.ipid = self.l4[IP].id
        self.l4[TCP].flags = "FA"
        self.l4[TCP].ack = pkt[TCP].seq+1
        send(self.l4)
        self.l4[TCP].seq += 1

    def send_ack(self, pkt):
        logger.debug("SND: ACK")
        self.l4[IP].id=self.ipid + 1
        self.ipid = self.l4[IP].id
        self.l4[TCP].flags = "A"
        self.l4[TCP].ack = pkt[TCP].seq+1
        send(self.l4)
        self.l4[TCP].seq += 1

    def launch_sniffer(self):
        logger.info("SniFFER THREAD STARTED!!!")
        t = Thread(target=self._sniff, name="SnifferThreadWithPktHandler")
        t.start()

if __name__=='__main__':
   logging.basicConfig(level=logging.DEBUG)
   logger.setLevel(logging.DEBUG)
   conf.verb = 0

   remote_host = ('oststrom.com',80)
   tcp_hs = TcpHandshake(remote_host)
   tcp_hs.launch_sniffer()
   tcp_hs.start()
   tcp_hs.ThreeWHS_Event.wait()
   if tcp_hs.ThreeWHS_Event.isSet():
      tcp_hs.ThreeWHS_Event.clear()
      tcp_hs.send_data("INTENTIONALLY BAD REQUEST FOR TESTING TCP_HANDSHAKE\r\n\r\n\r\n")
