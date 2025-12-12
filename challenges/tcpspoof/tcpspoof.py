import sys
import optparse, ConfigParser
import logging
import datetime
import time
import pprint
import struct
from scapy.all import *

# This command needs to be executed in order to prevent the host from sending resets
# sudo /sbin/iptables -A INPUT -p tcp --destination-port {PORT-NUMBER-HERE} -j DROP

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

cmdline_options = None
recent_conns = list()
logger = None

def get_credentials():
    return "CREDENTIALS: 5up3R53KooRP4s5w0rd"
    
def generate_seq():
    global logger
    
    t = int(time.time())
    logger.debug("Time is %d (%x)" % (t, t))
    b = list(struct.unpack("4B", struct.pack("I", t)))
    logger.debug("Bytes: %s" % str(b))
    random.shuffle(b)
    logger.debug("Shuffled bytes: %s" % str(b))
    s = "%c%c%c%c" %  (b[0], b[1], b[2], b[3])
    logger.debug("String is %s" % s)
    seq = struct.unpack("I", s)[0]
    logger.debug("Sequence number is %d (%x)" % (seq, seq))
    return seq

def packet_handler(p):
    global recent_conns
    global cmdline_options
    global logger
    
    logger.debug("Received packet")
    if p['TCP'].flags & SYN == SYN and p['TCP'].flags & ACK == 0:
        logger.debug("Received SYN packet")
        seq_num = generate_seq()
        logger.debug('Generated sequence number %d' % seq_num)    
        p.show()
        reply = IP(src=p['IP'].dst, dst=p['IP'].src)/TCP(ack=p['TCP'].seq + 1, seq=seq_num, flags="SA", sport=p['TCP'].dport, dport=p['TCP'].sport)
        conn = dict()
        conn['src'] = p['IP'].src
        conn['dst'] = p['IP'].dst
        conn['sport'] = p['TCP'].sport
        conn['dport'] = p['TCP'].dport
        conn['cseq'] = p['TCP'].seq
        conn['sseq'] = seq_num
        logger.debug("Created connection record %s" % str(conn))
        recent_conns.append(conn) 
        send(reply)
        logger.debug("SYN-ACK packet sent")
    if p['TCP'].flags & SYN == 0 and p['TCP'].flags & ACK == ACK:
        logger.debug("Received ACK packet")
        p.show()
        try:
            destination = str(p['Raw'].load)
        except Exception, e:
            logger.debug("Empty ACK packet. Skipping...")
            return
        for conn in recent_conns:
            print conn
            if conn['src'] == p['IP'].src and \
                conn['dst'] == p['IP'].dst and \
                conn['sport'] == p['TCP'].sport and \
                conn['dport'] == p['TCP'].dport and \
                conn['cseq'] + 1 == p['TCP'].seq and \
                conn['sseq'] + 1 == p['TCP'].ack:
                logger.debug("Found a matching connection")
                if p['IP'].src == cmdline_options.trusted_ip:
                    logger.debug("Connection coming from trusted IP, sending credentials")
                    credentials = get_credentials()
                    reply = IP(src=p['IP'].dst, dst=destination)/UDP(sport=int(cmdline_options.service_port), dport=int(cmdline_options.service_port))/credentials
                    try:
                        send(reply)
                    except Exception, e:
                        logger.error("Cannot send credentials to %s: %s" % (destination, str(e)))
                else:
                    logger.debug("Connection coming from untrusted IP, sending error message")
                    payload = "ERROR: You are not connecting from an authorized address"
                    reply = IP(src=p['IP'].dst, dst=p['IP'].src)/UDP(dport=int(cmdline_options.service_port))/payload
                    try:
                        send(reply)
                    except Exception, e:
                        logger.error("Cannot send error message to %s: %s" % (p['IP'].src, str(e)))
                recent_conns.remove(conn)
                break    
    return


def main(argv):
    global cmdline_options
    global logger
    
    parser = optparse.OptionParser()
    parser.add_option("-d", "--debug",
                      dest="debug", action="store_true",
                      help="enables debugging",
                      default=False)
    parser.add_option("-s", "--server",
                      dest="server_ip", type="string",
                      help="the IP address of the server providing the service",
                      default=None)
    parser.add_option("-p", "--port",
                      dest="service_port", type="string",
                      help="the port of the service",
                      default=None)
    parser.add_option("-t", "--trusted",
                      dest="trusted_ip", type="string",
                      help="the IP address of the trusted host",
                      default=None)
    parser.add_option("-i", "--interface",
                      dest="interface", type="string",
                      help="the interface to be used for sniffing",
                      default="eth0")
    
    (cmdline_options, args) = parser.parse_args()
    if len(args) != 0:
        parser.print_help()
        return 1
    if cmdline_options.debug == True:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logger = logging.getLogger('tcpspoof')
    ts = datetime.datetime.utcnow().isoformat()
    logger.debug("Starting at %s..." % str(ts))

    if cmdline_options.server_ip == None:
        logger.error("You need to specify a host to impersonate")
        parser.print_help()
        return 1

    bpf_filter = "tcp and host %s and port %s" % (cmdline_options.server_ip, cmdline_options.service_port)

    sniff(iface=cmdline_options.interface, prn=packet_handler, filter=bpf_filter, store=0)
    
    return 0

if __name__== "__main__":
    sys.exit(main(sys.argv))