import socket
import pyshark_ext.network.subnet_verify as net

""" constant variables """
UNKNOWN = '?'
DATE_FORMAT = "%Y-%m-%d %H:%M:%S:%f"
FILTER = 'bittorrent'
DST = 10
SRC = 11
BOTH = 12

"""
'private' functions
if something is wrong, it might be on those functions
"""
def _get_ips_info(packet):
    return

def _get_packet_ip(packet, tag):
    try:
        if tag == SRC:
            try:
                return packet.ip.src
            except:
                return packet.ipv6.src
        elif tag == DST:
            try:
                return packet.ip.dst
            except:
                return packet.ipv6.dst
        else:
            return UNKNOWN
    except:
        return UNKNOWN

def _get_packet_mac(packet, tag):
    try:
        if tag == SRC:
            return packet.eth.src
        elif tag == DST:
            return packet.eth.dst
        else:
            return UNKNOWN
    except:
        return UNKNOWN

def _get_host_by_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return UNKNOWN

def _get_packet_ip_mac_host(packet, tag):
    ip = _get_packet_ip(packet, tag)
    mac = _get_packet_mac(packet, tag)
    host = _get_host_by_ip(ip)
    return (ip, mac, host)

def _get_packet_hash(packet):
    try:
        return packet.bittorrent.info_hash.replace(':', '')
    except:
        return UNKNOWN

def _get_packet_date(packet):
    try:
        return packet.sniff_time.strftime(DATE_FORMAT)
    except:
        return UNKNOWN

"""
Costume list to store bittorrent trafic
"""
class BitTorrentList (object):

    """ indexes """
    MAC = 0;
    HOST = 1;
    HASHES = 2;

    """ BEGIN """
    def __init__(self, packets_limit=-1, live_capture=False):
        self._list = dict()
        self.size = 0
        self.statistic_id = 0
        self.packets_limit = packets_limit
        self.live_capture = live_capture
        self.running = self.size != self.packets_limit

    def __len__(self):
        return self.size

    """
    'public' functions
    """
    def _add_entrance(self, packet, tuple_info):
        _get_ips_info()

    def add(self, packet):
        if (packet.frame_info.protocols.find('bittorrent') > 0) and \
            self.running:
            (ip, mac, host) = _get_packet_ip_mac_host(packet, SRC)
            if (ip not in self._list):
                self._list[ip] = [mac, host, {}]
            if (self._list[ip][self.MAC] == UNKNOWN):
                self._list[ip][self.MAC] = mac
            if (self._list[ip][self.HOST] == UNKNOWN):
                self._list[ip][self.HOST] = host
            packet_hash = _get_packet_hash(packet)
            if (packet_hash not in self._list[ip][self.HASHES]):
                self._list[ip][self.HASHES][packet_hash] = {}
            dst_ip = _get_packet_ip(packet, DST)
            date = _get_packet_date(packet)
            if (dst_ip not in self._list[ip][self.HASHES][packet_hash]):
                self._list[ip][self.HASHES][packet_hash][dst_ip] = [date, date]
            self._list[ip][self.HASHES][packet_hash][dst_ip][1] = date
            self.size = self.size + 1;
            self.running = self.size != self.packets_limit
            print "Added bittorrent!", self.size

    def clear(self):
        self._list = dict()
        self.size = 0

    def is_running(self):
        return self.running



    """
    test functions
    """
    def _test_print_host_info(self):
        print 'IP:\t\tMAC:\t\t\tHOST NAME:'
        for i in self._list:
            info_list = self._list[i]
            print i + '\t' + info_list[self.MAC] + '\t' + info_list[self.HOST]

    def _test_print_recieved_hashes(self):
        print 'IP:\t\tHASH:\t\t\t\t\tSRC:'
        for i in self._list:
            hashes_list = self._list[i][self.HASHES]
            for j in hashes_list:
                src_ips = hashes_list[j]
                for k in src_ips:
                    print i + '\t' + j + '\t' + k + '\tfrom: ' + src_ips[k][0] + ' to: ' + src_ips[k][1]
