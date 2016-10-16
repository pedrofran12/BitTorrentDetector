import socket
import netifaces

"""
Costume list to store bittorrent trafic
"""
class BitTorrentList (object):

    """ indexes """
    MAC = 0;
    HOSTNAME = 1;
    HASHES = 2;

    """ variables """
    UNKNOWN = '?'
    SRC = 101
    DST = 102
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    FILTER = 'bittorrent'



    """ BEGIN """
    def __init__(self):
        self._list = dict()
        self.size = 0



    """
    'private' functions
    if something is wrong, it might be on those functions
    """
    def _get_packet_ip(packet, tag):
        try:
            return dict(SRC=packet.ip.src, DST=packet.ip.dst)[tag]
        except:
            return UNKNOWN

    def _get_packet_mac(packet, tag):
        try:
            return dict(SRC=packet.eth.src, DST=packet.eth.dst)[tag]
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
        return packet.bittorrent.info_hash.replace(':', '')

    def _get_packet_date(packet):
        return packet.sniff_time.strftime(DATE_FORMAT)



    """
    'public' functions
    """
    def add(self, packet):
        (ip, mac, host) = _get_packet_ip_mac_host(packet, SRC)
        if ip not in self._list:
            self._list[ip] = (mac, host, {})
        packet_hash = _get_packet_hash(packet)
        if packet_hash not in self._list[ip][HASHES]:
            self._list[ip][packet_hash] = {}
        dst_ip = _get_packet_ip(packet, DST)
        date = _get_packet_date(packet)
        if dst_ip not in self._list[ip][packet_hash]:
            self._list[ip][packet_hash][dst_ip] = (date, date)
        self._list[ip][packet_hash][dst_ip][1] = date
        self.size = self.size + 1;

    def size(self):
        return self._size

    def clear(self):
        self._list = dict()
        self.size = 0



    """
    test functions
    """
    def _test_print_host_info(self):
        print 'IP:\t\tMAC:\t\tHOST NAME:'
        for i in self._list:
            info_list = self._list[i]
            print i + '\t' + info_list[MAC] + '\t' + info_list[HOSTNAME]

    def _test_print_recieved_hashes(sefl):
        print 'IP:\t\tHASH:\t\tSRC:'
        for i in self._list:
            hashes_list = self._list[i][HASHES]
            for j in hashes_list:
                src_ips = hashes_list[j]
                for k in src_ips:
                    print i + '\t' + j + '\t' + k + '\tfrom: ' + src_ips[k][0] + ' to: ' + src_ips[k][1]

    def _test_self_fill(self, num_packets=10):
