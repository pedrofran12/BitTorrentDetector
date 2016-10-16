import socket
import netifaces

def getInterfaces():
    interfaces = netifaces.interfaces()
    for i in range(len(interfaces))[::-1]:
        if neticafes.AF_INET not in netifaces.ifaddresses(interfaces[i]):
            del interfaces[i]
    return interfaces

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

    def __len__(self):
        return self.size

    """
    'private' functions
    if something is wrong, it might be on those functions
    """
    def _get_packet_ip(self, packet, tag):
        try:
            if tag == self.SRC:
                return packet.ip.src
            elif tag == self.DST:
                return packet.ip.dst
            else:
                return self.UNKNOWN
        except:
            return self.UNKNOWN

    def _get_packet_mac(self, packet, tag):
        try:
            if tag == self.SRC:
                return packet.eth.src
            elif tag == self.DST:
                return packet.eth.dst
            else:
                return self.UNKNOWN
        except:
            return self.UNKNOWN

    def _get_host_by_ip(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return self.UNKNOWN

    def _get_packet_ip_mac_host(self, packet, tag):
        ip = self._get_packet_ip(packet, tag)
        mac = self._get_packet_mac(packet, tag)
        host = self._get_host_by_ip(ip)
        return (ip, mac, host)

    def _get_packet_hash(self, packet):
        try:
            return packet.bittorrent.info_hash.replace(':', '')
        except:
            return self.UNKNOWN

    def _get_packet_date(self, packet):
        try:
            return packet.sniff_time.strftime(self.DATE_FORMAT)
        except:
            return self.UNKNOWN



    """
    'public' functions
    """
    def add(self, packet):
        if (packet.frame_info.protocols.find('bittorrent') > 0):
            (ip, mac, host) = self._get_packet_ip_mac_host(packet, self.SRC)
            if (ip not in self._list):
                self._list[ip] = (mac, host, {})
            packet_hash = self._get_packet_hash(packet)
            if (packet_hash not in self._list[ip][self.HASHES]):
                self._list[ip][self.HASHES][packet_hash] = {}
            dst_ip = self._get_packet_ip(packet, self.DST)
            date = self._get_packet_date(packet)
            if (dst_ip not in self._list[ip][self.HASHES][packet_hash]):
                self._list[ip][self.HASHES][packet_hash][dst_ip] = [date, date]
            self._list[ip][self.HASHES][packet_hash][dst_ip][1] = date
            self.size = self.size + 1;
            print "Added bittorrent!", self.size

    def clear(self):
        self._list = dict()
        self.size = 0



    """
    test functions
    """
    def _test_print_host_info(self):
        print 'IP:\t\tMAC:\t\t\tHOST NAME:'
        for i in self._list:
            info_list = self._list[i]
            print i + '\t' + info_list[self.MAC] + '\t' + info_list[self.HOSTNAME]

    def _test_print_recieved_hashes(self):
        print 'IP:\t\tHASH:\t\t\t\t\tSRC:'
        for i in self._list:
            hashes_list = self._list[i][self.HASHES]
            for j in hashes_list:
                src_ips = hashes_list[j]
                for k in src_ips:
                    print i + '\t' + j + '\t' + k + '\tfrom: ' + src_ips[k][0] + ' to: ' + src_ips[k][1]
