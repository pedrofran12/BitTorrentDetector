import pyshark_ext.packet_handler as pa

class StatisticList(object):

    SENDED = 's'
    RECIEVED = 'r'

    def __init__(self):
        self._packets = dict()
        self._count = 0

    def _add_ip_entry(self, ip_src, ip_dst, packet):
        ip = (ip1, ip2)
        if (ip not in self._packets):
            self._packets[ip] = {}
        if (tag not in self._packets[ip]):
            self._packets[ip][tag] = {}
        size = pa._get_packet_size(packet)
        if (size nit in self._packets[ip][tag]):
            self._packets[ip][tag][size] = 0
        self._packets[ip][tag][size] = self._packets[ip][tag][size] + 1
        self._count = self._count + 1

    def add (self, packet):
        ip1 = pa(packet, pa.SRC)
        ip2 = pa(packet, pa.DST)
        self._add_ip_entry(ip1, ip2, packet)

    def get_torrent_flows_ip(self):
        
