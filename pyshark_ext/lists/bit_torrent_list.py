import socket
import pyshark_ext.network.subnet_verify as net
import pyshark_ext.packet_handler as pa

""" constant variables """
FILTER = 'bittorrent'

"""
Costume list to store bittorrent trafic
"""
class BitTorrentList (object):

    """ indexes """
    MAC = 0;
    HOST = 1;
    HASHES = 2;

    """ BEGIN """
    def __init__(self):
        self._list = dict()
        self.found = 0

    def packets_found(self):
        return self.found

    """
    'public' functions
    """

    def add(self, packet):
        if (packet.frame_info.protocols.find(FILTER) > 0):
            (ip, mac, host) = pa._get_packet_ip_mac_host(packet, SRC)
            if (ip not in self._list):
                self._list[ip] = [mac, host, {}]
            if (self._list[ip][self.MAC] == pa.UNKNOWN):
                self._list[ip][self.MAC] = mac
            if (self._list[ip][self.HOST] == pa.UNKNOWN):
                self._list[ip][self.HOST] = host
            packet_hash = pa._get_packet_hash(packet)
            if (packet_hash not in self._list[ip][self.HASHES]):
                self._list[ip][self.HASHES][packet_hash] = {}
            dst_ip = pa._get_packet_ip(packet, pa.DST)
            date = pa._get_packet_date(packet)
            if (dst_ip not in self._list[ip][self.HASHES][packet_hash]):
                self._list[ip][self.HASHES][packet_hash][dst_ip] = [date, date]
            self._list[ip][self.HASHES][packet_hash][dst_ip][1] = date
            self.found = self.found + 1;

    def clear(self):
        self._list = dict()
        self.size = 0

    def get_pairs(self):
        par_list = []
        for src in self._list:
            hashes_list = self._list[src][self.HASHES]
            for j in hashes_list:
                src_ips = hashes_list[j]
                for dst in src_ips:
                    par_list = par_list + [(src, dst)]
        return par_list
