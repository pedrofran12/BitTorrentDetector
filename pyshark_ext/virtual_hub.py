from pyshark_ext.lists.bit_torrent_list import BitTorrentList
from pyshark_ext.lists.statistic_list import StatisticList

class VirtualHub(object):

    def __init__(self):
        self._statistic = StatisticList()
        self._bitlist = BitTorrentList()

    def add (self, packet):
        if (packet.frame_info.protocols.find('bittorrent') > 0):
            self._bitlist.add(packet)
        else:
            condition1 = (packet.frame_info.protocols.find('tcp') > 0)
            condition2 = (packet.frame_info.protocols.find('udp') > 0)
            if condition1 or condition2:
                self._statistic.add(packet)
