import pyshark_ext as pyshark

interface_check = 'enp0s3'

'''
capture = pyshark.LiveCapture(interface='enp0s3')
capture.sniff(timeout=50)
capture

for packet in capture.sniff_continuously(packet_count=5):
        print 'Just arrived:', packet
'''

capture = pyshark.LiveCapture(interface=interface_check)
# capture.apply_on_packets(packet_captured)
capture.sniff(timeout=50)
#capture.apply_on_packets(print_bittorrent_info)


bitList = pyshark.BitTorrentList()
for packet in capture:
    bitList.add(packet)
    if len(bitList) >= 100:
        break
print "\n\n\nHOST INFO"
bitList._test_print_host_info()

print "\n\n\nRECIEVED HASHES INFO"
bitList._test_print_recieved_hashes()
