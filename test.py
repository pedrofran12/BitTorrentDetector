import pyshark
import socket
import netifaces

interface_check = 'enp0s3'

'''
capture = pyshark.LiveCapture(interface='enp0s3')
capture.sniff(timeout=50)
capture

for packet in capture.sniff_continuously(packet_count=5):
        print 'Just arrived:', packet
'''

# detectar bittorrent e imprimir
netifaces.interfaces()
def get_subnet_address (ip, mask):
    ip_split = ip.split('.')
    mask_split = mask.split('.')
    result = []
    for i in range(4):
        num = int(ip_split[i]) & int(mask_split[i])
        result = result + [str(num)]
    return result[0]+'.'+result[1]+'.'+result[2]+'.'+result[3]

def get_ip_and_mac_based_on_network (packet):
    inter = netifaces.ifaddresses(interface_check)[2][0]
    ip = inter['addr']
    mask = inter['netmask']
    subnet = get_subnet_address (ip, mask)

    src_ip = packet.ip.src
    src_mac = packet.eth.src
    dst_ip = packet.ip.dst
    dst_mac = packet.eth.dst

    if subnet == get_subnet_address(src_ip, mask):
        return (src_ip, src_mac)
    elif subnet == get_subnet_address(dst_ip, mask):
        return (dst_ip, dst_mac)
    else:
        return ('?', '?')

isLive = True
def print_bittorrent_info (packet):
    print "\n\n### FOUND BITTORRENT PACKET ###\n"
    (ip, mac) = get_ip_and_mac_based_on_network (packet)
    print "Destination IP:", ip
    print "Destination MAC:", mac
    if ip != '?':
        try:
            name = socket.gethostbyaddr(ip)[0]
            print "Host name:", name
        except:
            print "Host name: ?"
    else:
        print "Host name: ?"
    print "BitTorrent hash:", packet.bittorrent.info_hash.replace(':', '')
    print "Date:", packet.sniff_time.strftime("%d-%m-%Y %H:%M:%S")

capture = pyshark.LiveCapture(interface=interface_check, display_filter='bittorrent')
# capture.apply_on_packets(packet_captured)
capture.apply_on_packets(print_bittorrent_info)
