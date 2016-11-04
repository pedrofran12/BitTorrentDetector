import pyshark_ext as pyshark
import pyshark_ext.network.get as get
import signal

print pyshark.network.parser.parse_ipv4_mask('192.168.1.1/24')

'''
def signal_handler(signal, frame):
    sys.exit(0)

interface_check = get.get_interfaces()

bitList = pyshark.BitTorrentList(packets_limit = 50)

detections = []
signal.signal(signal.SIGINT, signal_handler)
while True:
    detectionType = raw_input('Escolha modo de funcionamento:\n1 - Deteccao em tempo real\n2 - Deteccao via ficheiro .pcap\n')
    if detectionType == '1':
        capture = pyshark.LiveCapture(interface=interface_check)
        capture.sniff_continuously()
        break
    elif detectionType == '2':
        capture = pyshark.FileCapture(getFileCapture())
        break

for packet in capture:
    bitList.add(packet)
    if (not bitList.is_running()):
        break
capture.close()

print "\n\n\nHOST INFO"
bitList._test_print_host_info()

print "\n\n\nRECIEVED HASHES INFO"
bitList._test_print_recieved_hashes()
'''
