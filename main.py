import pyshark_ext as pyshark
import socket
import netifaces
import os.path
import signal
import sys
import thread
import readline, glob
def complete(text, state):
    return (glob.glob(text+'*')+[None])[state]

readline.set_completer_delims(' \t\n;')
readline.parse_and_bind("tab: complete")
readline.set_completer(complete)


def getInterfaces():
    interfaces = netifaces.interfaces()
    for i in range(len(interfaces))[::-1]:
        if(netifaces.AF_INET not in netifaces.ifaddresses(interfaces[i])):
            del interfaces[i]
    return interfaces


def getFileCapture():
    isFile = False
    while (not isFile):
        fileName = raw_input('Nome/path do ficheiro de captura: ')
        isFile = os.path.isfile(fileName)
    return fileName

def signal_handler(signal, frame):
    sys.exit(0)



detections = []
signal.signal(signal.SIGINT, signal_handler)
while True:
    detectionType = raw_input('Escolha modo de funcionamento:\n1 - Deteccao em tempo real\n2 - Deteccao via ficheiro .pcap\n')
    if detectionType == '1':
        #capture = pyshark.LiveCapture(interface=getInterfaces())
        capture = pyshark.LiveCapture(interface='enp0s3')
        capture.sniff_continuously()
        break
    elif detectionType == '2':
        capture = pyshark.FileCapture(getFileCapture())
        break

print getInterfaces()
bitList = pyshark.BitTorrentList()
for packet in capture:
    bitList.add(packet)
    if len(bitList.get_pairs()) >= 10:
        break

bitList._test_print_host_info()

signal.pause()
