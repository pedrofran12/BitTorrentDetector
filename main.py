import pyshark
import os.path


def getFileCapture():
    isFile = False
    while (not isFile):
        fileName = raw_input('Nome/path do ficheiro de captura: ')
        isFile = os.path.isfile(fileName)
    return fileName


while True:
    detectionType = raw_input('Escolha modo de funcionamento:\n1 - Deteccao em tempo real\n2 - Deteccao via ficheiro .pcap\n')
    if detectionType == '1':
        capture = pyshark.LiveCapture(interface='any')
        capture.sniff_continuously()
        break
    elif detectionType == '2':
        capture = pyshark.FileCapture(getFileCapture())
        break

'''capture'''
print 'got intended capture'

for packet in capture:
    if(packet.frame_info.protocols.find('bittorrent') > 0):
        print 'Bittorrent packet found! - hash:', packet.bittorrent.info_hash.replace(':', '')
