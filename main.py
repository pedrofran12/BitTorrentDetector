import pyshark
import socket
import netifaces
import os.path
import urllib2
import signal
import sys
from bs4 import BeautifulSoup
from prettytable import PrettyTable


def getFileCapture():
    isFile = False
    while (not isFile):
        fileName = raw_input('Nome/path do ficheiro de captura: ')
        isFile = os.path.isfile(fileName)
    return fileName


def getPacketInfo(packet):
    ip = packet.ip.dst.show
    mac = packet.eth.dst.show
    date = packet.sniff_time.strftime("%d-%m-%Y %H:%M:%S")
    info_hash = getPacketInfoHash(packet)
    torrentInfo = getFileDescription(info_hash)
    return [ip, mac, getHostNameByIp(ip), info_hash, torrentInfo, date]

def getHostNameByIp(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return '?'

def getPacketInfoHash(packet):
    try:
        return packet.bittorrent.info_hash.replace(':', '')
    except:
        return '?'


def getFileDescription(info_hash):
    if info_hash == '?':
        return '?'
    url = "https://isohunt.bypassed.pw/torrents/?ihq=" + info_hash
    hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'}
    html = urllib2.urlopen(urllib2.Request(url, headers=hdr)).read()
    return BeautifulSoup(html, "html.parser").title.string.replace(" torrent on isoHunt", "")


def signal_handler(signal, frame):
    sys.exit(0)



signal.signal(signal.SIGINT, signal_handler)
while True:
    detectionType = raw_input('Escolha modo de funcionamento:\n1 - Deteccao em tempo real\n2 - Deteccao via ficheiro .pcap\n')
    if detectionType == '1':
        capture = pyshark.LiveCapture(interface=netifaces.interfaces())
        capture.sniff_continuously()
        break
    elif detectionType == '2':
        capture = pyshark.FileCapture(getFileCapture())
        break


os.system('clear')
t = PrettyTable(['IP', 'MAC', 'Hostname', 'Hash', 'Torrent Description', 'Date'])
print t
for packet in capture:
    if(packet.frame_info.protocols.find('bittorrent') > 0):
        t.add_row(getPacketInfo(packet))
        os.system('clear')
        print t


signal.pause()
