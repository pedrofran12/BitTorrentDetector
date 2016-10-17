import pyshark
import socket
import netifaces
import os.path
import urllib2
import signal
import sys
from BitTorrentDB import BitTorrentDB
from bs4 import BeautifulSoup
from prettytable import PrettyTable
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


def getPacketInfo(packet):
    [ip, mac] = getIpInfo(packet)
    #ip = getIpInfo(packet)
    #mac = getMacInfo(packet)
    date = packet.sniff_time.strftime("%d-%m-%Y %H:%M:%S")
    info_hash = getPacketInfoHash(packet)
    torrentInfo = getFileDescription(info_hash)
    return [ip, mac, getHostNameByIp(ip), info_hash, torrentInfo, date]

def getIpInfo(packet):
    ip_src = ''
    ip_dst = ''
    try:
        ip_src = packet.ip.src.show
        ip_dst = packet.ip.dst.show
    except Exception:
        ip_src = packet.ipv6.src.show
        ip_dst = packet.ipv6.dst.show
    global db
    ip_generator = db.get_ip_generator_of_traffic(ip_src, ip_dst)
    if(ip_generator==ip_src):
        return [ip_generator, getMacInfo(packet, 'SRC')]
    else:
        return [ip_generator, getMacInfo(packet, 'DST')]


def getMacInfo(paket, origin):
    try:
        if(origin=='SRC'):
            return packet.eth.src.show
        elif(origin=='DST'):
            return packet.eth.dst.show
        else:
            return '?'
    except Exception:
        return '?'


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
    try:
        url = "https://isohunt.bypassed.pw/torrents/?ihq=" + info_hash
        hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'}
        html = urllib2.urlopen(urllib2.Request(url, headers=hdr)).read()
        title = BeautifulSoup(html, "html.parser").title.string.replace(" torrent on isoHunt", "")
        if(title.lower().find(info_hash.lower())>=0):
            return '?'
        return title
    except:
        return '?'

def handleTable(packet):
    global detections
    packetInfo = getPacketInfo(packet)
    packetDetection = (packetInfo[0], packetInfo[3])
    if(packetDetection not in detections):
        detections.append(packetDetection)
        t.add_row(packetInfo)
        os.system('clear')
        print(t)
    return

def signal_handler(signal, frame):
    global t
    target = open('log.txt', 'w')
    target.write(t.get_string())
    target.close()
    sys.exit(0)



detections = []
signal.signal(signal.SIGINT, signal_handler)
while True:
    detectionType = raw_input('Escolha modo de funcionamento:\n1 - Deteccao em tempo real\n2 - Deteccao via ficheiro .pcap\n')
    if detectionType == '1':
        capture = pyshark.LiveCapture(interface=getInterfaces())
        capture.sniff_continuously()
        break
    elif detectionType == '2':
        capture = pyshark.FileCapture(getFileCapture())
        break

db = BitTorrentDB()
os.system('clear')
t = PrettyTable(['IP', 'MAC', 'Hostname', 'Hash', 'Torrent Description', 'Date'])
print(t)
for packet in capture:
    db.add_info_table(packet)
    if(packet.frame_info.protocols.find('bittorrent') > 0):
        handleTable(packet)
        #thread.start_new_thread ( handleTable, (packet,) )

signal.pause()
saveLog = open('log.txt', 'w')
saveLog.write(t.get_string())
saveLog.close()
