import pyshark
import socket
import netifaces
import urllib2
import signal
import sys
import time
import os
from Cli import Cli
from BitTorrentDB import BitTorrentDB
from bs4 import BeautifulSoup
import threading
import readline, glob
def complete(text, state):
    return (glob.glob(text+'*')+[None])[state]
#File path autocomplete
readline.set_completer_delims(' \t\n;')
readline.parse_and_bind("tab: complete")
readline.set_completer(complete)


def getInterfaces():
    interfaces = netifaces.interfaces()
    for i in range(len(interfaces))[::-1]:
        if(netifaces.AF_INET not in netifaces.ifaddresses(interfaces[i])):
            del interfaces[i]
        if(interfaces[i]=='localhost'):
            del interfaces[i]

    return interfaces


def getFileCapture():
    isFile = False
    while (not isFile):
        fileName = raw_input('Nome/path do ficheiro de captura: ')
        isFile = os.path.isfile(fileName)
    return fileName


def getPacketInfo(packet):
    info_hash = getPacketInfoHash(packet)
    if(info_hash!='?'):
        [ip, mac] = getIpInfo(packet)
        date = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S")
        torrentInfo = getFileDescription(info_hash)
        return [ip, mac, getHostNameByIp(ip), info_hash, torrentInfo, date]
    else:
        raise Exception('Bittorrent packet without hash!')


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
    '''
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
    '''
    return '?'

def handleTable(packet):
    global detections
    try:
        packetInfo = getPacketInfo(packet)
    except Exception:
        return;
    packetDetection = (packetInfo[0], packetInfo[3])
    if(packetDetection not in detections):
        detections.append(packetDetection)
        ui.writeLine(packetInfo)
    return

def signal_handler(signal, frame):
    global start_time
    global RUN
    RUN = False
    ui.finish()
    print("Execution time: %s seconds" % (time.time() - start_time))
    sys.exit(0)


def check_encrypted_traffic():
    global db
    global check
    if check != None:
        try:
            response = db.check_traffic()
            for row in response:
                if((row.ip, '?') not in detections):
                    detections.append((row.ip, '?'))
                    packetInfo = [row.ip, row.mac, getHostNameByIp(row.ip), '?', '?', row.date]
                    ui.writeLine(packetInfo)
        except Exception:
            pass
    # call check_encrypted_traffic() again in 60 seconds
    if(RUN):
        check = threading.Timer(20, check_encrypted_traffic)
        check.start()
    return

def chooseUI():
    while True:
        inputValue = raw_input('Escolha UI:\n1 - Linha de comandos\n2 - Interface grafica\n')
        if inputValue == '1':
            return Cli()
        elif inputValue == '2':
            return Cli()


def typeOfCaptureDetection():
    while True:
        detectionType = raw_input('Escolha modo de funcionamento:\n1 - Deteccao em tempo real\n2 - Deteccao via ficheiro .pcap\n')
        if detectionType == '1':
            #, display_filter='ip.src!=ip.dst and (tcp or udp)'
            capture = pyshark.LiveCapture(interface=getInterfaces())
            capture.sniff_continuously()
            return capture
        elif detectionType == '2':
            capture = pyshark.FileCapture(getFileCapture(), keep_packets=False)
            return capture


capture = typeOfCaptureDetection()
db = BitTorrentDB()
ui = chooseUI()
signal.signal(signal.SIGINT, signal_handler)
threadArray = []
detections = []
start_time = time.time()
# start calling check_encrypted_traffic now and every 60 sec thereafter
RUN=True
check=None
check_encrypted_traffic()
count=0
for packet in capture:
    count+=1
    sys.stdout.write("\r%d" % count)
    sys.stdout.flush()
    if(len(threadArray)<5):
        threadid = threading.Thread(target=db.add_info_table, args=(packet,))
        threadArray.append(threadid)
        threadid.start()
    else:
        for threadid in threadArray:
            threadid.join()
        threadArray=[]

    if(packet.frame_info.protocols.find('bittorrent') > 0):
        threadid = threading.Thread(target=handleTable, args=(packet,))
        threadid.start()
        threadid.join()

sys.stdout.write("\n")
sys.stdout.flush()
print("Execution time: %s seconds" % (time.time() - start_time))
#signal.pause()
RUN = False
if check != None:
    check.join()
ui.finish()
