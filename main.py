import pyshark
import socket
import netifaces
import signal
import sys
import time
import os
from Cli import Cli
from BitTorrentDB import BitTorrentDB
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
        return [ip, mac, getHostNameByIp(ip), info_hash, torrentInfo, date, 'Packet Inspection']
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
    if not LIVE_CAPTURE_FLAG:
        return '?'
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
    from googleSearch import GoogleSearch
    result = GoogleSearch(info_hash)
    title = result.getTitle()
    if title:
        return title
    else:
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
                    packetInfo = [row.ip, row.mac, getHostNameByIp(row.ip), '?', '?', row.date, 'Flow Inspection']
                    ui.writeLine(packetInfo)
        except Exception:
            pass
    # call check_encrypted_traffic() again in 20 seconds
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
    global LIVE_CAPTURE_FLAG
    while True:
        detectionType = raw_input('Escolha modo de funcionamento:\n1 - Deteccao em tempo real\n2 - Deteccao via ficheiro .pcap\n')
        if detectionType == '1':
            capture = pyshark.LiveCapture(interface=getInterfaces())
            capture.sniff_continuously()
            LIVE_CAPTURE_FLAG = True
            return capture
        elif detectionType == '2':
            capture = pyshark.FileCapture(getFileCapture(), keep_packets=False)
            LIVE_CAPTURE_FLAG = False
            return capture

LIVE_CAPTURE_FLAG = False
NUMBER_OF_THREADS = 5
capture = typeOfCaptureDetection()
db = BitTorrentDB()
ui = chooseUI()
signal.signal(signal.SIGINT, signal_handler)
threadArray = []
detections = []
start_time = time.time()
# start calling check_encrypted_traffic now and every 20 sec thereafter
RUN=True
check=None
check_encrypted_traffic()
count=0
for packet in capture:
    count+=1
    sys.stdout.write("\r%d" % count)
    sys.stdout.flush()
    if(len(threadArray) < NUMBER_OF_THREADS):
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
RUN = False
if check != None:
    check.join()
ui.finish()
