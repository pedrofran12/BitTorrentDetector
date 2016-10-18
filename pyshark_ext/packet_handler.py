UNKNOWN = '?'
DATE_FORMAT = "%Y-%m-%d %H:%M:%S:%f"
DST = 10
SRC = 11

def _get_packet_size(packet):
    return 0

def _get_packet_ip(packet, tag):
    try:
        if tag == SRC:
            try:
                return packet.ip.src
            except:
                return packet.ipv6.src
        elif tag == DST:
            try:
                return packet.ip.dst
            except:
                return packet.ipv6.dst
        else:
            return UNKNOWN
    except:
        return UNKNOWN

def _get_packet_mac(packet, tag):
    try:
        if tag == SRC:
            return packet.eth.src
        elif tag == DST:
            return packet.eth.dst
        else:
            return UNKNOWN
    except:
        return UNKNOWN

def _get_host_by_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return UNKNOWN

def _get_packet_ip_mac_host(packet, tag):
    ip = _get_packet_ip(packet, tag)
    mac = _get_packet_mac(packet, tag)
    host = _get_host_by_ip(ip)
    return (ip, mac, host)

def _get_packet_hash(packet):
    try:
        return packet.bittorrent.info_hash.replace(':', '')
    except:
        return UNKNOWN

def _get_packet_date(packet):
    try:
        return packet.sniff_time.strftime(DATE_FORMAT)
    except:
        return UNKNOWN
