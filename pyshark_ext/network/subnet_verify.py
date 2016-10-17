import pyshark_ext.network.get

IPV4 = 'ipv4'
IPV6 = 'ipv6'
IPV4_SEP = '.'

def is_ipv4(ip):
    try:
        parse = ip.split(IPV4_SEP)
        if len(parse) != 4:
            return False
        for i in range(4):
            parse[i] = int(parse[i])
            if parse[i] < 0 or parse[i] > 255:
                return False
        return True
    except:
        return False

def is_ipv6(ip):
    return False

def net_ipv4(ip, mask):
    parse_ip = ip.split(IPV4_SEP)
    parse_mask = mask.split(IPV4_SEP)
    res = []
    for i in range(4):
        num = int(parse_ip[i]) & int(parse_mask[i])
        res = res + [str(num)]
    return res[0] + IPV4_SEP + res[1] + IPV4_SEP + \
            res[2] + IPV4_SEP + res[3]


def same_subnet_ipv4(ip1, ip2, mask):
    return net_ipv4(ip1, mask) == net_ipv4(ip2, mask)

def same_subnet_ipv6(ip1, ip2, mask):
    return False

def same_subnet (ip1, ip2, mask):
    if is_ipv4(ip1) and is_ipv4(ip2) and is_ipv4(mask):
        return same_subnet_ipv4(ip1, ip2, mask)
    elif is_ipv6(ip1) and is_ipv6(ip2) and is_ipv6(mask):
        return same_subnet_ipv4(ip1, ip2, mask)
    else:
        return False

def from_my_subnet (ip):
    interfaces = get.get_interfaces()
    for i in interfaces:
        (local_ip, mask) = get_ip_and_mask(i)
        if same_subnet(local_ip, ip, mask):
            return True
    return False
