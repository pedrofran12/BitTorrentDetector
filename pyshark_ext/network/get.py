import netifaces as ne

def get_interfaces():
    interfaces = ne.interfaces()
    for i in range(len(interfaces))[::-1]:
        if ne.AF_INET not in ne.ifaddresses(interfaces[i]):
            del interfaces[i]
    return interfaces

def get_ip_and_mask(interface):
    info = ne.ifaddresses(interface)[ne.AF_INET]
    ip = info['addr']
    mask = info['netmask']
    return (ip, mask)
