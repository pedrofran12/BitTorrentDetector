from memsql.common import database

# Specify connection information for a MemSQL node
HOST = "127.0.0.1"
PORT = 3306
USER = "root"
PASSWORD = ""

# Specify which database and table to work with.
# Note: this database will be dropped at the end of this script
DATABASE = "csf"
TABLE = "packets"

# Encrypted traffic:
# every MINUTES_TO_CHECK_ENCRYPTED_TRAFFIC minutes check for Encrypted traffic
MINUTES_TO_CHECK_ENCRYPTED_TRAFFIC = 2 #check this
MINIMUM_NUMBER_OF_PORTS_TO_CONSIDER_BITTORRENT_TRAFFIC = 200


def get_connection(db=DATABASE):
    """ Returns a new connection to the database. """
    return database.connect(host=HOST, port=PORT, user=USER, password=PASSWORD, database=db)

class BitTorrentDB:
    def __init__(self):
        """ Create database and table """
        with get_connection(db="information_schema") as conn:
            print('Creating database %s' % DATABASE)
            conn.query('CREATE DATABASE IF NOT EXISTS %s' % DATABASE)
            conn.query('USE %s' % DATABASE)

            print('Creating table %s' % TABLE)
            conn.query('DROP TABLE IF EXISTS %s' % TABLE)
            conn.query('CREATE TABLE IF NOT EXISTS %s (ip_src VARCHAR(100), ip_dst VARCHAR(100), mac_src VARCHAR(17), mac_dst VARCHAR(17), port_src MEDIUMINT, port_dst MEDIUMINT, packet_size INT, date DATETIME(6))' % TABLE)



    def add_info_table(self, packet):
        try:
            protocol = packet.transport_layer
            port_src = packet[protocol].srcport
            port_dst = packet[protocol].dstport
        except AttributeError as e:
            port_src = 0
            port_dst = 0
        try:
            ip_src = packet.ip.src.show
            ip_dst = packet.ip.dst.show
            if(ip_src=='127.0.0.1' or ip_dst=='127.0.0.1' or ip_src==ip_dst):
                return
        except Exception:
            try:
                ip_src = packet.ipv6.src.show
                ip_dst = packet.ipv6.dst.show
            except Exception:
                return
        try:
            mac_src = packet.eth.src.show
            mac_dst = packet.eth.dst.show
        except Exception:
            mac_src = '?'
            mac_dst = '?'
        packet_length = packet.captured_length #check if this is the best length for the packet
        date = str(packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S.%f"))
        get_connection().execute('INSERT INTO packets VALUES (%s,%s,%s,%s,%s,%s,%s,str_to_date(%s, %s))', ip_src, ip_dst, mac_src, mac_dst, port_src, port_dst, packet_length, date, "%Y-%m-%d %H:%i:%s.%f")


    def get_table_print(self):
        response = get_connection().execute('select * from packets')
        for row in response:
            print row

    def get_ip_generator_of_traffic(self, ip1, ip2):
        query = "SELECT D.IP \
                 FROM ( SELECT C.IP, COUNT(C.IP) AS COUNT \
                        FROM (  SELECT A.ip_src AS IP, A.date \
                                FROM packets A \
                                WHERE A.ip_src=%s \
                                UNION \
                                SELECT B.ip_dst AS IP, B.date \
                                FROM packets B \
                                WHERE B.ip_dst=%s ) AS C \
                        GROUP BY C.IP  ) AS D \
                 WHERE D.COUNT=( SELECT MAX(H.COUNT) \
                                 FROM ( SELECT COUNT(G.IP) AS COUNT \
                                        FROM ( SELECT E.ip_src AS IP, E.date \
                                               FROM packets E \
                                               WHERE E.ip_src=%s \
                                               UNION \
                                               SELECT F.ip_dst AS IP, F.date \
                                               FROM packets F \
                                               WHERE F.ip_dst=%s ) AS G \
                                        GROUP BY G.IP ) AS H)"
        response = get_connection().query(query, ip1, ip2, ip1, ip2)
        print response
        if(len(response) == 1):
            #Just one answer from DB
            return response[0].IP
        raise Exception('2 ips equally frequent')


    def check_traffic(self):
        number_of_ports = MINIMUM_NUMBER_OF_PORTS_TO_CONSIDER_BITTORRENT_TRAFFIC
        minutes_to_check = MINUTES_TO_CHECK_ENCRYPTED_TRAFFIC
        date = self.get_max_date()
        query = "SELECT C.ip, C.mac, STR_TO_DATE(%s, %s) AS date, COUNT(*) AS Number_Packets, SUM(C.packet_size) AS Generated_Traffic_Per_Port \
                 FROM ( \
                       SELECT A.ip_src AS ip, A.mac_src AS mac, A.port_src AS port, A.packet_size \
                       FROM packets AS A \
                       WHERE A.date > (SELECT DATE_SUB(STR_TO_DATE(%s, %s), INTERVAL %s MINUTE)) \
                       UNION \
                       SELECT B.ip_dst AS ip, B.mac_dst AS mac, B.port_dst AS port, B.packet_size \
                       FROM packets AS B \
                       WHERE B.date > (SELECT DATE_SUB(STR_TO_DATE(%s, %s), INTERVAL %s MINUTE)) \
                       ) AS C \
                 GROUP BY C.ip, C.mac \
                 HAVING COUNT(DISTINCT C.port) > %s OR (((COUNT(DISTINCT C.port) < 10 AND COUNT(DISTINCT C.port) >= 2) OR SUM(C.port) = 0) AND COUNT(*) > 190 AND SUM(C.packet_size)/COUNT(*) >= 512)"

        response = get_connection().query(query, date, "%Y-%m-%d %H:%i:%s", date, "%Y-%m-%d %H:%i:%s.%f", minutes_to_check, date,"%Y-%m-%d %H:%i:%s.%f", minutes_to_check, number_of_ports)
        print 'check_traffic:', response
        if(len(response) == 0):
            raise Exception('no traffic detected')
        return response


    def get_max_date(self):
        query = "SELECT MAX(CAST(date AS CHAR)) AS Max_Date\
                 FROM packets"
        response = get_connection().query(query)
        if(len(response) == 1):
            #Just one answer from DB
            return response[0].Max_Date
        raise Exception('No Info On Database')
