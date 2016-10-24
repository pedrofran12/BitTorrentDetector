import os
import time
import threading

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

# The number of workers to run
NUM_WORKERS = 20

# Run the workload for this many seconds
WORKLOAD_TIME = 10

# Batch size to use
BATCH_SIZE = 5000

def get_connection(db=DATABASE):
    """ Returns a new connection to the database. """
    return database.connect(host=HOST, port=PORT, user=USER, password=PASSWORD, database=db)

class BitTorrentDB:
    def __init__(self):
        """ Create a database and table for this benchmark to use. """
        with get_connection(db="information_schema") as conn:
            print('Creating database %s' % DATABASE)
            conn.query('CREATE DATABASE IF NOT EXISTS %s' % DATABASE)
            conn.query('USE %s' % DATABASE)

            print('Creating table %s' % TABLE)
            conn.query('DROP TABLE IF EXISTS packets')
            conn.query('CREATE TABLE IF NOT EXISTS packets (ip_src VARCHAR(100), ip_dst VARCHAR(100),port_src MEDIUMINT, port_dst MEDIUMINT, packet_size INT, date VARCHAR(100))')



    def add_info_table(self, packet):
        try:
            protocol = packet.transport_layer
            port_src = packet[protocol].srcport
            port_dst = packet[protocol].dstport
        except AttributeError as e:
            #ignore packets that aren't TCP/UDP
            return
        try:
            ip_src = packet.ip.src.show
            ip_dst = packet.ip.dst.show
            if(ip_src=='127.0.0.1' or ip_dst=='127.0.0.1'):
                return
            if(ip_src==ip_dst):
                return
        except Exception:
            try:
                ip_src = packet.ipv6.src.show
                ip_dst = packet.ipv6.dst.show
            except Exception:
                return
        packet_length = packet.length #check if this is the best length for the packet
        date = str(packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S"))
        get_connection().execute('INSERT INTO packets VALUES (%s,%s,%s,%s,%s,%s)', ip_src, ip_dst, port_src, port_dst, packet_length, date)
        #self.connection.commit()


    def get_table_print(self):
        self.connection.commit()
        for row in self.cursor.execute('select * from packets'):
            print row

    def get_ip_generator_of_traffic(self, ip1, ip2):
        print 'entered'
        query = "SELECT D.IP FROM ( SELECT C.IP, COUNT(C.IP) AS COUNT FROM ( SELECT A.ip_src AS IP, A.date FROM packets A WHERE A.ip_src=%s UNION SELECT B.ip_dst AS IP, B.date FROM packets B WHERE B.ip_dst=%s ) AS C GROUP BY C.IP ) AS D WHERE D.COUNT=( SELECT MAX(H.COUNT) FROM ( SELECT COUNT(G.IP) AS COUNT FROM ( SELECT E.ip_src AS IP, E.date FROM packets E WHERE E.ip_src=%s UNION SELECT F.ip_dst AS IP, F.date FROM packets F WHERE F.ip_dst=%s ) AS G GROUP BY G.IP ) AS H)"
        response = get_connection().query(query, ip1, ip2, ip1, ip2)
        print response
        if(len(response) == 1):
            #Just one answer from DB
            return response[0].IP
        raise Exception('2 ips equally frequent')
