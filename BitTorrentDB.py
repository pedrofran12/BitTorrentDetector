import sqlite3
import os

class BitTorrentDB:
    def __init__(self):
        try:
            os.remove('btd.db')
        except:
            pass
        self.connection = sqlite3.connect('btd.db')
        self.cursor = self.connection.cursor()

        # Create table
        self.cursor.execute("CREATE TABLE packets (ip_src text, ip_dst text,port_src text, port_dst text, packet_size text, data text);")

    def add_info_table(self, packet):
        ## fazer try para n crashar
        try:
            ip_src = packet.ip.src.show
            ip_dst = packet.ip.dst.show
            port_src = '0'
            port_dst = '0'
            packet_length = '0'
            date = str(packet.sniff_time.strftime("%d-%m-%Y %H:%M:%S"))
            self.cursor.execute('INSERT INTO packets VALUES (?,?,?,?,?,?)', (ip_src, ip_dst, port_src, port_dst, packet_length, date))
            self.connection.commit()
        except Exception:
            pass

            
    def get_table_print(self):
        self.cursor.execute("select * from packets")
        for row in self.cursor.execute('select * from packets'):
            print row

    def get_ip_generator_of_traffic(self, ip1, ip2):
        print 'entered'
        print ip1
        print ip2
        query = "SELECT D.IP FROM ( SELECT C.IP, COUNT(C.IP) AS COUNT FROM ( SELECT A.ip_src AS IP, A.data FROM packets A WHERE A.ip_src=? UNION SELECT B.ip_dst AS IP, B.data FROM packets B WHERE B.ip_dst=? ) AS C GROUP BY C.IP ) AS D WHERE D.COUNT=( SELECT MAX(H.COUNT) FROM ( SELECT COUNT(G.IP) AS COUNT FROM ( SELECT E.ip_src AS IP, E.data FROM packets E WHERE E.ip_src=? UNION SELECT F.ip_dst AS IP, F.data FROM packets F WHERE F.ip_dst=? ) AS G GROUP BY G.IP ) AS H)"
        for row in self.cursor.execute(query, (ip1, ip2, ip1, ip2)):
            print row
            return row[0]
