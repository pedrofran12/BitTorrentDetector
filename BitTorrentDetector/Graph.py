import interface.writeCSV0 as writeCSV
from prettytable import PrettyTable

class Graph:
    def __init__(self):
        self.table = PrettyTable(['IP', 'MAC', 'Hostname', 'Hash', 'Torrent Description', 'Date'])
        writeCSV.init()
        return

    def writeLine(self, row ):
        self.table.add_row(row)
        new = row
        del new[4]
        writeCSV.writeLine(new)
        return

    def finish(self):
        target = open('BitTorrentDetector/log.txt', 'w')
        target.write(self.table.get_string())
        target.close()
