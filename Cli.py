import os.path
from prettytable import PrettyTable

class Cli:
    def __init__(self):
        os.system('clear')
        self.table = PrettyTable(['IP', 'MAC', 'Hostname', 'Hash', 'Torrent Description', 'Date', 'Type of Detection'])
        self.table.max_width = 40
        print(self.table)
        return

    def writeLine(self, row ):
        self.table.add_row(row)
        os.system('clear')
        print(self.table)
        return

    def finish(self):
        target = open('log.txt', 'w')
        target.write(self.table.get_string())
        target.close()
