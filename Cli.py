import os.path
from texttable import Texttable
import threading

class Cli:
    def __init__(self):
        os.system('clear')
        self.table = Texttable()
        self.lock = threading.Lock()
        self.table.add_row(['IP', 'MAC', 'Hostname', 'Hash', 'Torrent Description', 'Date', 'Type of Detection'])
        self.table.set_cols_align(["c", "c", "c", "c", "c", "c", "c"])
        self.table.set_cols_width([15, 17, 8, 30, 30, 19, 17])
        print(self.table.draw())
        return

    def writeLine(self, row ):
        self.lock.acquire()
        self.table.add_row(row)
        os.system('clear')
        print(self.table.draw())
        self.lock.release()
        return

    def finish(self):
        target = open('log.txt', 'w')
        target.write(self.table.draw())
        target.close()
