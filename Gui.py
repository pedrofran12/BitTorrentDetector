import os
import csv
import threading
import webbrowser
import subprocess
import time
import signal
from texttable import Texttable

filename = "interface/cap.csv"
url = "http://localhost:3000"
command = "cd interface && npm run start"

def clearFile():
    fd = open(filename, 'w')
    fd.flush()
    fd.close()

def writeRow(row):
    fd = open(filename, 'a')
    csv.writer(fd).writerow(row)
    fd.flush()
    fd.close()


class Gui:
    def __init__(self):
        self.lock = threading.Lock()
        self.process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
        time.sleep(5)
        clearFile()
        writeRow(["ip", "mac", "host", "hash", "description", "date", "detectiontype"])
        webbrowser.open_new(url)
        return

    def writeLine(self, row ):
        self.lock.acquire()
        writeRow(row)
        self.lock.release()
        return

    def finish(self):
        os.killpg(self.process.pid, signal.SIGTERM)
        table = Texttable()
        table.set_cols_align(["c", "c", "c", "c", "c", "c", "c"])
        table.set_cols_width([15, 17, 8, 30, 30, 19, 17])
        fd = open(filename, 'r')
        lines = fd.readlines()
        fd.close()
        for i in range(len(lines)):
            table.add_row(lines[i].split(','))
        target = open('log.txt', 'w')
        target.write(table.draw())
        target.close()
