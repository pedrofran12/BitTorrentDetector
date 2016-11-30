import os
import csv
import threading
import webbrowser

filename = "interface/cap.csv"
url = "http://localhost:3000"

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
        pass
