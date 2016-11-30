import os
import csv
import threading
import webbrowser

filename = "interface/cap.csv"
url = "http://localhost:3000"

class Gui:
    def __init__(self):
        self.fd = open(filename, 'w')
        self.spamwriter = csv.writer(self.fd)
        self.lock = threading.Lock()
        self.spamwriter.writerow(["ip", "mac", "host", "hash", "description", \
                "date", "detectiontype"])
        webbrowser.open_new(url)
        return

    def writeLine(self, row ):
        self.lock.acquire()
        self.spamwriter.writerow(row)
        self.lock.release()
        return

    def finish(self):
        self.fd.close()
