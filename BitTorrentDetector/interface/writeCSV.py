import csv
from pylocker import Locker

# Run this before starting to write to a file, run it once to specify the
# headers and then start using writeLine(), otherwise the parser will not know
# the name of the headers and therefore fail the parsing
def init():
    FL = Locker(filePath='BitTorrentDetector/interface/cap.csv', lockPass="passwd", mode='w', timeout=20, wait=0.05)
    with FL as r:
        acquired, code, fd  = r
        if fd is not None:
            spamwriter = csv.writer(fd);
            spamwriter.writerow(['ip', 'mac', 'host', 'hash', 'date'])
    # no need to release anything because with statement takes care of that
    return

def writeLine( row ):
    FL = Locker(filePath='BitTorrentDetector/interface/cap.csv', lockPass="passwd", mode='a', timeout=20, wait=0.05)
    with FL as r:
        acquired, code, fd  = r
        if fd is not None:
            spamwriter = csv.writer(fd);
            spamwriter.writerow(row)
    # no need to release anything because with statement takes care of that
    return
