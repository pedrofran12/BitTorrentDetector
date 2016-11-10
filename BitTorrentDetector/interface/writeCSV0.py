import csv
from pylocker import Locker

# Run this before starting to write to a file, run it once to specify the
# headers and then start using writeLine(), otherwise the parser will not know
# the name of the headers and therefore fail the parsing
def join_string (row):
    string = ''
    for i in row:
        if string != '':
            string += ','
        string += i
    return string+'\n'

def init():
    f = open('BitTorrentDetector/interface/cap.csv', 'w')
    f.write(join_string(['ip', 'mac', 'host', 'hash', 'date']))
    f.flush()
    f.close()
    # no need to release anything because with statement takes care of that
    return

def writeLine( row ):
    f = open('BitTorrentDetector/interface/cap.csv', 'a')
    f.write(join_string(row))
    f.flush()
    f.close()
    # no need to release anything because with statement takes care of that
    return
