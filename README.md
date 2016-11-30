# BitTorrentDetector
BitTorrent traffic detector. Project made for the FCS (Forensics Cyber-Security) course in the first semester of 2016.

## Instalation
```
$ git clone https://github.com/pedrofran12/BitTorrentDetector
$ cd BitTorrentDetector
```

Install requirements
```
$ apt-get install python python-pip tshark
$ pip install -r requirements.txt
$ wget http://download.memsql.com/memsql-ops-5.5.3/memsql-ops-5.5.3.tar.gz
$ tar -xzf memsql-ops-5.5.3.tar.gz
$ cd memsql-ops-5.5.3
$ ./install.sh
```
(it might need to run as sudo to install those)


To run the web interface, you will need to have Node.JS installed
We strongly recommend installing node through the [Node Version Manager](https://github.com/creationix/nvm)

After intall Node.JS, install all the node dependencies
```
$ npm install
```

## Usage
```
$ python main.py
```
(you migth need sudo privileges to perform a live capture)


To use the web interface, you will need to start Node.JS local server
```
$ cd interface
$ npm run start
```

## Authors
[Pedro Oliveira @pedrofran12](https://github.com/pedrofran12)

[Luís Duarte @luisrafael1995](https://github.com/luisrafael1995)

[Joao Tiago @johnytiago](https://github.com/johnytiago)
