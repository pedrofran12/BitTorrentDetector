Bit Torrent Trafic Detector
=====================

## The interface

This is just an web interface of the BT Trafic Detector.  
It consumes a CSV (Comma Separated Value) file, that, currently must be named **`cap.csv`**

It is built on [Node.JS](https://nodejs.org/en/) using [Socket.io](https://github.com/user/repo/blob/branch/other_file.md) and [React](https://facebook.github.io/react/)

## Dependencies

To run the web interface you will need to have Node.JS installed
We strongly recomend installing node through the [Node Version Manager](https://github.com/creationix/nvm)

### Linux
Either way ** Do not try `apt-get install nodejs` **
The repo is too old and not updated

[User this instead](http://workshop.botter.ventures/2015/10/23/how-to-install-node-js-using-nvm-on-ubuntu/)

## Instalation
Install all the node dependencies
```
$ npm install
```
If it takes too long use yarn
`npm install yarn -g` then use `yarn` as regular `npm`

## Usage

`npm run test` this continuously generates a CSV (`cap.csv`) and then runs the interface over it
