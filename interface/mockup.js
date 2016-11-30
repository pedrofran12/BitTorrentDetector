const Chance = require('chance')
const chance = new Chance()

const fs = require('fs')
const csvWriter = require('csv-write-stream')
var writer

const EventEmitter = require('events')
class eventEmitter extends EventEmitter {}
const WriteLine = new eventEmitter();

WriteLine.on('begin', () => {
  const ws = fs.createWriteStream('cap.csv', {
    flags: 'w+',
    defaultEncoding: 'utf8',
  });

  writer = new csvWriter({ headers: ["ip", "mac", "host", "hash", "description", "date", "detectiontype"] })
  writer.pipe(ws)
})

WriteLine.on('data', data => {
  var { ip, mac, host, hash, date, detectiontype} = data;
  writer.write({ ip, mac, host, hash, date, detectiontype})
})

WriteLine.on('end', () => {
  writer.end()
})

WriteLine.emit('begin')

var interval = setInterval(() => {
  WriteLine.emit('data', {
    ip: chance.ip(),
    mac: chance.mac_address(),
    host: chance.name().replace(/\s+/g, '')+'-PC',
    hash: chance.hash(),
    date: chance.date({string: true, american: false}),
    detectiontype: 'packet inspection'
  })
}, 1000)

setTimeout(() => {
  clearInterval(interval)
  WriteLine.emit('end')
}, 120*1000)
