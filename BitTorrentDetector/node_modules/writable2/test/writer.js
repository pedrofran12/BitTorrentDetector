var test = require('tape')
var writable = require('../')

test('basic writable', function (t) {
  var dataIn = ['a', 'b', 'c', 'd']
  var dataOut = ['a', 'b', 'c', 'd']
  var count = 0

  var w = writable(function (d, e, n) {
    var v = d.toString()
    var a = dataOut[count++]
    t.equals(v, a, v + ' should equal ' + a)
    n()

    if (count === dataOut.length)
      t.end()
  })
  
  dataIn.forEach(function (v, i) {
    ((i + 1) !== dataIn.length)
      ? w.write(v)
      : w.end(v)
  })

})

test('basic objectMode', function (t) {
  var dataIn = ['a', 'b', 'c', 'd']
  var dataOut = ['a', 'b', 'c', 'd']
  var count = 0

  var w = writable.obj(function (d, e, n) {
    var v = d
    var a = dataOut[count++]
    t.equals(v, a, v + ' should equal ' + a)
    n()

    if (count === dataOut.length)
      t.end()
  })
  
  dataIn.forEach(function (v, i) {
    ((i + 1) !== dataIn.length)
      ? w.write(v)
      : w.end(v)
  })
})

test('basic from constructor', function (t) {
  var dataIn = ['a', 'b', 'c', 'd']
  var dataOut = ['a', 'b', 'c', 'd']
  var count = 0

  var W = writable.ctor(function (d, e, n) {
    var v = d.toString()
    var a = dataOut[count++]
    t.equals(v, a, v + ' should equal ' + a)
    n()

    if (count === dataOut.length)
      t.end()
  })

  var w = new W()
  
  dataIn.forEach(function (v, i) {
    ((i + 1) !== dataIn.length)
      ? w.write(v)
      : w.end(v)
  })

})
