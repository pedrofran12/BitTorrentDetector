
var Writable = require('readable-stream/writable')
var inherits = require('inherits')
var xtend = require('xtend')

function creator(ctor) {
  return function (options, write, onFinish) {
    if ('function' === typeof options) {
      onFinish = write
      write = options
      options = {}
    }
    
    if ('function' !== typeof write)
      throw new Error('`write` must be a function')
    
    if ('function' !== typeof onFinish)
      onFinish = null

    return ctor(options, write, onFinish)
  }
}

function prime(w, write, onFinish) {
  w._write = write
  
  if ('function' === typeof onFinish)
    w.on('finish', onFinish)

  return w
}

module.exports = exports = creator(function (options, write, onFinish) {
  return prime(new Writable(options), write, onFinish)
})

exports.obj = creator(function (options, write, onFinish) {
  // this will ALWAYS be an object stream
  options = xtend(options, { objectMode: true })
  return prime(new Writable(options), write, onFinish)
})

exports.ctor = creator(function (options, write, onFinish) {
  function Writer(opts) {
    Writable.call(this, xtend({}, options, opts))
    if ('function' === typeof onFinish)
      this.on('finish', onFinish)
  }

  inherits(Writer, Writable)

  Writable.prototype._write = write

  return Writer
})
