# Writable2


[![Build Status](https://travis-ci.org/sonewman/writable2.svg?branch=master)](http://travis-ci.org/sonewman/writable2)

Inspired by the two great `through` stream modules ([through](https://github.com/dominictarr/through) and [through2](https://github.com/rvagg/through2))

This is a simple way to create a `writable` stream

```javascript
var writable = require('writable2')

someReadable.pipe(writable(function (data, enc, next) {
  // do something with `data`
  next()
}))

```

## Usage:

### writable([options, ] write [, onFinish])
Will create a standard writable stream which requires all written data to be a `string` or `buffer`

### writable.obj([options, ] write [, onFinish])
Will create an writable stream in `objectMode` which means that an object can be written to the stream

### writable.ctor([options, ] write [, onFinish])
Will create a constructor for a writable stream with the specified arguments
