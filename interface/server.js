const express = require('express')
const app = express()  
const server = require('http').Server(app)
const io = require('socket.io')(server)

const writable = require('writable2')
const ts = require('tail-stream');
const csv = require('csv-parser');

const webpack = require('webpack')
const webpackDevMiddleware = require('webpack-dev-middleware')
const webpackHotMiddleware = require('webpack-hot-middleware')
const config = require('./webpack.config');
const compiler = webpack(config)

app.use(webpackDevMiddleware(compiler, {  
    publicPath: config.output.publicPath,  
    stats: {colors: true}  
}))

app.use(webpackHotMiddleware(compiler, {  
    log: console.log 
}))

const router = express.Router()  

router.get('/', (req, res) => {
  res.sendFile('index.html', {root: '.'})
})  

io.on('connection', function (socket) {
  console.log('New connection')

  var csvStream = csv()
  var tstream = ts.createReadStream('cap.csv')
  .pipe(csvStream)

  csvStream.on("data", function(data){
    socket.emit('data', data)
  })
  csvStream.on("end", function(){
       console.log("done");
  });
  tstream.on('eof', function() {
      console.log("reached end of file");
  });
});

app.use(router) 
server.listen(3000,  () => {console.log('listening on 3000')})
