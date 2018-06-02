var app = require('express')();
var server = require('http').createServer(app);
var io = require('socket.io')(server);
var amqp = require('amqplib');
var forEach = require('async-foreach').forEach;

let rabbitMqConnection


retryRmqConnection = () =>{
  if (rabbitMqConnection!==null)console.log('retry connection to rabbitMq')
    rabbitMq = amqp.connect('amqp://guest:guest@localhost:5672').then((conn) => {
    rabbitMqConnection = conn
    console.log('readyrabbit')
    // io.emit('rabbitOn', 'rabbit')
    conn.on('close', function(err){
      setTimeout( function() {
              retryRmqConnection()
          }, 0 );
    })
  }).catch( (err) => {
    rabbitMqConnection = null
    setTimeout( function() {
            retryRmqConnection()
        }, 0 );
  })
}
var rabbitMq = amqp.connect('amqp://guest:guest@localhost:5672').then((conn) => {
  rabbitMqConnection = conn
  conn.on('close', function(err){
    retryRmqConnection()
  })
}).catch((err)=>{
  console.log(err)
  retryRmqConnection()
})

// rabbitMq.on('ready', function())
io.on('connection', function (socket) {
  var consumerChannel;
  var id;
  console.log(socket.id+' connected');

  socket.on('disconnect', function () {
    console.log(socket.id+' disconnected');
    consumerChannel.deleteQueue(id).then(() => {
      return consumerChannel.close();
    });
  });

  socket.on('startRabbit', function(msg){
      console.log('startRabbit : ', msg)
      id = msg['id'];
      try {
        rabbitMqConnection.createChannel().then(function(ch) {
          consumerChannel = ch
          var q;
              function allDone(notAborted, arr) {
                ch.consume(q, logMessage, {noAck: true})
                .then(() => {
                  console.log(' [*] Waiting for '+msg['data']+'.');
                })
              }
              forEach(msg['data'], function (item, index, arr) {
                  var done = this.async()
                  var ok = ch.assertExchange(item, 'fanout', {durable: false});
                  ok = ok.then(function() {
                    return ch.assertQueue(msg['id'], {exclusive: false});
                  });
                  ok = ok.then(function(qok) {
                    return ch.bindQueue(qok.queue, item, '').then(function() {
                      q = qok.queue
                      return qok.queue;
                    });
                  });
                  ok = ok.then(function() {
                    done()
                  })
              }, allDone)

              function logMessage(msg) {
                console.log("emitting : ", msg.content.toString());
                console.log(socket.id)
                socket.emit('consume', msg.content.toString())
              }
          }).catch(console.warn);
      }
      catch(err){
        console.log(err)
      }
    })


});

server.listen(8000, function(){
  console.log('listening on *:8000');
});
