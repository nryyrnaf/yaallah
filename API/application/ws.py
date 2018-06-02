from flask import Flask, render_template, request
from flask_socketio import SocketIO, Namespace, emit, send
import logging
import pika
from threading import Thread

logging.basicConfig(level=logging.INFO)
DEBUG = True
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
logging.info('Connected: RabbitMQ Server')

clients = []
threadRMQ = None
channel = connection.channel()

def disconnect_to_rabbitmq():
	channel.stop_consuming()
	connection.close()
	logging.info('Disconnected from Rabbitmq')


def consumer_callback(ch, method, properties, body, client):
    logging.info("[x] Received %r" % (body,))
    print client
    socketio.emit('hello', 'world', room=client, namespace='\ws')

def threaded_rmq(sid):
    channel.exchange_declare(exchange='logs', exchange_type='fanout')
    result = channel.queue_declare(exclusive=True)
    queue_name = result.method.queue
    channel.queue_bind(exchange='logs', queue=queue_name)
    logging.info('consumer ready, on my_queue')
    logging.info(sid)
    channel.basic_consume(lambda ch, method, properties, body: consumer_callback(ch, method, properties, body, client = sid), queue=queue_name, no_ack=True)
    channel.start_consuming()

@socketio.on('connect', namespace='/ws')
def test_connect():
    threadRMQ = Thread(target=threaded_rmq, kwargs=dict(sid=request.sid))
    threadRMQ.start()
    emit('hello', 'connected')
    logging.info('WebSocket opened')
    # logging.info(request.namespace.socket)
    clients.append(request.sid)

@socketio.on('disconnect', namespace='/ws')
def on_disconnect():
    # print "status: "+ str(self.threadRMQ.isAlive())
    channel.stop_consuming()
    # print "status: "+ str(self.threadRMQ.isAlive())
    logging.info('WebSocket closed')

if __name__ == '__main__':
    logging.info('Server Starts')
    socketio.run(app, port=8000, host='0.0.0.0')
