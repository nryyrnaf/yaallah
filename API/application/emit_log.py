#!/usr/bin/python
import pika
import sys
from threading import Thread
from uuid import UUID
from peewee import *
import subprocess
import json
import time

database = MySQLDatabase('mydb', user='root', password='root', host='localhost', port=3316)

class BaseModel(Model):
    class Meta:
        database = database

class Users(BaseModel):
    id = UUIDField(primary_key=True)
    name = CharField()
    username = CharField(unique=True)
    password = CharField()
    email = CharField()
    role = CharField()

class Devices(BaseModel):
    id = UUIDField(primary_key=True)
    name = CharField()
    type = CharField()
    location = CharField()
    address = CharField()

class Oid(BaseModel):
    id = UUIDField(primary_key=True)
    oid = CharField()
    oidname = CharField()
    devices_id = ForeignKeyField(Devices)

class Subscribe(BaseModel):
    users_id = ForeignKeyField(Users)
    devices_id = ForeignKeyField(Devices)

def rabbitMq(exchange, address):
    try:
        deviceoid =  Oid.select().join(Devices).where(Oid.devices_id == exchange)
        oidList = []
        for oid in deviceoid:
            oidList.append({
            'oidname' : oid.oidname,
            'oid': oid.oid,
            'snmpresult' : None,
            'deviceid' : str(exchange)
            })
    except Exception as e:
        oidList = []
        for oid in deviceoid:
            oidList.append({
            'oidname' : None,
            'oid': None,
            'snmpresult' : None,
            'deviceid' : str(exchange)
            })

    for oid in oidList:
        p = subprocess.Popen(["/usr/local/nagios/libexec/check_snmp", "-H", address, "-o", oid['oid']], stdout=subprocess.PIPE)
        output, err = p.communicate()
        oid['snmpresult'] = output.split('|')[0]

    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()
    message = json.dumps(oidList)
    try:
        channel.basic_publish(exchange=str(exchange),
                              routing_key='',
                              body=message)
    except Exception as e:
        channel.exchange_declare(exchange=str(exchange),
                                 exchange_type='fanout')
        channel.basic_publish(exchange=str(exchange),
                              routing_key='',
                              body=message)
    print(" [x] Sent %r" % message)
    connection.close()

if __name__ == '__main__':

    while True:
        devices = Devices.select()
        deviceInfo = []
        for device in devices:
            deviceInfo.append({
             'id' : device.id,
             'address' : device.address
            })

        for info in deviceInfo:
            threadRMQ = Thread(target=rabbitMq, kwargs=dict(exchange=info['id'], address=info['address']))
            threadRMQ.start()
            threadRMQ.join()
        time.sleep(1)
