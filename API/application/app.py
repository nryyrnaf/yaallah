import datetime

from flask import Flask
from flask import g
from flask import redirect
from flask import request
from flask import session, jsonify
from flask import url_for, abort, render_template, flash
from functools import wraps
from hashlib import md5
import uuid
import requests
from datetime import timedelta

DEBUG = True
SECRET_KEY = 'hin6bab8ge25*r=x&amp;+5$0kn=-#log$pt^#@vrqjld!^2ci@g*b'

app = Flask(__name__)
app.config.from_object(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)

def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return inner

def auth_user(object, token):
    session['logged_in'] = True
    session['userid'] = object['current_identity']
    session['username'] = object['current_username']
    session['email'] = object['current_email']
    session['role'] = object['current_role']
    session['token'] = token

@app.route('/')
def index():
    return render_template('index.html', data = session)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        login = requests.post('http://localhost:5555/login', json={ "username": username, "password":password })
        try:
            jwtoken = login.json()['access_token']
            headers = {'Authorization': 'Bearer %s' % jwtoken}
            auth =  requests.get('http://localhost:5555', headers = headers).json()
            auth_user(auth, jwtoken)
            return index()
        except Exception as e:
            return redirect(url_for('login'))

@app.route('/logout')
def logout():
    headers = { 'Authorization' : 'Bearer %s' % session['token'] }
    logout = requests.delete('http://localhost:5555/logout', headers = headers).json()
    # return jsonify(logout)
    session.pop('logged_in', None)
    session.pop('userid', None)
    session.pop('username', None)
    session.pop('email', None)
    session.pop('role', None)
    session.pop('token', None)
    return login()

@app.route('/users', methods=['GET'])
@login_required
def users():
    print session['token']
    headers = { 'Authorization' : 'Bearer %s' % session['token'] }
    users = requests.get('http://localhost:5555/users', headers = headers).json()
    # print devices
    return render_template('userlist.html', users = users)

@app.route('/users/<string:username>', methods=['GET'])
@login_required
def userdetail(username):
    print session['token']
    headers = { 'Authorization' : 'Bearer %s' % session['token'] }
    userdetail = requests.get('http://localhost:5555/users/%s' % username, headers = headers).json()
    print userdetail
    return render_template('userdetail.html', userdetail = userdetail)

@app.route('/devices', methods=['GET'])
@login_required
def devices():
    print session['token']
    headers = { 'Authorization' : 'Bearer %s' % session['token'] }
    devices = requests.get('http://localhost:5555/devices', headers = headers).json()
    # print devices
    return render_template('devicelist.html', devices = devices)

@app.route('/devices/<string:id>', methods=['GET'])
@login_required
def devicedetail(id):
    print session['token']
    headers = { 'Authorization' : 'Bearer %s' % session['token'] }
    devicedetail = requests.get('http://localhost:5555/devices/%s' % id, headers = headers).json()
    # print devicedetail['subscribed_by']
    subscriber = []
    try:
        for subscribe in devicedetail['subscribed_by']:
            subscriber.append(subscribe['id'])
        return render_template('devicedetail.html', devicedetail = devicedetail, subscriber = subscriber)
    except Exception as e:
        return render_template('devicedetail.html', devicedetail = devicedetail)


@app.route('/subscribe/devices', methods=['POST'])
@login_required
def subscribedevice():
    headers = { 'Authorization' : 'Bearer %s' % session['token'] }
    subscribe = requests.post('http://localhost:5555/subscribe/devices', headers = headers, json={ "deviceid": request.form['deviceid'] }).json()
    return redirect(request.url_root+'devices/%s' % request.form['deviceid'])

@app.route('/unsubscribe/devices', methods=['POST'])
@login_required
def unsubscribedevice():
    headers = { 'Authorization' : 'Bearer %s' % session['token'] }
    subscribe = requests.post('http://localhost:5555/unsubscribe/devices', headers = headers, json={ "deviceid": request.form['deviceid'] }).json()
    return redirect(request.url_root+'devices/%s' % request.form['deviceid'])

@app.route('/monitor', methods=['GET'])
@login_required
def monitor():
    headers = { 'Authorization' : 'Bearer %s' % session['token'] }
    monitor = requests.get('http://localhost:5555/users/%s' % session['username'], headers = headers).json()
    return render_template('monitor.html', monitor = monitor)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5555)
