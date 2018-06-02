import datetime

from flask import Flask
from flask import g
from flask import redirect
from flask import request
from flask import session, jsonify
from flask import url_for, abort, render_template, flash
from functools import wraps
from hashlib import md5
from peewee import *
from playhouse.shortcuts import model_to_dict, dict_to_model
import uuid
from pprint import pprint

DEBUG = True
SECRET_KEY = 'hin6bab8ge25*r=x&amp;+5$0kn=-#log$pt^#@vrqjld!^2ci@g*b'

app = Flask(__name__)
app.config.from_object(__name__)

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

class Devices(BaseModel):
    id = UUIDField(primary_key=True)
    name = CharField()
    type = CharField()

class Subscribe(BaseModel):
    users_id = ForeignKeyField(Users)
    devices_id = ForeignKeyField(Devices)

def auth_user(user):
    session['logged_in'] = True
    session['user_id'] = user.id
    session['username'] = user.username
    flash('You are logged in as %s' % (user.username))

def get_current_user():
    if session.get('logged_in'):
        return Users.get(Users.id == session['user_id'])
    else:
        return "no user currently logged in"

def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return inner

# def object_list(template_name, qr, var_name='object_list', **kwargs):
#     kwargs.update(
#         page=int(request.args.get('page', 1)),
#         pages=qr.count() / 20 + 1)
#     kwargs[var_name] = qr.paginate(kwargs['page'])
#     return render_template(template_name, **kwargs)
#
# def get_object_or_404(model, *expressions):
#     try:
#         return model.get(*expressions)
#     except model.DoesNotExist:
#         abort(404)

@app.before_request
def before_request():
    g.db = database
    g.db.connect()

@app.after_request
def after_request(response):
    g.db.close()
    return response

@app.route('/')
@login_required
def homepage():
    if session.get('logged_in'):
        return "homepage"
    else:
        return abort(404)

@app.route('/register/', methods=['GET', 'POST'])
def join():
    if request.method == 'POST' and request.form['username']:
        try:
            with database.atomic():
                user = Users.create(
                    id=uuid.uuid4(),
                    name=request.form['name'],
                    username=request.form['username'],
                    password=md5((request.form['password']).encode('utf-8')).hexdigest(),
                    email=request.form['email'],
                    join_date=datetime.datetime.now())

            auth_user(user)
            return redirect(url_for('homepage'))

        except IntegrityError:
            flash('That username is already taken')

    return homepage()

@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and request.form['username']:
        try:
            pw_hash = md5(request.form['password'].encode('utf-8')).hexdigest()
            user = Users.get(
                (Users.username == request.form['username']) &
                (Users.password == pw_hash))
        except Users.DoesNotExist:
            flash('The password entered is incorrect')
        else:
            auth_user(user)
            return "login success"

    return "you are not logged in"

@app.route('/logout/')
def logout():
    session.pop('logged_in', None)
    return "you were logged out"

@app.route('/users/<string:username>/', methods=['GET'])
def user_detail(username):
    if request.method == 'GET':
        try:
            users = Users.select().where(Users.username == username).get()
            res = jsonify({
                'id': users.id,
                'name': users.name,
                'username': users.username,
                'password': users.password,
                'email': users.email,
                })
            res.status_code = 200
        except Users.DoesNotExist:
            output = {
                "error": "No results found. Check url again",
                "url": request.url,
            }
            res = jsonify(output)
            res.status_code = 404
        return res

@app.route('/currentuser/', methods=['GET'])
def currentuser():
    try:
        res = jsonify({'current_user': get_current_user().username})
        res.status_code = 200
        return res
    except Exception as e:
        return str(get_current_user())

@app.route('/createdevice/', methods=['GET', 'POST'])
def createdevice():
    if request.method == 'POST' and request.form['name']:
        try:
            with database.atomic():
                device = Devices.create(
                    id=uuid.uuid4(),
                    name=request.form['name'],
                    type=request.form['type'],)

            return redirect(url_for('homepage'))

        except IntegrityError:
            flash('error create device data')

    return homepage()

@app.route('/devices/', methods=['GET'])
def devices():
    if request.method == 'GET':
        try:
            devicelist = []
            devices = Devices.select().order_by(Devices.name)
            for device in devices:
                data = devicelist.append({
                    'id': device.id,
                    'name': device.name,
                    'type': device.type,
                    })
            res = jsonify(devicelist)
            res.status_code = 200
        except Devices.DoesNotExist:
            # if no results are found.
            output = {
                "error": "No results found. Check url again",
                "url": request.url,
            }
            res = jsonify(output)
            res.status_code = 404
        return res

@app.route('/devices/<string:id>/', methods=['GET'])
def device_detail(id):
    if request.method == 'GET':
        try:
            device = Devices.select().where(Devices.id == id).get()
            res = jsonify({
                'id': device.id,
                'name': device.name,
                'type': device.type,
                })
            res.status_code = 200
        except Devices.DoesNotExist:
            output = {
                "error": "No results found. Check url again",
                "url": request.url,
            }
            res = jsonify(output)
            res.status_code = 404
        return res

@app.route('/subscribe/', methods=['GET', 'POST'])
def subscribe():
    if request.method == 'POST' and request.form['deviceid']:
        try:
            with database.atomic():
                subscribe = Subscribe.create(
                    users_id=get_current_user().id,
                    devices_id=request.form['deviceid'],)

            return redirect(url_for('homepage'))

        except IntegrityError:
            flash('error create device data')

    return homepage()

@app.route('/unsubscribe/', methods=['GET', 'POST'])
def unsubscribe():
    if request.method == 'POST' and request.form['deviceid']:
        try:
            with database.atomic():
                unsubscribe = Subscribe.delete().where( Subscribe.users_id == get_current_user().id, Subscribe.devices_id == request.form['deviceid'] )
                unsubscribe.execute()
            return redirect(url_for('homepage'))

        except IntegrityError:
            flash('error delete subscribe data')

    return homepage()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
