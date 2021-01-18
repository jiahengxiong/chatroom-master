import os
import click
import sys
import hashlib
from datetime import datetime
import time

from flask import Flask, render_template, request, url_for, redirect, flash
from flask_bootstrap import Bootstrap
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_socketio import SocketIO, emit
from lxml.html.clean import clean_html

from werkzeug.security import generate_password_hash, check_password_hash

WIN = sys.platform.startswith('win')
if WIN:
    prefix = 'sqlite:///'
else:
    prefix = 'sqlite:////'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'
app.config['SQLALCHEMY_DATABASE_URI'] = prefix + os.path.join(app.root_path, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 关闭对模型修改的监控
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
CSRFProtect(app)
socketio = SocketIO(app, async_mode='eventlet')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password = db.Column(db.String(128))
    password_hash = db.Column(db.String(128))
    messages = db.relationship('Message', back_populates='author', cascade='all')
    avatar_url = db.Column(db.String(256))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.username is not None and self.avatar_url is None:
            email = self.username + "@xuzichi.com"
            self.avatar_url = 'https://cdn.v2ex.com/gravatar/' + hashlib.md5(
                email.encode('utf-8')).hexdigest() + '?d=identicon'


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', back_populates='messages')


@app.after_request
def after_request(response):
    # 调用函数生成 csrf_token
    csrf_token = generate_csrf()
    # 通过 cookie 将值传给前端
    response.set_cookie("csrf_token", csrf_token)
    return response


@app.cli.command()  # 注册为命令
@click.option('--drop', is_flag=True, help='Create after drop.')  # 设置选项
def initdb(drop):
    """Initialize the database."""
    if drop:  # 判断是否输入了选项
        db.drop_all()
    db.create_all()
    click.echo('Initialized database.')  # 输出提示信息


@app.route('/test')
def test():
    return render_template('test.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('chat')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user is not None:
            if username == user.username and user.verify_password(password):
                login_user(user)
                flash('登陆成功')
                return redirect(url_for('chat'))
            flash('用户名或密码错误')
            return redirect(url_for('login'))
        else:
            flash('用户不存在，请注册')
            return redirect(url_for('register'))
        return redirect(url_for('login'))
    flash('欢迎进入登录界面')
    return render_template('login.html')


@app.route('/chat')
@login_required
def chat():
    user_list = db.session.query(User).order_by(User.id).all()
    user_list.reverse()
    if request.method == 'GET':
        message_list = db.session.query(Message).order_by(Message.id).all()
        message_list.reverse()
        message_list = message_list[:30]
        message_list.reverse()
    flash('欢迎进入聊天室')
    return render_template('chat.html', message_list=message_list, user_list=user_list)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已经退出登陆')
    return redirect('login')


@app.route('/', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        username = request.form['username']
        if request.form['password'] != request.form['password2']:
            flash('两次密码不同')
            return redirect('register')
        user = User.query.filter_by(username=username).first()
        if user is not None:
            flash('用户名已经存在.')
            return redirect(url_for('register'))

        password = request.form['password']
        username = request.form['username']
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    flash('欢迎进入注册界面')
    return render_template('register.html')


@socketio.on('new_message')
def new_message(content):
    print(content)
    message = Message(author=current_user._get_current_object(), content=clean_html(content))
    db.session.add(message)
    db.session.commit()
    emit('new_message', {'message_html': render_template('message.html', message=message)}, broadcast=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=80)
