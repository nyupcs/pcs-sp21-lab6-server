from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from pcs_verify import pcs_verify
import os
from werkzeug.security import check_password_hash
import sqlite3

# Flask
app = Flask(__name__)

# PCS Forum
users = {}
DATABASE = 'lab6.db'

def get_db():

    db = sqlite3.connect(DATABASE)
    return db
    
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def init():
    flagvalue = open('flag').read().strip()
    get_db().execute("CREATE TABLE flag(id INTEGER PRIMARY KEY AUTOINCREMENT, flag TEXT)")
    conn=get_db()
    conn.execute("INSERT INTO flag(id, flag) VALUES(NULL, ?)", (flagvalue,))
    conn.commit()
    
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    if g.user:
        return redirect(url_for('profile', username=g.user))
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        error = None

        if username not in users:
            error = 'Incorrect username.'
        elif not check_password_hash(users[username]['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['username'] = username

            flash("Welcome back, {}!".format(users[username]['name']), 'success')

            return redirect(url_for('profile', username=username))

        flash(error, 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()

    flash("You have been logged out successfully.", 'success')

    return redirect(url_for('index'))


@app.route('/profile/<username>')
def profile(username):
    if username not in users:
        flash("The username does not exist!", 'danger')
        return redirect(url_for('index'))

    if username != g.user and not users[username]['public']:
        flash("{}'s profile is not public!".format(users[username]['name']), 'warning')
        return redirect(url_for('index'))

    user = users[username]

    return render_template(
        'profile.html',
        username=username,
        name=user['name'],
        avatar=user['avatar'],
        slogan=user['slogan'],
        description=user['description'],
        visibility=user['public']
    )


@app.route('/profile/<username>/edit', methods=('GET', 'POST'))
def edit_profile(username):
    if not g.user or g.user != username:
        flash("You don't have permission to edit this profile!", 'danger')
        return redirect(url_for('profile', username=username))

    if request.method == 'POST':
        if 'slogan' in request.form:
            users[username]['slogan'] = request.form['slogan']

        if 'description' in request.form:
            users[username]['description'] = request.form['description']

        flash("Your profile has been updated!", 'success')

        return redirect(url_for('profile', username=username))

    user = users[username]

    return render_template(
        'edit_profile.html',
        username=username,
        name=user['name'],
        avatar=user['avatar'],
        slogan=user['slogan'],
        description=user['description']
    )
    


    
@app.route('/profile/<username>/secret', methods=('GET', 'POST'))
def see_secret(username):
    if not g.user or g.user != username:
        flash("You don't have permission to edit this profile!", 'danger')
        return redirect(url_for('profile', username=username))

    if request.method == 'POST':
    
        secret_s=None
        if 'secret' in request.form:
            search= request.form['secret']
            query='select secret from secrets where name='+"'"+search+"'"
            secret_s=query_db(query)
            print(secret_s)
        string="".join(x[0] for x in secret_s)
        if string:
            flash("Your secret is   "+string, 'success')
        else:
            flash("None one of name "+search+" found", 'success')


    user = users[username]

    return render_template(
        'see_secret.html',
        username=username,
        name=user['name'],
        avatar=user['avatar'],
        slogan=user['slogan'],
        description=user['description']
    )


@app.route('/profile/<username>/visibility')
def set_visibility(username):
    if not g.user or g.user != username:
        flash("You don't have permission to edit this profile!", 'danger')
        return redirect(url_for('profile', username=username))

    visibility = request.args.get('to', default='private')

    users[username]['public'] = (visibility == 'public')

    flash("Your profile visibility has been set to {}!".format(
        'public' if visibility == 'public' else 'private'
    ), 'success')

    return redirect(url_for('profile', username=username))


@app.before_request
def before_request():
    username = session.get('username')

    if username is None:
        g.user = None
    else:
        g.user = username

    g.users = {key: value['name'] for key, value in users.items()}


@app.route('/verify', methods=('GET', 'POST'))
def verify():
    code1 = ''

    if request.method == 'POST':

        code1 = request.form['code1']
        secret_s=None
        
        search= request.form['secret']
        query='select secret from secrets where name='+"'"+search+"'"
        secret_s=query_db(query)
        string="".join(x[0] for x in secret_s)
        if string:
            flash("Your secret is   "+string, 'success')
        else:
            flash('danger')

    return render_template('verify.html', code1=code1)


@app.route('/reset')
def reset():
    global users
    users = default_user_info()

    flash("All profiles have been reset!", "success")

    return redirect(url_for('index'))


def default_user_info():
    return {
        'catrina': {
            'username': 'catrina',
            'password': 'pbkdf2:sha256:150000$sd8iXVUr$6882dfebceb7ce71a242667fdec076bc93e33b22d42e51edf3cb9fe1d454c501',
            'name': 'Catrina',
            'avatar': '8918ce317a7726255b37fe972a423c3b',
            'slogan': 'Hi, my name is Catrina!',
            'description': '',
            'public': True
        },
        'hugh': {
            'username': 'hugh',
            'password': 'pbkdf2:sha256:150000$UphSisaZ$5ed91664ffa2c8e4dee9844045902f43b8bc47c0491ba482b24ed573dfb93737',
            'name': 'Hugh',
            'avatar': '491dbec39f772fb5ac326b6829faf542',
            'slogan': 'And my name is Hugh.',
            'description': '',
            'public': False
        },
        'sarah': {
            'username': 'sarah',
            'password': '',
            'name': 'Sarah',
            'avatar': 'b0afb5dba0df5de740d72f14c22ea075',
            'slogan': 'I am Sarah!',
            'description': '',
            'public': True
        },
        'emma': {
            'username': 'emma',
            'password': '',
            'name': 'Emma',
            'avatar': '421a669761c59f3278735113941a55c0',
            'slogan': 'I am Emma!',
            'description': '',
            'public': False
        },
        'joe': {
            'username': 'joe',
            'password': '',
            'name': 'Joe',
            'avatar': '10fc31fcdefb8126b67fd3a5404ce65a',
            'slogan': 'And I am Joe to you.',
            'description': '',
            'public': False
        },
        'samy': {
            'username': 'samy',
            'password': '',
            'name': 'Samy',
            'avatar': '3bc011b83a83224e97ee34fdd8fe35ea',
            'slogan': '',
            'description': '',
            'public': True
        }
    }


if __name__ == '__main__':
    init()
    users = default_user_info()
    app.config['SECRET_KEY'] = os.urandom(16)
    app.config['SESSION_COOKIE_NAME'] = 'pcs'
    app.config['SESSION_COOKIE_HTTPONLY'] = False
    app.run(host="0.0.0.0", port=4000)
