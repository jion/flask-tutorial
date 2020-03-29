import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    def render_form():
        return render_template('auth/register.html')

    if request.method != 'POST':
        return render_form()

    username = request.form['username']
    password = request.form['password']
    db = get_db()

    error = None
    if not username:
        error = 'Username is required'
    elif not password:
        error = 'Password is required'
    else:
        existent_user = db.execute(
                'SELECT id FROM user WHERE username = ?', (username,)
                ).fetchone()
        if existent_user is not None:
            error = 'User {} is already registered.'.format(username)

    if error is not None:
        flash(error)
        return render_form()

    db.execute(
        'INSERT INTO user (username, password) VALUES (?, ?)',
        (username, generate_password_hash(password))
    )
    db.commit()

    return redirect(url_for('auth.login'))


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method != 'POST':
        return render_template('auth/login.html')

    username = request.form['username']
    password = request.form['password']

    db = get_db()
    user = db.execute(
        'SELECT * FROM user WHERE username = ?', (username,)
    ).fetchone()

    error = None
    if user is None or not check_password_hash(user['password'], password):
        flash(error)
        return render_template('auth/login.html')

    session.clear()
    session['user_id'] = user['id']
    return redirect(url_for('index'))


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
