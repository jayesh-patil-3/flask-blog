import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

# from flaskblog.db import get_db
from flask_blog.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute(
                'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.execute(
                'INSERT INTO user (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        '''
        session is a dict that stores data across requests. When validation succeeds, 
        the user’s id is stored in a new session. The data is stored in a cookie that is sent to the browser, 
        and the browser then sends it back with subsequent requests. 
        
        Flask securely signs the data so that it can’t be tampered with.
        '''
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')


'''
Now that the user’s id is stored in the session, it will be available on subsequent requests. 
At the beginning of each request, if a user is logged in their information should be loaded and made available to other views.
'''


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


''' To log out, you need to remove the user id from the session '''


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


"""
Creating, editing, and deleting blog posts will require a user to be logged in.
A decorator can be used to check this for each view it’s applied to.

This decorator returns a new view function that wraps the original view it’s applied to.
The new function checks if a user is loaded and redirects to the login page otherwise.
If a user is loaded the original view is called and continues normally. You’ll use this decorator when writing the blog views.
"""


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
