from flask import render_template, flash, redirect, url_for
from flask import request
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse

from app import app, db
from app.forms import LoginForm, RegistrationForm
from app.models import User


@app.route('/')
@app.route('/index')
@login_required
def index():
    user = {'username': 'Oasis'}
    posts =[
        {
            'author':{'username':'John'},
            'body':'Rainy day in Kobe'
        },
        {
            'author':{'username': 'Susan'},
            'body': 'The Avengers movie was so cool!'
        }
    ]

    return render_template('index.html', title='Home Page', posts=posts)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        # check if there is a record with that username
        user = User.query.filter_by(username=form.username.data).first()
        # check whether that user was found and the entered password corresponds
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        # in case all is well mark the user as logged in and pass the data for remember

        login_user(user, remember=form.remember_me.data)
        # try to see if there is next in the variables in the route
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            # in case there is no next variable or we are given an external link bring the user to the index page
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


# Logout method

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


# register route

@app.route('/register', methods=['GET', 'POST'])
def register():
    # in case the user is already authenticated dont bother
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # create the user object with the inserted data
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


# profile page
@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'body': 'Test post #1'},
        {'author': user, 'body': 'Test post #2'}
    ]
    return render_template('user.html', user=user, posts=posts)
