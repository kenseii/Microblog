from datetime import datetime

from flask import jsonify
from flask import render_template, flash, redirect, url_for, request, g
from flask_babel import _, get_locale
from flask_login import login_user, logout_user, current_user, login_required
from guess_language import guess_language
from werkzeug.urls import url_parse

from app import app, db
from app.email import send_password_reset_email
from app.forms import LoginForm, RegistrationForm, EditProfileForm, PostForm, \
    ResetPasswordRequestForm, ResetPasswordForm
from app.models import User, Post
from app.translate import translate


# index page form

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    form = PostForm()
    if form.validate_on_submit():
        # try and get the language of the post and save it
        language = guess_language(form.post.data)
        if language == 'UNKNOWN' or len(language) > 5:
            language = ''
        post = Post(body=form.post.data, author=current_user, language=language)
        db.session.add(post)
        db.session.commit()
        flash(_('Your post is now live!'))
        return redirect(url_for('index'))
    # pagination
    page = request.args.get('page', 1, type=int)
    posts = current_user.followed_posts().paginate(
        page,
        app.config['POSTS_PER_PAGE'], False
    )
    next_url = url_for('index', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num) \
        if posts.has_prev else None

    return render_template("index.html",
                           title='Home Page',
                           form=form,
                           posts=posts.items,
                           next_url=next_url,
                           prev_url=prev_url)


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
            flash(_('Invalid username or password'))
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
        flash(_('Congratulations, you are now a registered user!'))
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


# profile page
@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('user', username=user.username, page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('user', username=user.username, page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('user.html', user=user, posts=posts.items,
                           next_url=next_url, prev_url=prev_url)

# record last visit
@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
    # tells moment which language to use for dates
    g.locale = str(get_locale())


# edit profile form
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash(_('Your changes have been saved.'))
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html',
                           title='Edit Profile',
                           form=form)


# follow route


@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(_('User %(username)s not found.', username=username))
        return redirect(url_for('index'))
    if user == current_user:
        flash(_('You cannot follow yourself!'))
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    db.session.commit()
    flash(_('You are following %(username)s!', username=username))
    return redirect(url_for('user', username=username))


# Unfollow route


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(_('User %(username)s not found.', username=username))
        return redirect(url_for('index'))
    if user == current_user:
        flash(_('You cannot unfollow yourself!'))
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash(_('You are not following %(username)s.', username=username))
    return redirect(url_for('user', username=username))


# timeline route

@app.route('/explore')
@login_required
def explore():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False
    )
    next_url = url_for('explore', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('explore', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('index.html',
                           title='Explore',
                           posts=posts.items,
                           next_url=next_url,
                           prev_url=prev_url)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    # if the user is already signed in, if so redirect to index
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        # when it is submitted and valid check if that email is in the db
        user = User.query.filter_by(
            email=form.email.data
        ).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password',
                           form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # check if authenticated if so bring to home
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # else try to verify token
    user = User.verify_reset_password_token(token)
    # case the user is not found in the db bring home
    if not user:
        print("Invalid token")
        return redirect(url_for('index'))
    # call the reset form
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/translate', methods=['POST'])
@login_required
def translate_test():
    return jsonify(
        {'text': translate(
            request.form['text'],
            request.form['source_language'],
            request.form['dest_language']
        )}
    )
