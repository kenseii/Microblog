from datetime import datetime
from hashlib import md5
from time import time

import jwt
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login, app

# followers association table


followers = db.Table('followers',
                     db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
                     db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
                     )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    # reference back to followed from followers
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic'
    )

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # get gravatar of that user

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size
        )

    # enabling users to follow/unfollow other users

    def follow(self, user):
        # check if not following already before appending
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        # check if was following before unfollowing
        if self.is_following(user):
            self.followed.remove(user)

    # check if a link between 2 users already exists
    # then return 0 or 1 depending on whether there is existing follow or not
    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    # returning the posts from users followed by the user

    def followed_posts(self):
        # join the posts and followers by author == followed user
        # filter and retain only data with follower == current user
        # get posts created by the current user
        # join both and order
        followed = Post.query.join(
            followers, (followers.c.followed_id == Post.user_id)).filter(
            followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)

        return followed.union(own).order_by(Post.timestamp.desc())

    # for resetting password
    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    # once the user clicks on the link lauch me to verify
    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(
                token, app.config['SECRET_KEY'],
                algorithms=['HS256'])['reset_password']

        except:
            return
        return User.query.get(id)


# adding on posts


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)


# loads info about the user given the id


@login.user_loader
def load_user(id):
    return User.query.get(int(id))
