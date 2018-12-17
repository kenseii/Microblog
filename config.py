import os

from dotenv import load_dotenv

# path to this main application folder
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    # for indicating the path to the sqlitedb
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Mail configs
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = ['oasisagano@gmail.com']
    # accepted languages
    LANGUAGES = ['en', 'es']
    # pagination setting
    POSTS_PER_PAGE = 3
    # get microsoft key from environment variable
    MS_TRANSLATOR_KEY = os.environ.get('MS_TRANSLATOR_KEY')
    # Elastic search config
    ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL')
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT')
    # Redis
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'
