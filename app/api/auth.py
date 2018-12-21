from flask import g
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth

from app.api.errors import error_response
from app.models import User

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()

"""
Check if the username and password supplied via basicauth are correct if so save the auth user
"""


@basic_auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user is None:
        return False
    g.current_user = user
    return user.check_password(password)


"""
In case there are problems return unauthorized 401 error
"""


@basic_auth.error_handler
def basic_auth_error():
    return error_response(401)


#   --------------------------------- Token methods -------------------------------

# call the check_token in the model to verify if there is a similar token

@token_auth.verify_token
def verify_token(token):
    g.current_user = User.check_token(token) if token else None
    return g.current_user is not None


# return the error once there is unauthorized request


@token_auth.error_handler
def token_auth_error():
    return error_response(401)
