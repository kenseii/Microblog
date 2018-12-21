"""
Code to interact with the tokens from external requests

"""
from flask import jsonify, g

from app import db
from app.api import bp
from app.api.auth import basic_auth, token_auth


# route to call when you need a token


@bp.route('/tokens', methods=['POST'])
@basic_auth.login_required
def get_token():
    token = g.current_user.get_token()
    db.session.commit()
    return jsonify({'token': token})


# route called to delete a token in the database
@bp.route('/tokens', methods=['DELETE'])
@token_auth.login_required
def revoke_token():
    g.current_user.revoke_token()
    db.session.commit()
    return '', 204
