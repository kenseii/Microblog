from flask import jsonify
from werkzeug.http import HTTP_STATUS_CODES


# this function is intended to return a more clear error status code


def error_response(status_code, message=None):
    payload = {'error': HTTP_STATUS_CODES.get(status_code, 'Unknown error')}
    if message:
        payload['message'] = message
    response = jsonify(payload)
    response.status_code = status_code
    return response


# due to the frequency of bad requests it gets its own fx that receives
# a specific message to return to the user
def bad_request(message):
    return error_response(400, message)
