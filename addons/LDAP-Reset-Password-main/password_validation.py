from zxcvbn import zxcvbn
from flectra import http

import json
import re
import logging


_logger = logging.getLogger(__name__)

class PasswordValidation(http.Controller):

    @http.route('/validate_password', type='json', auth='public', csrf=False)
    def validate_password(self, **kwargs):
        password = kwargs.get('password')
        valid, message = self._validate_password(password)
        return {
            'error': None if valid else message,
            'valid': valid,
            'message': message
        }

    def _validate_password(self, password):
        if not password:
            return False, "Password must not be empty."

        result = zxcvbn(password)
        if result['score'] < 3:
            return False, "Password is too weak."

        rules = [
            (len(password) >= 10, "Password must be at least 10 characters long."),
            (re.search("[a-z]", password), "Password must contain at least 1 lowercase letter."),
            (re.search("[A-Z]", password), "Password must contain at least 1 uppercase letter."),
            (re.search("[0-9]", password), "Password must contain at least 1 number."),
            (re.search("[!@#$%^&*(),.?\":{}|<>]", password), "Password must contain at least 1 special character."),
        ]

        failed_rules = [message for condition, message in rules if not condition]

        if failed_rules:
            return False, " ".join(failed_rules)

        return True, "Success"
