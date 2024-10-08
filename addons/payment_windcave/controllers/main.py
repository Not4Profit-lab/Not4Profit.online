import json
import logging
import pprint
import werkzeug
from werkzeug import urls
import requests

from odoo import http, _
from odoo.http import request, Response

_logger = logging.getLogger(__name__)

class WindcaveController(http.Controller):
    _callback_url = '/payment/windcave/callback'
    _notification_url = '/payment/windcave/notification'
    _redirect_handler_url = '/payment/windcave/redirect_handler'

    _retry_limit = 5

    @http.route(_callback_url, type='http', auth='public', csrf=False, save_session=False)
    def windcave_callback(self, **data):
        _logger.info('Windcave Callback with data\n%s', pprint.pformat(data))

        tx = request.env['payment.transaction'].sudo()._handle_notification_data('windcave', data)
        if not tx:
            return Response("Internal error", status=500)
        
        redirect_url = tx._callback(data)
        return request.redirect(redirect_url)

    @http.route(_notification_url, type='json', auth='public', csrf=False, save_session=False)
    def windcave_notification(self, **data):
        _logger.info("Windcave Notification with data:\n%s", pprint.pformat(data))

        if data.get('sessionId') != None:
            # If session notification
            session = request.env['windcave.session'].search([('session_id', '=', data['sessionId'])])

            if session.session_state == 'pending' or session.session_state == 'processing':
                _logger.info('Response: 400')
                return Response("Pending", status=400)
        elif data.get('id') != None:
            # If transaction notification
            transaction = request.env['windcave.transaction'].search([('transaction_id', '=', data['id'])])

            if transaction.status == 'pending':
                _logger.info('Response: 400')
                return Response("Pending", status=400)

        _logger.info('Response: 200')
        return Response("OK", status=200)


    @http.route(_redirect_handler_url, type='http', auth="public", csrf=False)
    def windcave_redirect_handler(self, **kwargs):
        _logger.info('WindcaveController.windcave_redirect_handler with data:\n%s', pprint.pformat(kwargs))
        payment_transaction = request.env['payment.transaction'].sudo().search([('reference','=',kwargs['reference'])])

        if kwargs['windcave_payment_exists']:
            if kwargs['windcave_result'] == 'approved':
                payment_transaction._set_done()
            elif kwargs['windcave_result'] == 'declined':
                payment_transaction._set_canceled()
            elif kwargs['windcave_result'] == 'error':
                payment_transaction._set_error('Error while processing payment.')
            _logger.info('Redirecting to /payment/status')
            return werkzeug.utils.redirect('/payment/status')

        _logger.info('Redirecting to ' + kwargs['windcave_redirect_url'])
        return werkzeug.utils.redirect(kwargs['windcave_redirect_url'])
