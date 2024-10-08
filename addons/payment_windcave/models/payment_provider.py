import json
import math
from odoo.exceptions import ValidationError
import logging
import requests
import base64
import time
from requests.exceptions import HTTPError
from werkzeug import urls
import werkzeug

from odoo import api, fields, models, _, service
from odoo.http import request

from odoo.addons.payment_windcave.controllers.main import WindcaveController
from .windcave_helper import WindcaveHelper
from ..const import DEFAULT_PAYMENT_METHODS_CODES

_logger = logging.getLogger(__name__)
_helper = WindcaveHelper()

class PaymentProvider(models.Model):
    _inherit = 'payment.provider'

    code = fields.Selection(selection_add=[('windcave', 'Windcave')], ondelete={'windcave': 'set default'})

    windcave_api_url = fields.Char(
        groups='base.group_user', 
        string='Windcave API URL',
        default='https://sec.windcave.com/api/v1', 
        required_if_provider='windcave')
    windcave_api_user = fields.Char(
        groups='base.group_user', 
        string='Windcave API User', 
        required_if_provider='windcave')
    windcave_api_key = fields.Char(
        groups='base.group_user', 
        string='Windcave API Key', 
        required_if_provider='windcave')
    windcave_payment_methods = fields.Many2many('windcave.method', string='HPP Payment Methods')

    _retry_limit = 5
    
    #=== BUSINESS METHODS ===#
    
    def windcave_get_form_action_url(self):
        _logger.info('WINDCAVE GET_FORM_ACTION_URL')
        self.ensure_one()
        return urls.url_join(self.get_base_url(), '/payment/windcave/redirect_handler')

    def start_session(self, data):
        _logger.info('PaymentAcquirerWindcave._start_session()')

        data['windcave_payment_exists'] = False
        data['windcave_result'] = 'pending'
        data['windcave_amount_refunded'] = 0
        data['windcave_pending_transactions'] = 0
        data['windcave_fully_refunded'] = False

        order_id = data['reference'].split('-',1)[0]

        if self.env['windcave.transaction'].check_transaction_set(order_id, 'purchase') or self.env['windcave.transaction'].check_transaction_set(order_id, 'auth'):
            _logger.info('Payment already made.')
            data['windcave_payment_exists'] = True
            data['windcave_result'] = 'approved'
            return False

        session = self.env['windcave.session'].search([('order_id', '=', order_id)], order='write_date desc')
        if len(session) > 1:
            session = session[0]
        if session.session_state in ['pending', 'processing']:
            _logger.info('Session already exists. Session Id: %s. Checking amount and currency.', session.session_id)
            if math.isclose(float(session.amount), data['amount']) and session.currency == data['currency'].name:
                _logger.info('Amount and currency match order. Redirecting to HPP.')
                return session.session_url
            _logger.info('Amount and currency do not match order. Unlinking old session from order and creating new session.')
            session.update({'order_id':'unlinked'})

        xid = _helper.get_xid(self.get_base_url(), data['reference'], 'session')
        result = self._create_session(xid, data)

        if result == True:
            transaction = self.env['windcave.transaction'].search([('reference', '=', data['reference'])])
            if transaction.transaction_type in ['purchase', 'auth']:
                _logger.info("Payment successful.")
                data['windcave_payment_exists'] = True
                data['windcave_result'] = 'approved'
            else:
                _logger.info("Payment unsuccessful.")
                data['windcave_payment_exists'] = True
                data['windcave_result'] = 'declined'
            return False

        elif result == False:
            _logger.info("Payment error.")
            raise ValidationError("Windcave: " + _("Unable to start the payment session. Please contact the website administrator."))

        elif "redirect" in  result.values():
            _logger.info("Redirect requested")
            return result['url']

    def _create_session(self, xid, session_data, retries = 0):
        _logger.info('PaymentAcquirerWindcave._create_session()')

        base_url = self.get_base_url()

        if self.capture_manually:
            transaction_type = 'auth'
        else:
            transaction_type = 'purchase'

        data = {
            'type': transaction_type,
            'amount': session_data['amount'],
            'currency': session_data['currency'].name,
            'methods': [method.code for method in self.windcave_payment_methods],
            'merchantReference':session_data['reference'],
            'language':session_data['partner_lang'],
            'callbackUrls':{
                'approved':urls.url_join(base_url, WindcaveController._callback_url), 
                'declined':urls.url_join(base_url, WindcaveController._callback_url), 
                'canceled':urls.url_join(base_url, WindcaveController._callback_url)
            },
            'notificationUrl':urls.url_join(base_url, WindcaveController._notification_url)
        }

        transaction = self.env['payment.transaction'].sudo().search([('reference', '=', session_data['reference'])])

        if transaction.tokenize:
            data['storeCard'] = True
            data['storedCardIndicator'] = 'credentialonfileinitial'

        response = self._do_request(data, xid)
        response_data = response.json()

        _logger.info("Response. Status Code: %s. Body: %s", response.status_code, response_data)

        if response.status_code == 200:
            transaction_data = _helper.get_transaction(response_data)
            approved = transaction_data.authorised
            session = self.env['windcave.session'].search([('reference', '=', session_data['reference'])])
            if approved:
                _logger.info("Transaction approved. Adding transaction record")
                self.env['windcave.transaction'].add_transaction(transaction.provider_id, response_data, 'approved', session.reference)
                if (response_data['storeCard'] and transaction_data['card'] is not None): #and customer wants to store
                        self.env['payment.token'].sudo().create({
                        'acquirer_id' : self.acquirer_id.id,
                        'partner_id' : session.customer_id,
                        'acquirer_ref' : transaction_data['card']['id'],
                        'windcave_card_id' : transaction_data['card']['id'],
                        'windcave_card_number' : transaction_data['card']['cardNumber'],
                        'windcave_card_expiration' : transaction_data['card']['dateExpiryMonth'] + '/' + transaction_data['card']['dateExpiryYear']
                    })
                _logger.info("Setting session state: approved")
                session.update({'session_state':'approved'})
            else:
                _logger.info("Transaction declined. Adding transaction record")
                self.env['windcave.transaction'].add_transaction(transaction.provider_id, response_data, 'declined', session.reference)
                _logger.info("Setting session state: declined")
                session.update({'session_state':'declined'})
            return True
        elif response.status_code == 202:
            _logger.info("Session created. Adding session record.")
            session_url = _helper.findHPPUrl(response_data['links'])
            WindcaveSession = self.env['windcave.session']
            WindcaveSession.create({
                'session_id' : response_data['id'],
                'session_state' : 'pending',
                'reference' : session_data['reference'],
                'order_id' : session_data['reference'].split('-',1)[0],
                'session_url' : session_url,
                'customer_id' : session_data['partner'].id,
                'amount' : session_data['amount'],
                'currency' : session_data['currency'].name
                })
            return {
                'result':'redirect',
                'url': session_url
            }
        elif 400 <= response.status_code < 500:
            _logger.error("Request failed. Details: %s", _helper.parse_errors(response_data['errors']))
            return False
        elif 500 <= response.status_code < 600:
            if retries < self._retry_limit:
                time.sleep(5)
                _logger.info("Request failed. Retrying")
                return self._create_session(xid, session_data, retries + 1)
            else:
                _logger.error("Request failed. Gave up after %s retries.", retries)
                return False
        else:
            if retries < self._retry_limit:
                time.sleep(5)
                _logger.info("Request failed. Retrying")
                return self._create_session(xid, session_data, retries + 1)
            else:
                _logger.error("Request failed. Gave up after %s retries.", retries)
                return False

    def _do_request(self, data=None, xid=None):
        self.ensure_one()
        _logger.info('PaymentAcquirerWindcave.do_windcave_request()')
        auth_to_encode = (self.windcave_api_user + ":" + self.windcave_api_key).encode('ascii')
        authorization = base64.b64encode(auth_to_encode).decode('ascii')
        headers = {
            "Content-Type" : "application/json; charset=utf-8",
            "Authorization" : "Basic " + authorization,
            "X-ID" : xid,
            "X-Client-Version" : "Odoo: " + service.common.exp_version()['server_version'] + ", Extension: " + self.env.ref('base.module_payment_windcave').installed_version
        }
        data_str = json.dumps(data)
        payload = json.loads(data_str)
        url = self.windcave_api_url + '/sessions'
        try:
          response = requests.post(url, json=payload, headers=headers)

          try:
            response.raise_for_status()
          except requests.exceptions.HTTPError:
            _logger.exception("Unable to process the API request to %s", url)  
            raise ValidationError("Windcave: " + _("The communication with API failed."))
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            _logger.exception("Unable to reach the server at %s", url)
            raise ValidationError("Windcave: " + _("Could not establish connection to the API."))
        return response

    def _compute_feature_support_fields(self):
        """ Override of `payment` to enable additional features. """
        super()._compute_feature_support_fields()
        self.filtered(lambda p: p.code == 'windcave').update({
            'support_manual_capture': 'full_only',
            'support_refund': 'partial',
            'support_tokenization': True,
        })

    def _get_feature_support(self):
        res = super(PaymentProvider, self)._get_feature_support()
        res['authorize'].append('windcave')
        res['tokenize'].append('windcave')
        return res


    def _get_default_payment_method_codes(self):
        """ Override of `payment` to return the default payment method codes. """
        default_codes = super()._get_default_payment_method_codes()
        if self.code != 'windcave':
            return default_codes
        return DEFAULT_PAYMENT_METHODS_CODES
