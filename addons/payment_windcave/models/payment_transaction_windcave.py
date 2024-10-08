import logging
import math
import time
import base64
import requests

from werkzeug import urls
import werkzeug
import os

from odoo import api, fields, models, _, service
from odoo.exceptions import UserError, ValidationError

from .windcave_helper import WindcaveHelper

_logger = logging.getLogger(__name__)
_helper = WindcaveHelper()

class PaymentTransactionWindcave(models.Model):
    _inherit = 'payment.transaction'

    windcave_payment_exists = fields.Boolean('Payment Exists')
    windcave_result = fields.Char('Result')
    windcave_amount_refunded = fields.Monetary('Amount Refunded')
    windcave_fully_refunded = fields.Boolean('Fully Refunded')
    windcave_pending_transactions = fields.Integer('Pending Transactions')

    _retry_limit = 5

    def _get_specific_rendering_values(self, processing_values):
        res = super()._get_specific_rendering_values(processing_values)
        if self.provider_code != 'windcave':
            return res
        
        data = {
            'currency': self.currency_id,
            'reference': self.reference,
            'amount': self.amount,
            'partner_lang': self.partner_id.lang,
            'partner': self.partner_id
        }
        redirectUrl = self.provider_id.start_session(data)
        return {
            'windcave_payment_exists': data['windcave_payment_exists'], 
            'windcave_result': data['windcave_result'],
            'windcave_amount_refunded': data['windcave_amount_refunded'],
            'windcave_pending_transactions': data['windcave_pending_transactions'],
            'windcave_fully_refunded': data['windcave_fully_refunded'],
            'windcave_redirect_url': redirectUrl,
            'windcave_action_url': urls.url_join(self.provider_id.get_base_url(), '/payment/windcave/redirect_handler')
        }
    
    def _get_tx_from_notification_data(self, provider_code, notification_data):
        tx = super()._get_tx_from_notification_data(provider_code, notification_data)
        if provider_code != 'windcave' or len(tx) == 1:
            return tx
        
        _logger.info('PaymentTransactionWindcave._get_tx_from_notification_data')

        reference = ''
        if notification_data.get('sessionId') != None:
            session = self.env['windcave.session'].search([('session_id', '=', notification_data['sessionId'])])
            reference = session.reference
        elif notification_data.get('id') != None:
            windcaveTransaction = self.env['windcave.transaction'].search([('transaction_id', '=', notification_data['id'])])
            reference = windcaveTransaction.reference

        if reference != '':
          tx = self.env['payment.transaction'].search([('reference', '=', reference), ('provider_code', '=', 'windcave')])

        if not tx:
            raise ValidationError(
                "Windcave: " + _("No transaction found matching reference %s.", reference)
            )

        return tx
    

    def _process_notification_data(self, notification_data):
        super()._process_notification_data(notification_data)
        if self.provider_code != 'windcave':
            return


    def _send_capture_request(self):
        super()._send_capture_request()
        if self.provider_code != 'windcave':
            return
        
        _logger.info("PaymentTransactionWindcave _windcave_s2s_capture_transaction")

        order_id = self.reference.split('-',1)[0]

        auth_transaction = self.env['windcave.transaction'].search([
            ('reference', '=', self.reference), 
            ('transaction_type', '=', 'auth'), 
            ('status', '=', 'approved')
        ])

        if auth_transaction.reference == False:
           _logger.error("Complete failed: Auth transaction not found.")
           raise ValidationError(_('Complete failed: Auth transaction not found.'))

        if auth_transaction.get_pending_count(auth_transaction.reference) > 0:
            _logger.info('Complete failed: Pending transactions.')
            raise ValidationError(_('Complete failed: Pending transactions.'))
        
        if self.env['windcave.transaction'].check_transaction_set(order_id, 'complete'):
            _logger.info('Complete already made. Do not continue with transaction.')
            self._set_done()
            return
        
        if self.env['windcave.transaction'].check_transaction_set(order_id, 'void'):
            _logger.info('Void already made. Do not continue with transaction.')
            self._set_canceled()
            return
        
        auth_transaction.do_complete(self)
    
    def _send_void_request(self, amount_to_void=None):
        child_void_txn = super()._send_void_request(amount_to_void=amount_to_void)
        if self.provider_code != 'windcave':
            return child_void_txn

        _logger.info("PaymentTransactionWindcave._send_void_request")

        order_id = self.reference.split('-',1)[0]

        auth_transaction = self.env['windcave.transaction'].search([
            ('reference', '=', self.reference), 
            ('transaction_type', '=', 'auth'), 
            ('status', '=', 'approved')
        ])

        if auth_transaction.reference == False:
           _logger.error("Void failed: Auth transaction not found.")
           raise ValidationError(_('Void failed: Auth transaction not found.'))
        
        if auth_transaction.get_pending_count(auth_transaction.reference) > 0:
            _logger.info('Void failed: Pending transactions.')
            raise ValidationError(_('Void failed: Pending transactions.'))

        if auth_transaction.check_transaction_set(order_id, 'complete'):
            _logger.info('Complete already made. Do not continue with transaction.')
            self._set_done()
            return
        
        if auth_transaction.check_transaction_set(order_id, 'void'):
            _logger.info('Void already made. Do not continue with transaction.')
            self._set_canceled()
            return
        
        auth_transaction.do_void(self)

    def _send_payment_request(self):
        super()._send_payment_request()
        if self.provider_code != 'windcave':
            return
        
        if not self.token_id.windcave_card_id:
            raise UserError("Windcave: " + _("The transaction is not linked to a token."))

        _logger.info('PaymentAcquirerWindcave._send_payment_request()')

        order_id = self.reference.split('-',1)[0]

        if self.provider_id.capture_manually:
            transaction_type = 'auth'
        else:
            transaction_type = 'purchase'
        
        if self.env['windcave.transaction'].check_transaction_set(order_id, 'purchase') or self.env['windcave.transaction'].check_transaction_set(order_id, 'auth'):
            _logger.info('Payment already made. Do not continue with transaction.')
            self._set_done()
            return
        
        session = self.env['windcave.session'].search([('order_id', '=', order_id)], order='write_date desc')
        if len(session) > 1:
            session = session[0]
        if session.session_state in ['pending', 'processing']:
            _logger.info('Session already exists. Session Id: %s. Checking amount and currency.', session.session_id)
            if math.isclose(float(session.amount), self.amount) and session.currency == self.currency_id.name:
                _logger.info('Amount and currency match order. Vaild session exists, do not continue with transaction.')
                return
            _logger.info('Amount and currency do not match order. Unlinking old session from order.')
            session.update({'order_id':'unlinked'})

        self.env['windcave.transaction'].do_rebill(self, self.reference, transaction_type, self.amount, self.currency_id.name, self.token_id.windcave_card_id)


    def _send_refund_request(self, amount_to_refund=None):
        _logger.info('PaymentAcquirerWindcave._send_refund_request()')

        self.ensure_one()

        if self.provider_code != 'windcave':
            return super()._send_refund_request(amount_to_refund=amount_to_refund)

        transaction = self.env['windcave.transaction'].search([
            ('reference', '=', self.reference), 
            ('transaction_type', 'in', ['complete', 'purchase']), 
            ('status', '=', 'approved')
        ])

        if transaction.reference == False:
           _logger.error("Refund failed: Complete or Purchase transaction not found.")
           raise ValidationError(_('Refund failed: Complete or Purchase transaction not found.'))
        
        transaction.do_refund(self.provider_id, amount_to_refund)
        

    def action_show_refund_wizard(self, **data):
        _logger.info('PaymentAcquirerWindcave.action_show_refund_wizard()')
        
        transaction = self.env['windcave.transaction'].search([('reference', '=', self.reference), ('transaction_type', 'in', ['complete', 'purchase']), ('status', '=', 'approved')])

        if transaction.reference == False:
            _logger.error("Refund failed: Complete or Purchase transaction not found.")
            raise ValidationError(_('Refund failed: Complete or Purchase transaction not found.'))

        return {
            'type': 'ir.actions.act_window',
            'name': _('Windcave Refund'),
            'res_model': 'windcave.transaction.refund.wizard',
            'view_type': 'form',
            'view_mode': 'form',
            'target': 'new',
            'view_id': self.env.ref('payment_windcave.windcave_refund_wizard_form').id,
            'context': {'default_refund_amount': transaction.get_balance(), 'default_currency_id': self.currency_id.id, 'default_reference': self.reference}
        }
    
    def action_query_transaction(self, **data):
        self.ensure_one()

        _logger.info('PaymentAcquirerWindcave.action_query_transaction()')

        transaction = self.env['windcave.transaction'].search([('reference', '=', self.reference),  ('status', '=', 'pending')])

        if transaction.reference == False:
            _logger.error("Query failed: Pending transaction not found.")
            raise ValidationError(_('Query failed: Pending transaction not found.'))
        
        transaction.do_query()

    def _callback(self, data):
        retries = data.get('retries')
        if retries is None:
            retries = 0
        else:
            retries = int(retries)

        session_id = data.get('sessionId')
        session = self.env['windcave.session'].search([('session_id', '=', session_id)])
        

        retry_url = urls.url_join(self.env['ir.config_parameter'].sudo().get_param('web.base.url'), '/payment/windcave/callback?sessionId=%s&retries=%s'%(session_id, str(retries)))
        retry_url_increment = urls.url_join(self.env['ir.config_parameter'].sudo().get_param('web.base.url'), '/payment/windcave/callback?sessionId=%s&retries=%s'%(session_id, str(retries + 1)))

        filepath = os.path.join(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'data/lock_files/%s.txt'%(session_id))
        _logger.info('Attempting to get lock. File:%s', filepath)
        got_lock = self._lock_file(filepath)
        if not got_lock:
            _logger.info('Failed to get lock.')
            time.sleep(5)
            _logger.info('Retrying')
            return retry_url
        try:
          _logger.info('Got lock. Session state: %s', session.session_state)

          if session.session_state == 'pending':
              session.update({'session_state' : 'processing'})
              _logger.info('Querying session')
              query_result = self._query_session(session_id, retries)
              result = query_result['result']
              _logger.info('Query session result: %s', result)
              if result == "OK":
                  transaction = self.env['windcave.transaction'].search([('reference', '=', session.reference)])
                  if transaction.check_transaction_set(session.order_id, 'purchase') or transaction.check_transaction_set(session.order_id, 'auth'):
                      _logger.info('Setting session: approved')
                      session.update({'session_state' : 'approved'})
                      if transaction.transaction_type == 'purchase':
                          self._set_done()
                      elif transaction.transaction_type == 'auth':
                          self._set_authorized()
                  else:
                      _logger.info('Setting session: declined')
                      session.update({'session_state' : 'declined'})
                      self._set_canceled("The payment has failed")
                  self._unlock_file(filepath)
                  _logger.info('Lock released.')
                  return '/payment/status'
              elif result == "error":
                  _logger.info('Setting session: declined')
                  session.update({'session_state' : 'declined'})
                  self._set_canceled('An error occurred during the transaction.')
                  self._unlock_file(filepath)
                  _logger.info('Lock released. Redirecting to cart.')
              elif result == 'retry':
                  _logger.info('Setting session: pending')
                  session.update({'session_state' : 'pending'})
                  self._unlock_file(filepath)
                  _logger.info('Lock released. Retrying.')
                  return retry_url_increment
              elif result == 'pending':
                  _logger.info('Setting session: pending')
                  session.update({'session_state' : 'pending'})
                  self._unlock_file(filepath)
                  _logger.info('Lock released. Redirecting to home.')
                  return '/payment/status'
              elif result == 'void required':
                  _logger.info('Setting session: void required.')
                  session.update({'session_state':'declined'})
                  self._do_internal_void(query_result['transaction_id'])
                  self._unlock_file(filepath)
                  return '/payment/status'
          else:
              if session.session_state == 'processing':
                  time.sleep(5)
                  self._unlock_file(filepath)
                  _logger.info('Lock released. Retrying.')
                  return retry_url
        finally:
          self._unlock_file(filepath)
          _logger.info('Lock released.')

        return '/payment/status'

    
    def _sessionNotification(self, session_id, retries = 0):

        session = self.env['windcave.session'].search([('session_id', '=', session_id)])

        #get lock folder
        filepath = os.path.join(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'data/lock_files/%s.txt'%(session_id))
        got_lock = self._lock_file(filepath)

        if got_lock:
            _logger.info('Got lock. Session state: %s', session.session_state)

            if session.session_state == 'pending' or session.session_state == 'processing':
                session.update({'session_state' : 'processing'})
                _logger.info('Querying session')
                query_result = self._query_session(session_id, retries)
                result = query_result['result']
                _logger.info('Query session result: %s', result)
                if result == "OK":
                    transaction = self.env['windcave.transaction'].search([('reference', '=', session.reference)])
                    if transaction.check_transaction_set(session.order_id, 'purchase') or transaction.check_transaction_set(session.order_id, 'auth'):
                        _logger.info('Setting session: approved')
                        session.update({'session_state' : 'approved'})
                        if transaction.transaction_type == 'purchase':
                            self._set_done()
                        elif transaction.transaction_type == 'auth':
                            self._set_authorized()
                    else:
                        _logger.info('Setting session: declined')
                        session.update({'session_state' : 'declined'})
                        self._set_canceled()
                elif result == "error":
                    _logger.info('Setting session: declined')
                    session.update({'session_state' : 'declined'})
                    self._set_canceled('An error occurred during the transaction.')
                elif result == 'retry':
                    _logger.info('Setting session: pending')
                    session.update({'session_state' : 'pending'})
                    self._unlock_file(filepath)
                    _logger.info('Lock released. Retrying.')
                elif result == 'pending':
                    _logger.info('Setting session: pending')
                    session.update({'session_state' : 'pending'})
                    _logger.info('Redirecting to home.')
                elif result == 'void required':
                    _logger.info('Setting session: void required.')
                    session.update({'session_state':'declined'})
                    self._do_internal_void(query_result['transaction_id'])
                    self._set_canceled()
            self._unlock_file(filepath)
            _logger.info('Lock released.')
        else:
            _logger.info('Failed to get lock.')
            time.sleep(5)
            _logger.info('Retrying')

    def _transactionNotification(self, transactionId):
        transaction = self.env['windcave.transaction'].search([('transaction_id', '=', transactionId)])

        _logger.info('Transaction status: %s', transaction.status)

        if transaction.status == 'pending':
            _logger.info('Querying transaction')
            transaction.do_query()

    def _query_session(self, session_id, retries):
        _logger.info('Starting session query. Session ID: %s. Retries: %s'%(session_id, retries))

        response = self._do_request(session_id)
        response_data = response.json()

        _logger.info('Response. Status Code: %s. Body: %s'%(response.status_code, response_data)) #parse

        if response.status_code == 200:
            transaction_data = _helper.get_transaction(response_data)
            approved = transaction_data['authorised']
            session = self.env['windcave.session'].search([('session_id', '=', session_id)])
            if approved:
                _logger.info('Transaction approved. Adding record.')
                self.env['windcave.transaction'].add_transaction(self.provider_id, transaction_data, 'approved', session.reference)
                order = self.env['sale.order'].search([('name', '=', self.reference.split('-',1)[0])])
                if math.isclose(float(session.amount), order.amount_total) and session.currency == order.currency_id.name:
                    _logger.info('Transaction approved. Adding record.')
                    self.env['windcave.transaction'].add_transaction(self.provider_id, transaction_data, 'approved', session.reference)
                    if response_data['storeCard'] and ('card' in transaction_data): #and save cards enabled
                        expiry = transaction_data['card']['dateExpiryMonth'] + '/' + transaction_data['card']['dateExpiryYear']
                        self.env['payment.token'].create({
                            'provider_id' : self.provider_id.id,
                            'partner_id' : session.customer_id,
                            'payment_method_id': self.payment_method_id.id,
                            'provider_ref' : transaction_data['card']['id'],
                            'payment_details' : "%s Expiry: %s"%(transaction_data['card']['cardNumber'], expiry),
                            'windcave_card_id' : transaction_data['card']['id'],
                            'windcave_card_number' : transaction_data['card']['cardNumber'],
                            'windcave_card_expiration' : expiry
                        })
                else:
                    _logger.info('Session amount and currency do not match order amount and currency. Void required.')
                    return {'result':'void required', 'transaction_id':transaction_data['id']}
            else:
                _logger.info('Transaction declined. Adding record.')
                self.env['windcave.transaction'].add_transaction(self.provider_id, transaction_data, 'declined', session.reference)
            return {'result':'OK'}
        elif response.status_code == 202:
            if retries < self._retry_limit:
                time.sleep(5)
                _logger.info('Session outcome unknown')
                return {'result':'retry'}
            else:
                _logger.error('Request failed. Session outcome unknown. Gave up after %s retries.', retries)
                return {'result':'pending'}
        elif 400 <= response.status_code < 500:
            error_list = _helper.parse_errors(response_data['errors'])
            _logger.error('Request failed. Details: %s', error_list)
            return {'result':'error'}
        elif  500 <= response.status_code < 600:
            if retries < self._retry_limit:
                time.sleep(5)
                _logger.info('Request failed.')
                return {'result':'retry'}
            else:
                _logger.error('Request failed. Session outcome unknown. Gave up after %s retries.', retries)
                return {'result':'error'}
        else:
            if retries < self._retry_limit:
                time.sleep(5)
                _logger.info('Request failed.')
                return {'result':'retry'}
            else:
                _logger.error('Request failed. Session outcome unknown. Gave up after %s retries.', retries)
                return {'result':'error'}
        return True

    def _do_request(self, session_id):
        auth_to_encode = (self.provider_id.windcave_api_user + ":" + self.provider_id.windcave_api_key).encode('ascii')
        authorization = base64.b64encode(auth_to_encode).decode('ascii')
        headers = {
            "Content-Type" : "application/json; charset=utf-8",
            "Authorization" : "Basic " + authorization,
            "X-Client-Version" : "Odoo: " + service.common.exp_version()['server_version'] + ", Extension: " + self.env.ref('base.module_payment_windcave').installed_version
        }
        response = requests.get(self.provider_id.windcave_api_url + '/sessions/' + session_id, headers=headers)
        return response        
    
    def _do_internal_void(self, transaction_id):
        _logger.info('Starting internal void for transaction id %s', transaction_id)

        transaction = self.env['windcave.transaction'].search([('transaction_id', '=', transaction_id)])

        result, error_message = transaction.start_transaction(
            self.provider_id,
            _helper.get_xid(self.env['ir.config_parameter'].sudo().get_param('web.base.url'), self.reference, 'void'), 
            'void', self.reference, self.amount, self.currency_id.name, 0)

        if result == True:
            if transaction.check_transaction_set(transaction.reference.split('-',1)[0], 'void'):
                _logger.info('Void approved.')
                transaction.update({'status' : 'voided'})
                self._set_canceled('Error - tried to pay for an order using an invalid payment session. This transaction was voided, please try again.')
                return True
            else:
                _logger.info('Void declined.')
                return False
        elif result == False:
            _logger.error('Void falied: error occurred during the transaction. ' + error_message)
            self._set_canceled('Error - failed to void an invalid payment session.')
            return False
        elif result == 'pending':
            _logger.error('Void outcome unknown.')
            self._set_canceled('Error - attempted to void an invalid payment session. Outcome unknown.')
            return False

    def _lock_file(self, filepath):
        try:
            with open(filepath, 'x') as lockfile:
                lockfile.write(str(os.getpid()))
        except IOError:
            return False
        return True

    def _unlock_file(self, filepath):
        try:
          os.remove(filepath)
        except IOError:
          return
