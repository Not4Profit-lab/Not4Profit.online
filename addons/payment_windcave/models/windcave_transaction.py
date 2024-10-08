import logging
import base64
import requests
import time
import json
import hashlib

from werkzeug import urls
from odoo import _, api, fields, models, service
from odoo.addons.payment_windcave.controllers.main import WindcaveController
from odoo.exceptions import ValidationError
from .windcave_helper import WindcaveHelper

_logger = logging.getLogger(__name__)
_helper = WindcaveHelper()

class WindcaveTransaction(models.Model):
    _name = 'windcave.transaction'
    _description = 'Windcave Transaction'

    _order = 'id desc'

    transaction_id = fields.Char(name="Transaction Id")
    parent_transaction_id = fields.Char(name="Parent Transaction Id")
    order_id = fields.Char(name="Order Id")
    reference = fields.Char(name="Reference")
    status = fields.Char(name="Status")
    response_code = fields.Char(name="Response Code")
    response_text = fields.Char(name="Response Text")
    auth_code = fields.Char(name="Auth Code")
    transaction_type = fields.Char(name="Transaction Type")
    payment_method = fields.Char(name="Payment Method")
    payment_authentication = fields.Char(name="Payment Authentication")
    amount = fields.Char(name="Amount")
    currency = fields.Char(name="Currency")
    card_holder = fields.Char(name="Card Holder")
    card_number = fields.Char(name="Card Number")
    card_expiration = fields.Char(name="Card Expiration")
    card_brand = fields.Char(name="Card Brand")
    cvc2_result = fields.Char(name="CVC2 Result")
    avs_action = fields.Char(name="AVS Action")
    avs_description = fields.Char(name="AVS Description")
    risk_action = fields.Char(name="Risk Action")
    risk_summary = fields.Char(name="Risk Summary")
    acquirer_id = fields.Char(name="Acquirer Id")
    customer_id = fields.Char(name="Customer Id")

    _retry_limit = 5

    def do_query(self):
        odoo_transaction = self.env['payment.transaction'].search([('reference', '=', self.reference)])
        
        result, _ = self.query_transaction(odoo_transaction.provider_id, self.transaction_id, 0)
        if result == True:
            if self.check_transaction_set(self.order_id, self.transaction_type):
                _logger.info('Transaction approved.')
                if self.transaction_type == 'purchase' or self.transaction_type == 'complete':
                    odoo_transaction._set_done()
                elif self.transaction_type == 'auth':
                    odoo_transaction._set_authorized()
                elif self.transaction_type == 'refund':
                    parent_transaction = self.env['windcave.transaction'].search([('transaction_id', '=', self.parent_transaction_id)])
                    new_balance = parent_transaction.get_balance()
                    odoo_transaction.write({'windcave_amount_refunded': odoo_transaction.amount - new_balance})
                    if new_balance == 0:
                        odoo_transaction.write({'windcave_fully_refunded': True})
                odoo_transaction._set_error('This transaction was approved.')
            else:
                _logger.info('Transaction declined.')
                if self.transaction_type == 'purchase' or self.transaction_type == 'auth':
                    odoo_transaction._set_canceled('This transaction was declined.')
                odoo_transaction._set_error('This transaction was declined.')
        elif result == False:
            _logger.error('Transaction failed: Error occured during the transaction.')
            odoo_transaction._set_canceled('An error occurred during the transaction.')
        elif result == 'pending':
            _logger.error('Transaction outcome unknown.')
            odoo_transaction._set_error('Error - transaction outcome unknown.')

    def do_rebill(self, odoo_transaction, reference, transaction_type, amount, currency, card_id):
        xid = _helper.get_xid(self.get_base_url(), reference, transaction_type)
        result, error_message = self.start_transaction(odoo_transaction.provider_id, xid, transaction_type, reference, amount, currency, 0, card_id)
        if result == True:
            new_transaction = self.env['windcave.transaction'].search([('reference', '=', self.reference)])
            if new_transaction.check_transaction_set(reference.split('-',1)[0], transaction_type):
                _logger.info('Transaction approved.')
                if transaction_type == 'purchase':
                    odoo_transaction._set_done()
                elif transaction_type == 'auth':
                    odoo_transaction._set_authorized()
            else:
                _logger.info('Transaction declined.')
                odoo_transaction._set_canceled('This transaction was declined.')
        elif result == False:
            _logger.error('Transaction failed: Error occured during the transaction. ' + error_message)
            odoo_transaction._set_canceled('An error occurred during the transaction.')
        elif result == 'pending':
            _logger.error('Transaction outcome unknown.')
            odoo_transaction._set_error('Error - transaction outcome unknown.')
        

    def do_refund(self, acquirer, refund_amount_requested = None):
        self.ensure_one()

        _logger.info('Attempting to refund order %s', self.order_id)

        if self.transaction_type != 'purchase' and self.transaction_type != 'complete':
            _logger.error('Attempted to complete non-auth or non-complete transaction. Transaction ID: %s', self.transaction_id)
            return False

        if self.status != 'approved':
            _logger.error('Attempted to complete non-approved transaction. Transaction ID: %s', self.transaction_id)
            return False
        
        refund_amount_available = self.get_balance()

        # If not specified, refund the entire amount.
        if refund_amount_requested == None:
            refund_amount_requested = refund_amount_available

        # Don't allow refund if the payment method is account2account.
        if self.payment_method == 'account2account':
            _logger.error('Account 2 Account does not support refunds. Transaction ID: %s', self.transaction_id)
            return False

        _logger.info('Refund attempt triggered. Amount requested: %s. Refund amount available: %s.', refund_amount_requested, refund_amount_available)

        result, error_message = self.start_transaction(
            acquirer,
            _helper.get_xid(self.env['ir.config_parameter'].sudo().get_param('web.base.url'), self.reference, 'transaction'), 
            'refund', self.reference, refund_amount_requested, self.currency, 0)

        if result == True:
            if self.check_transaction_set(self.order_id, 'refund'):
                _logger.info('Refund approved.')
                new_balance = self.get_balance()
                odoo_transaction = self.env['payment.transaction'].search([('reference', '=', self.reference)])
                odoo_transaction.write({'windcave_amount_refunded': odoo_transaction.amount - new_balance})
                if new_balance == 0:
                    odoo_transaction.write({'windcave_fully_refunded': True})
                self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Refund of {} successful.".format(refund_amount_requested))
            else:
                _logger.info('Refund declined.')
                self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Refund declined.")
        elif result == False:
            _logger.error('Refund failed: Error occured during the transaction. ' + error_message)
            self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Error while refunding transaction. Please retry. Error: " + error_message)
        elif result == "pending":
            _logger.error('Refund outcome pending, query the transaction to confirm.')
            self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Refund outcome unknown. Please retry.")

    def do_complete(self, odoo_transaction):
        self.ensure_one()
        _logger.info('Attempting to complete order %s', self.order_id)
        
        if self.transaction_type != 'auth':
            _logger.error('Attempted to complete non-auth transaction. Transaction ID: %s', self.transaction_id)
            return False
        
        result, error_message = self.start_transaction(
            odoo_transaction.provider_id,
            _helper.get_xid(self.env['ir.config_parameter'].sudo().get_param('web.base.url'), self.reference, 'transaction'), 
            'complete', self.reference, self.amount, self.currency, 0)
        if result == True:
            if self.check_transaction_set(self.order_id, 'complete'):
                _logger.info('Complete approved.')
                self.update({'status' : 'complete'})
                odoo_transaction._set_done()
                self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Capture successful.")
            else:
                _logger.info('Complete declined.')
                self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Capture declined.")
        elif result == False:
            _logger.error('Complete failed: Error occured during the transaction. ' + error_message)
            self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Error while capturing transaction. Please retry. Error: " + error_message)
        elif result == "pending":
            _logger.error('Complete outcome pending, query the transaction to confirm.')
            self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Capture outcome unknown. Please retry.")
    
    def do_void(self, odoo_transaction):
        self.ensure_one()
        _logger.info('Attempting to void order %s', self.order_id)
        
        if self.transaction_type != 'auth':
            _logger.error('Attempted to void non-auth transaction. Transaction ID: %s', self.transaction_id)
            return False
        
        result, error_message = self.start_transaction(
            odoo_transaction.provider_id,
            _helper.get_xid(self.env['ir.config_parameter'].sudo().get_param('web.base.url'), self.reference, 'transaction'), 
            'void', self.reference, self.amount, self.currency, 0)
        if result == True:
            if self.check_transaction_set(self.order_id, 'void'):
                _logger.info('Void approved.')
                self.update({'status' : 'voided'})
                odoo_transaction._set_canceled()
                self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Void successful.")
            else:
                _logger.info('Void declined.')
                self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Void declined.")
        elif result == False:
            _logger.error('Void failed: Error occured during the transaction. ' + error_message)
            self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="An error occurred while voiding. Void failed. Error: " + error_message)
        elif result == "pending":
            _logger.error('Void outcome pending, query the transaction to confirm.')
            self.env['sale.order'].search([('name', '=', self.order_id)]).message_post(body="Void outcome unknown. Please retry.")

    def start_transaction(self, acquirer, x_id, transaction_type, reference, amount, currency, retries, card_id = None):
        _logger.info('Starting transaction. X-ID: %s. Parent transaction ID: %s. Transaction type: %s. Reference: %s. Amount: %s. Currency: %s. Retries: %s. Card ID: %s.'%(x_id, self.transaction_id, transaction_type, reference, amount, currency, retries, card_id))

        auth_to_encode = (acquirer.windcave_api_user + ":" + acquirer.windcave_api_key).encode('ascii')
        authorization = base64.b64encode(auth_to_encode).decode('ascii')
        headers = {
            "Content-Type" : "application/json; charset=utf-8",
            "Authorization" : "Basic " + authorization,
            "X-ID" : x_id,
            "X-Client-Version" : "Odoo: " + service.common.exp_version()['server_version'] + ", Extension: " + self.env.ref('base.module_payment_windcave').installed_version,
        }

        data = {
            "type" : transaction_type,
            "merchantReference" : reference,
            "notificationUrl" : urls.url_join(acquirer.get_base_url(), WindcaveController._notification_url)
        }

        if transaction_type == "auth" or transaction_type == "purchase":
            data['cardId'] = card_id
            data['storedCardIndicatior'] = 'credentialOnFile'
        else:
            data['transactionId'] = self.transaction_id

        if amount is not None:
            data['amount'] = amount
            data['currency'] = currency

        data_str = json.dumps(data)
        payload = json.loads(data_str)

        response = requests.post(acquirer.windcave_api_url + '/transactions', json=payload, headers=headers)
        response_data = response.json()

        _logger.info('Response. Status Code: %s. Body: %s'%(response.status_code, response_data))

        if response.status_code == 200:
            approved = response_data['authorised']
            if approved:
                _logger.info('Transaction approved, adding record.')
                self.add_transaction(acquirer, response_data, 'approved', reference, self.transaction_id)
            elif response_data['type'] == 'void':
                _logger.info('Transaction declined.')
            else:
                _logger.info('Transaction declined. Adding record.')
                self.add_transaction(acquirer, response_data, 'declined', reference, self.transaction_id)
            return True
        elif response.status_code == 201:
            approved = response_data['authorised']
            if approved:
                _logger.info('Transaction approved, adding record.')
                self.add_transaction(acquirer, response_data, 'approved', reference, self.transaction_id)
            elif response_data['type'] == 'void':
                _logger.info('Transaction declined.')
            else:
                _logger.info('Transaction declined. Adding record.')
                self.add_transaction(acquirer, response_data, 'declined', reference, self.transaction_id)
            return True, None
        elif response.status_code == 202:
            time.sleep(5)
            _logger.info('Transaction outcome unknown. Adding transaction record. Querying transaction.')
            self.add_transaction(acquirer, response_data, 'pending', reference, self.transaction_id)
            return self.query_transaction(acquirer, response_data['id'], 0)
        elif 400 <= response.status_code < 500:
            if 'errors' in response_data:
              errors = _helper.parse_errors(response_data['errors'])
              _logger.error("Request failed. Details: %s", errors)
            else:
              _logger.error("Request failed. No details. Status: %d", response.status_code)
            
            raise ValidationError("Windcave: " + _('Unexpected response from the server.'))
        elif 500 <= response.status_code < 600:
            if retries < self._retry_limit:
                _logger.error("Request failed. Retrying.")
                return self.start_transaction(acquirer, x_id, transaction_type, reference, amount, currency, retries + 1, card_id)
            else:
                _logger.error("Request failed. Gave up after %s retries.", retries)
                return False, "Gave up after %s retries" % retries
        else:
            if retries < self._retry_limit:
                _logger.error("Request failed. Retrying.")
                return self.start_transaction(acquirer, x_id, transaction_type, reference, amount, currency, retries + 1, card_id)
            else:
                _logger.error("Request failed. Gave up after %s retries.", retries)
                return False, "Gave up after %s retries" % retries
    
    def query_transaction(self, acquirer, new_transaction_id, retries):
        _logger.info('Starting transaction query. Parent transaction ID: %s. Transaction ID: %s. Retries: %s.'%(self.transaction_id, new_transaction_id, retries))

        auth_to_encode = (acquirer.windcave_api_user + ":" + acquirer.windcave_api_key).encode('ascii')
        authorization = base64.b64encode(auth_to_encode).decode('ascii')
        headers = {
            "Content-Type" : "application/json; charset=utf-8",
            "Authorization" : "Basic " + authorization
        }

        response = requests.get(acquirer.windcave_api_url + '/transactions/' + new_transaction_id, headers=headers)
        response_data = response.json()

        _logger.info('Response. Status Code: %s. Body: %s'%(response.status_code, response_data))

        if response.status_code == 200:
            approved = response_data['authorised']
            if approved:
                _logger.info('Transaction approved, adding record.')
                self.add_transaction(acquirer, response_data, 'approved', response_data['merchantReference'], self.transaction_id)
            elif response_data['type'] == 'void':
                _logger.info('Transaction declined.')
            else:
                _logger.info('Transaction declined, adding record.')
                self.add_transaction(acquirer, response_data, 'declined', response_data['merchantReference'], self.transaction_id)
            return True, None
        elif response.status_code == 202:
            if retries < self._retry_limit:
                time.sleep(5)
                _logger.info('Transaction outcome unknown. Querying transaction.')
                return self.query_transaction(acquirer, new_transaction_id, retries + 1)
            else:
                _logger.error("Request failed. Transaction outcome unknown. Gave up after %s retries.", retries)
                return 'pending', None
        elif 400 <= response.status_code < 500:
            errors = _helper.parse_errors(response_data['errors'])
            _logger.error("Request failed. Details: %s", errors)
            return False, errors
        elif 500 <= response.status_code < 600:
            if retries < self._retry_limit:
                time.sleep(5)
                _logger.info('Request failed. Retrying.')
                return self.query_transaction(acquirer, new_transaction_id, retries + 1)
            else:
                _logger.error("Request failed. Gave up after %s retries.", retries)
                return False, "Gave up after %s retries." % retries
        else:
            if retries < self._retry_limit:
                time.sleep(5)
                _logger.info('Request failed. Retrying.')
                return self.query_transaction(acquirer, new_transaction_id, retries + 1)
            else:
                _logger.error("Request failed. Gave up after %s retries.", retries)
                return False, "Gave up after %s retries." % retries

    def check_transaction_set(self, order_id, transaction_type):
        transaction = self.env['windcave.transaction'].search([('order_id', '=', order_id), ('transaction_type', '=', transaction_type)], order='write_date desc')
        if len(transaction) > 0:
            transaction = transaction[0]
            if transaction.status == 'approved':
                return True
        return False

    def get_balance(self):
        balance = float(self.amount)
        refund_transactions = self.env['windcave.transaction'].search([('parent_transaction_id', '=', self.transaction_id), ('status', '=', 'approved'), ('transaction_type', '=', 'refund')])

        for transaction in refund_transactions:
            balance -= float(transaction.amount)

        return round(balance, 2)
    
    def get_pending_count(self, reference):
        return self.env['windcave.transaction'].search_count([('reference', '=', reference), ('status', '=', 'pending')])

    
    def add_transaction(self, acquirer, transaction_data, status, reference, parent_transaction_id=None):
        _logger.info('Setting transaction record of transaction ID %s - %s'%(transaction_data['id'], status))

        odoo_order = self.env['sale.order'].search([('name', '=', reference.split('-',1)[0])])
        
        transaction = self.env['windcave.transaction'].search([('transaction_id', '=', transaction_data['id'])])
        if transaction.transaction_id == False:
            transaction = self.env['windcave.transaction'].create({
                'transaction_id' : transaction_data['id'],
                "parent_transaction_id" : parent_transaction_id,
                'acquirer_id' : acquirer.id,
                'customer_id' : odoo_order.partner_id
                })

        transaction.save_transaction_record(transaction_data, status, reference)
        
        odoo_transaction = self.env['payment.transaction'].search([('reference','=', reference)])
        
        if transaction_data.get('type') == 'purchase' or transaction_data.get('type') == 'auth':
            odoo_transaction.write({'windcave_result': status, 'provider_reference': transaction_data['id']})
            if status == 'approved':
                odoo_transaction.write({'windcave_payment_exists': True})

        odoo_transaction.write({'windcave_pending_transactions': self.get_pending_count(reference)})
        
    
    def save_transaction_record(self, transaction_data, status, reference):
        order_id = reference.split('-',1)[0]
        transaction_data = self.filter_transaction(transaction_data)
        transaction_values = {
            'status' : status,
            'order_id' : order_id,
            'reference' : reference,
            'response_code' : transaction_data.get('reCo'),
            'response_text' : transaction_data.get('responseText'),
            'auth_code' : transaction_data.get('authCode'),
            'transaction_type' : transaction_data.get('type'),
            'payment_method' : transaction_data.get('method'),
            'amount' : transaction_data.get('amount'),
            'currency' : transaction_data.get('currency')
        }

        if 'card' in transaction_data:
            card = transaction_data['card']
            transaction_values['card_holder'] = card['cardHolderName'] if 'cardHolderName' in card else ''
            transaction_values['card_number'] = card['cardNumber'] if 'cardNumber' in card else ''
            transaction_values['card_expiration'] = card['dateExpiryMonth'] + '/' + card['dateExpiryYear'] if 'dateExpiryMonth' in card and 'dateExpiryYear' in card else ''
            transaction_values['card_brand'] = card['type'] if 'type' in card else ''

        if 'paymentAuthentication' in transaction_data:
            transaction_values['payment_authentication'] = transaction_data['paymentAuthentication']

        if 'cvc2Result' in transaction_data:
            transaction_values['cvc2_result'] = transaction_data['cvc2Result']
        if 'avs' in transaction_data:
            transaction_values['avs_action'] = transaction_data['avs']['avsActionName']
            transaction_values['avs_description'] = transaction_data['avs']['avsResultDescription']
        if 'risk' in transaction_data:
            transaction_values['risk_action'] = transaction_data['risk']['action']
            transaction_values['risk_summary'] = transaction_data['risk']['summaryText']
        self.update(transaction_values)
        _logger.info('Transaction record of transaction ID %s saved', transaction_data['id'])

    def filter_transaction(self, transaction_data):
        if 'liabilityIndicator' in transaction_data:
            if transaction_data['liabilityIndicator'] == 'standard':
                transaction_data['paymentAuthentication'] = 'No'
            elif transaction_data['liabilityIndicator'] == '3ds1verifiedbyvisa':
                transaction_data['paymentAuthentication'] = 'Verified by Visa'
            elif transaction_data['liabilityIndicator'] == '3ds1mastercardsecurecode':
                transaction_data['paymentAuthentication'] = 'Mastercard SecureCode'
            elif transaction_data['liabilityIndicator'] == '3ds1amexsafekey':
                transaction_data['paymentAuthentication'] = 'American Express SafeKey'
            elif transaction_data['liabilityIndicator'] == '3ds1other':
                transaction_data['paymentAuthentication'] = '3D Secure 1 (other)'
            elif transaction_data['liabilityIndicator'] == '3ds2frictionless':
                transaction_data['paymentAuthentication'] = '3D Secure 2 (Frictionless)'
            elif transaction_data['liabilityIndicator'] == '3ds2challenge':
                transaction_data['paymentAuthentication'] = '3D Secure 2 (Challenge)'
            elif transaction_data['liabilityIndicator'] == '3ds2decoupled':
                transaction_data['paymentAuthentication'] = '3D Secure 2 (Decoupled)'
            else:
                transaction_data['paymentAuthentication'] = transaction_data['liabilityIndicator']
            transaction_data.pop('liabilityIndicator')
        if 'cvc2ResultCode' in transaction_data:
            if transaction_data['cvc2ResultCode'] == 'N':
                transaction_data['cvc2Result'] = 'NotMatched'
            elif transaction_data['cvc2ResultCode'] == 'M':
                transaction_data['cvc2Result'] = 'Matched'
            elif transaction_data['cvc2ResultCode'] == 'S':
                transaction_data['cvc2Result'] = 'Suspicious'
            elif transaction_data['cvc2ResultCode'] == 'P':
                transaction_data['cvc2Result'] = 'NotProcessed'
            elif transaction_data['cvc2ResultCode'] == 'U':
                transaction_data['cvc2Result'] = 'IssuerNotParticipate'
            else:
                transaction_data['cvc2Result'] = transaction_data['cvc2ResultCode']
            transaction_data.pop('cvc2ResultCode')
        return transaction_data
