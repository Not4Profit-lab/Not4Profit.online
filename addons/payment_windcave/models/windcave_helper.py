import logging
import hashlib

from odoo import _
from odoo.http import request

_logger = logging.getLogger(__name__)

class WindcaveHelper():
    def get_xid(self, base_url, reference, request_type):
        txn_count = str(len(request.env['windcave.transaction'].search([('reference', '=', reference)])))
        string_to_encode = (base_url + reference + txn_count + request_type).encode('ascii')
        h = hashlib.sha1(string_to_encode)
        return h.hexdigest() + reference

    def parse_errors(self, errors):
        error_list = ""
        for error in errors:
            error_list = "%s [%s] "%(error_list, error)
        return error_list
    
    def get_transaction(self, json_response):
        for transaction in json_response['transactions']:
            if not transaction['isSurcharge']:
                return transaction
        return None
    
    def _findUrl(self, links, rel):
        for link in links:
            if link['rel'] == rel:
                return link['href']
        
        return ""

    def findHPPUrl(self, links):
        return self._findUrl(links, 'hpp')
