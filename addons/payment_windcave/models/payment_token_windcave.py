import logging
from odoo import api, fields, models, _, service

_logger = logging.getLogger(__name__)

class PaymentTokenWindcave(models.Model):
    _inherit = 'payment.token'

    windcave_card_id = fields.Char('Windcave Card Id')
    windcave_card_number = fields.Char('Windcave Card Number')
    windcave_card_expiration = fields.Char('Windcave Card Expiration')

    @api.model
    def windcave_create(self, values):
        _logger.info('token create')
        return values