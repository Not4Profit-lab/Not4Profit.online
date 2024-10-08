import logging

from odoo import _, fields, models
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)

class WindcaveTransactionRefundWizard(models.TransientModel):
    _name = "windcave.transaction.refund.wizard"
    _description = "Windcave Refund"

    refund_amount = fields.Monetary('Refund amount')
    currency_id = fields.Many2one('res.currency', string='Refund Currency')
    reference = fields.Char('Reference')

    def confirm_refund(self):
        _logger.info('WindcaveTransactionRefundWizard.confirm_refund()')
        
        transaction = self.env['windcave.transaction'].search([('reference', '=', self.reference), ('transaction_type', 'in', ['complete', 'purchase']), ('status', '=', 'approved')])

        if transaction.reference == False:
            _logger.error("Refund failed: Complete or Purchase transaction not found.")
            raise ValidationError(_('Refund failed: Complete or Purchase transaction not found.'))

        if transaction.currency != self.currency_id.name:
            _logger.error("Refund failed: Currency does not match transaction.")
            raise ValidationError(_('Refund failed: Currency does not match transaction.'))

        provider = self.env['payment.provider'].search([('id', '=', transaction.acquirer_id)])
        if not provider:
            raise ValidationError(_('Windcave: transaction has an unexpected payment provider.'))
        
        if provider.code != 'windcave':
            raise ValidationError(_('Windcave: transaction has an unexpected payment provider.'))

        balance = transaction.get_balance()

        if self.refund_amount <= 0:
            _logger.error("Refund failed: refund amount must be more than 0.00")
            raise ValidationError(_('Refund failed: refund amount must be more than 0.00'))

        if self.refund_amount > balance:
            _logger.error("Refund failed: Maximum refund amount %s.", balance)
            raise ValidationError(_('Refund failed: Maximum refund amount %s.', balance))

        return transaction.do_refund(provider, self.refund_amount)
