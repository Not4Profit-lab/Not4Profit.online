from flectra import models, fields

class MembershipLine(models.Model):
    _inherit = 'membership.membership_line'

    membership_id = fields.Many2one('product.product', string="Membership Dues", required=True)
