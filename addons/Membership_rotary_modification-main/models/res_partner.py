import logging

from flectra import fields, models, api

_logger = logging.getLogger(__name__)

class ResPartner(models.Model):
    _inherit = 'res.partner'

    membership_club_type = fields.Selection(
        [
         ('','(None)'),
         ('rotary', 'Rotary'),
         ('rotaract','Rotaract'),
         ('interact','Interact'),
         ('rota-kids','Rota-Kids')],
        string='Membership Club Type',
        default=''
        )

    club_type_selected = fields.Boolean(compute='_compute_club_type_selected')

    membership_club_name = fields.Many2one(
        'res.partner', 
        string='Membership Club Name',
        domain="[('club_name', '!=', ''), ('club_type', '=', membership_club_type)]"
        )

    @api.onchange('membership_club_type')
    def _onchange_membership_club_type(self):
        self.membership_club_name = False
        _logger.info("Context: %s, membership_club_type: %s" % (self, self.membership_club_type))
        if self.membership_club_type:
            return {'domain': {'membership_club_name': [('club_name', '!=', False), ('club_type', '=', self.membership_club_type)]}}
        else:
            return {'domain': {'membership_club_name': [('club_name', '=', False)]}}
        
    @api.depends('membership_club_type')
    def _compute_club_type_selected(self):
        for record in self:
            if record.membership_club_type:
                record.club_type_selected = True
            else:
                record.club_type_selected = False
