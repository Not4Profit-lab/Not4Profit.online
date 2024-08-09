from flectra import models, fields


class ResPartner(models.Model):
    _inherit = 'res.partner'

    club_name = fields.Char(default='', string='Club Name')
    rotary_club_id = fields.Many2one('res.partner', string='Rotary Club', domain="[('club_name', '!=', False)]")

    club_id = fields.Char(string='Club ID')
    charter_date = fields.Date(string='Charter Date')
    club_type = fields.Selection([('rotary', 'Rotary'),
                                  ('rotaract','Rotaract'),
                                  ('interact','Interact'),
                                  ('rota-kids','Rota-Kids')], string='Club Type', default='')
    club_longitude = fields.Float(string='Longitude', digits=(9, 6), default=0.0)
    club_latitude = fields.Float(string='Latitude', digits=(9, 6), default=0.0)

    #TODO - Move to Rotary Membership module when created
    rotary_membership_id = fields.Char(string="Rotary ID")
