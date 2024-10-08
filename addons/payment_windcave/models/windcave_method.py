import logging
from odoo import api, fields, models, _, service

class WindcaveMethod(models.Model):
    _name = 'windcave.method'
    _description = 'Windcave Payment Method'

    name = fields.Char(string='Name')
    code = fields.Char(string='Code')