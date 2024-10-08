import logging

from odoo import _, api, fields, models

_logger = logging.getLogger(__name__)


class WindcaveSession(models.Model):
    _name = 'windcave.session'
    _description = 'Windcave Session'

    session_id = fields.Char(name="Session Id")
    session_state = fields.Char(name="Session State")
    order_id = fields.Char(name="Order Id")
    reference = fields.Char(name="Reference")
    session_url = fields.Char(name="Session URL")
    customer_id = fields.Char(name="Customer Id")
    amount = fields.Char(name="Amount")
    currency = fields.Char(name="Currency")