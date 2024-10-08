import json
import logging
import pprint
import werkzeug
from werkzeug import urls
import requests

from odoo import http, _
from odoo.http import request, Response

from odoo.addons.portal.controllers.portal import CustomerPortal
from odoo.addons.portal.controllers.portal import CustomerPortal, pager as portal_pager

_logger = logging.getLogger(__name__)

class WindcaveAccount(CustomerPortal):

    def _prepare_home_portal_values(self, counters):
        _logger.info('WindcaveAccount._prepare_home_portal_values()')
        values = super()._prepare_home_portal_values(counters)

        providers = request.env['payment.provider'].search([('code', '=', 'windcave')])
        partner = request.env.user.partner_id

        if 'windcave_card_count' in counters:
            values['windcave_card_count'] = request.env['payment.token'].search_count([
                ('partner_id', '=', partner.id), 
                ('provider_id', 'in', providers.ids)
            ])

        return values

    @http.route(['/my/windcave-saved-cards', '/my/windcave-saved-cards/page/<int:page>'], type='http', auth="user", website=True)
    def windcave_saved_cards(self, page=1, **kw):
        _logger.info('WindcaveAccount.windcave_saved_cards()')
        values = self._prepare_portal_layout_values()

        providers = request.env['payment.provider'].search([('code', '=', 'windcave')])
        partner = request.env.user.partner_id

        domain = [('partner_id', '=', partner.id), ('provider_id', 'in', providers.ids)]

        card_count = request.env['payment.token'].search_count(domain)

        pager = portal_pager(
            url="/my/windcave-saved-cards",
            total=card_count,
            page=page,
            step=self._items_per_page
        )

        cards = request.env['payment.token'].search(domain, order='create_date desc', limit=self._items_per_page, offset=pager['offset'])

        values.update({
            'cards': cards,
            'page_name': 'windcave-card',
            'pager': pager,
            'default_url': '/my/windcave-saved-cards'
        })

        return request.render("payment_windcave.portal_my_windcave_cards", values)

    @http.route('/my/windcave-saved-cards/<model("payment.token"):card>/delete', type='http', auth='user')
    def delete_windcave_card(self, card):
        _logger.info('WindcaveAccount.delete_windcave_card()')

        partner = request.env.user.partner_id

        if partner.id == card.partner_id.id:
            _logger.info('Deleting Windcave card')

            try:
              card.unlink()
            except:
              _logger.info('Deleting failed, possibly due to card being referenced. Archiving.')

              card._cr.rollback()

              card.write({
                  'active': False
              })
        else:
            _logger.info('Failed to delete Windcave card, user id %s does not match %s', partner.id, card.partner_id.id)
            
        return werkzeug.utils.redirect('/my/windcave-saved-cards')
