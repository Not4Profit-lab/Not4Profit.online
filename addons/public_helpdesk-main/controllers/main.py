from collections import OrderedDict
import magic

from flectra import http, _
from flectra.http import request
from flectra.addons.portal.controllers.portal import CustomerPortal
from flectra.addons.portal.controllers.portal import get_records_pager
from flectra.addons.portal.controllers.portal import pager as portal_pager
from flectra.exceptions import AccessError, MissingError
import copy
from flectra.osv import expression

class PublicHelpdesk(http.Controller):

    @http.route(['/helpdesk-form'], type='http', auth='public', website=True)
    def helpdesk_issue_form(self, **post):
        issue_type = request.env['issue.type'].sudo().search([])
        team_ids = request.env['helpdesk.team'].sudo().search([])
        assign_to_ids = request.env['res.users'].sudo().search([])
        config = request.env['res.config.settings'].sudo().search([])
        get_param = request.env['ir.config_parameter'].sudo().get_param
        website_form = get_param('helpdesk_basic.use_website_form')
        post.update({
            #'asignee': request.env.user,
            #'email': request.env.user.partner_id.email or '',
            #'partner_id': request.env.user.partner_id.id,
            'issue_type': issue_type,
            'assign_to_ids': assign_to_ids,
        })
        if website_form:
            return request.render('website_helpdesk.helpdesk_form', post)
        else:
            return request.render('website_helpdesk.helpdesk_web_form')


    @http.route(['/issue-submitted'], type='http', auth='public', website=True, csrf=False)
    def issue_submitted(self, **post):
        if 'issue_type_id' in post:
            is_id = post['issue_type_id']
            type_id = int(is_id)
            team = request.env['helpdesk.team'].sudo().search([('issue_type_ids', '=', type_id)])

        attachment_obj = request.env['ir.attachment']
        post_data = copy.deepcopy(post)

        for k in post:
            if k=='file' or 'file_data_' in k:
                post_data.pop(k)

        # Remove 'csrf_token' from post_data if present
        post_data.pop('csrf_token', None)

        ticket = request.env['helpdesk.ticket'].sudo().create(post_data)

        for rec in team:
            if rec:
                ticket.update(
                    {'team_id': rec[0],
                     'stage_id': rec.stage_ids[0].id or False})
                user_dict = {}
                for member in ticket.team_id.member_ids:
                    if rec.assignment_method == 'balanced':
                        tickets = request.env['helpdesk.ticket'].sudo().search_count([('team_id', '=', rec.id),('user_id', '=', member.id)])
                        user_dict.update({member: tickets})
                        temp = min(user_dict.values())
                        res = [key for key in user_dict if user_dict[key] == temp]
                        ticket.user_id = res[0]

                    if rec.assignment_method == 'random':
                        ticket.user_id = member.id

        values = {'ticket_seq': ticket.ticket_seq}
                
        file_data = [key for key in post if 'file_data_' in key]

        mime = magic.Magic(mime=True)
        for name in file_data:
            file_type = mime.from_buffer(post.get(name))
            if file_type.startswith('image/'):
                attachment_obj.sudo().create(
                    {'name': name,
                    'res_model': 'helpdesk.ticket',
                    'res_id': ticket,
                    'res_name': post.get('name'),
                    'datas': post.get(name)})
        
        return request.render("website_helpdesk.issue_submitted", values)

    @http.route(
        ['/helpdesk-form/issue_description/<model("issue.type"):issue_type_id>'
         ], type='json', auth="public", methods=['POST'], website=True)
    def issue_description(self, issue_type_id, **kw):
        domain = []
        if issue_type_id:
            domain.append(('id', '=', issue_type_id.id))
        return dict(
            help_description=request.env['issue.type'].sudo().search(
                domain, limit=1).mapped('reporting_template'))