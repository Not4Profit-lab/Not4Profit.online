import ldap
import ldap.modlist as modlist

import logging
import werkzeug
import random
import string
import json

from datetime import datetime, timedelta, date
from ldap.filter import filter_format
from flectra import api, fields, models, tools, SUPERUSER_ID, _, http
from flectra.exceptions import AccessDenied, AccessError, UserError, ValidationError
from flectra.tools.misc import str2bool
from flectra.tools.pycompat import to_text
from flectra.http import content_disposition, Controller, request, route
from flectra.addons.auth_signup.controllers.main import AuthSignupHome as AuthSignupController
from flectra.addons.mail.models.mail_mail import MailMail
from flectra.addons.mail.models.mail_template import MailTemplate
from flectra.addons.web.controllers.main import Home

_logger = logging.getLogger(__name__)

SIGN_UP_REQUEST_PARAMS = {'db', 'login', 'debug', 'token', 'message', 'error', 'scope', 'mode',
                          'redirect', 'redirect_hostname', 'email', 'name', 'partner_id',
                          'password', 'confirm_password', 'city', 'country_id', 'lang',
                          'first_name', 'last_name', 'rotary_id', 'rotary_club', 'rotary_club_id'
}

class ResPartner(models.Model):
    _inherit = 'res.partner'
  
    rotary_membership_id = fields.Char(string="Rotary ID")

class ChangePasswordWizard(models.TransientModel):
    """ A wizard to manage the change of users' passwords. """
    _name = 'change.password.wizard'
    _inherit = 'change.password.wizard'
    _description = "Change Password Wizard"

    def _default_user_ids(self):
        user_ids = self._context.get('active_model') == 'res.users' and self._context.get('active_ids') or []
        return [
            (0, 0, {'user_id': user.id, 'user_login': user.login})
            for user in self.env['res.users'].browse(user_ids)
        ]

    user_ids = fields.One2many('change.password.user', 'wizard_id', string='Users', default=_default_user_ids)

    def change_password_button(self):
        # Ensure one record in set
        self.ensure_one()
        self.user_ids.change_password_button()
        if self.env.user in self.user_ids.user_id:
            return {'type': 'ir.actions.client', 'tag': 'reload'}
        return {'type': 'ir.actions.act_window_close'}

class ChangePasswordUser(models.TransientModel):
    _name = 'change.password.user'
    _inherit = 'change.password.user'
    _description = "User, Change Password LDAP"

    wizard_id = fields.Many2one('change.password.wizard', string='Wizard', required=True, ondelete='cascade')
    user_id = fields.Many2one('res.users', string='User', required=True, ondelete='cascade')
    user_login = fields.Char(string='User Login', readonly=True)
    new_passwd = fields.Char(string='New Password', default='')

    def change_password_button(self):
        user_id = self.user_id
        username = str(user_id.login)
        new_passwd = self.new_passwd

        _logger.info("Calling LDAPAPI. Updating LDAP Password for" + username)

        if len(new_passwd) == 0:
            raise UserError(_("Before clicking on 'Change Password', you have to write a new password."))
        
        # Get LDAP Config and store in dictionary
        env = api.Environment(http.request.cr, SUPERUSER_ID, {})
        ldap_records = env['res.company.ldap'].search([])
        ldap_dict = {}
        for record in ldap_records:
            ldap_dict[record.id] = record.read()

        # Use LDAP Config to change password
        if ldap_dict:
            first_ldap_id = next(iter(ldap_dict))
            ldap_config = env['res.company.ldap'].browse(first_ldap_id)
        else:
            ldap_config = None

        if ldap_config:
            changed, message = ldap_config._change_password_admin_exceptions(ldap_config, username, new_passwd)

            if changed:
                _logger.info("Password reset has succeeded for: " + username + ".")
                user_id.password = ''
                user_id._set_password()

                return { 'type': 'ir.actions.act_window_close' }

            else:
                _logger.error("Password reset has failed for: " + username + ".")
                raise UserError(message)
        else:
            _logger.info("No LDAP Config.")
            raise UserError('No LDAP Configuration found.')        

class LDAPResetController(http.Controller):

    @http.route('/web/reset_ldap_password', type='http', auth='public', website=True)
    def reset_ldap_password(self, **kwargs):
        
        if kwargs.get('otp') and kwargs.get('login') and kwargs.get('new_password') and kwargs.get('confirm_password'):
            otp_code = kwargs.get('otp')
            username = kwargs.get('login')
            new_password = kwargs.get('new_password')
            confirm_password = kwargs.get('confirm_password')

            error_response_values = {'login': username}


            # Verify the passwords entered are the same
            if new_password != confirm_password:
                error_response_values['password_error'] = "Passwords do not match!"
                return http.request.render('ldap_reset_password.template_otp_entry', error_response_values)
            
            # Check OTP
            env = api.Environment(http.request.cr, SUPERUSER_ID, {})
            try:
                otp = env['otp'].search([('otp_code', '=', otp_code)], limit=1)

                if not otp:
                    error_response_values['error_message'] = "One Time Password not found!"
                    return http.request.render('ldap_reset_password.template_otp_entry', error_response_values)

                # Verify it isn't expired
                if otp.expiration_time < datetime.now() - timedelta(minutes=15):
                    error_response_values['error_message'] = "One Time Password has expired!"
                    return http.request.render('ldap_reset_password.template_otp_entry', error_response_values)

                # Verify it belongs to the same user
                user = env['res.users'].search([('login', '=', username)], limit=1)

                if not user or otp.user_id.id != user.id:
                    error_response_values['error_message'] = "User not found or One Time Password mismatch!"
                    return http.request.render('ldap_reset_password.template_otp_entry', error_response_values)

                ldap_config = env['res.company.ldap'].search([], limit=1)

                if ldap_config:
                    changed, message = ldap_config._change_password_admin_exceptions(ldap_config, username, new_password)

                    if changed:
                        _logger.info("Password reset has succeeded for: " + username + ".")

                        # Set Flectra password to nothing so that LDAP is primary form of authentication
                        user.password = ''
                        user.sudo()._set_password()
                        return http.request.render('ldap_reset_password.portal_thanks', {'message': 'Password reset has succeeded for {}'.format(username)})
                    else:
                        _logger.info("LDAP Server produced the following error: " + message)
                        error_response_values['error_message'] = "Password reset has failed for: " + username + "."
                        return http.request.render('ldap_reset_password.template_otp_entry', error_response_values)
                else:
                    error_response_values['error_message'] = "No LDAP Configuration. Please contact a System administrator via the helpdesk."
                    return http.request.render('ldap_reset_password.template_otp_entry', error_response_values)

            except Exception as e:
                error_response_values['error_message'] = f"An error occurred: {e}"
                return http.request.render('ldap_reset_password.template_otp_entry', error_response_values)

        if kwargs.get('login'):

            username = kwargs.get('login')

            # Get LDAP Config and store in dictionary
            env = api.Environment(http.request.cr, SUPERUSER_ID, {})
            user = env['res.users'].search([('login', '=', username)])

            # Get the first user (administrator) to get their email
            administrator = env['res.users'].search([], limit=1, order='id')
            administrator_email = administrator.partner_id.email_normalized if administrator.partner_id else ""

            if user:
                # Make sure the user has an email address (so email_normailzed or email)
                if user.partner_id.email:
                    
                    # Generate and store OTP
                    otp_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                    expiration_time = datetime.now() + timedelta(minutes=15)

                    env['otp'].create({
                        'user_id': user.id,
                        'otp_code': otp_code,
                        'expiration_time': expiration_time,
                    })

                    #website_name = http.request.website.name
                    website_domain = http.request.httprequest.headers.get('Host')

                    subject = "One Time Password for Password Change Verification"

                    # Fix for localhost (remove Host port if exists before using in email_from)
                    website_domain = website_domain.split(':')[0]

                    if website_domain == "localhost":
                        website_domain = "rotaryoceania.zone"
                    email_from = f"no-reply@{website_domain}"
                    
                    # Load the email template
                    mail_template = env['mail.template'].sudo().search([('name', '=', 'Reset LDAP Password Email')], limit=1)

                    # Required by function and doesn't actually do anything. Custom values entered through custom context.
                    email_values = {
                        'email_from': email_from,
                    }

                    # Create the dict to hold custom values to pass to the template via context
                    custom_context = {
                        'subject': subject,
                        'otp_code': otp_code,
                        'administrator_email': administrator_email,
                        'email_from': email_from
                    }

                    # Call send_mail function
                    mail_template.with_context(custom_context).sudo().send_mail(user.id, email_values)

                    # No email address on partner
                    return http.request.render('ldap_reset_password.template_otp_entry', {'login': username})
                else:
                    # Helpdesk
                    return http.request.render('ldap_reset_password.template_contact_admin')
            else:
                # No user exists with that username
                return http.request.render('ldap_reset_password.template_invalid_login')
                             
        return http.request.render('ldap_reset_password.template_otp', {'message': 'Placeholder'})

    # Redirect to change LDAP password page
    @http.route('/web/reset_password', type='http', auth="public", website=True)
    def reset_password(self):
        _logger.info("Redirecting to Reset LDAP Password.")
        return request.redirect('/web/reset_ldap_password')

class LDAPSignupController(AuthSignupController):
    
    @http.route('/web/is_member', type='http', auth='public', website=True)
    def is_member(self, **kwargs):
        return http.request.render('ldap_reset_password.signup_is_member')

    @http.route('/web/signup_non_member', type='http', auth='public', website=True, sitemap=False)
    def web_auth_signup_non_member(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()

        if not qcontext.get('token') and not qcontext.get('signup_enabled'):
            raise werkzeug.exceptions.NotFound()

        if 'error' not in qcontext and request.httprequest.method == 'POST':
            
            try:
                # Register LDAP
                env = api.Environment(http.request.cr, SUPERUSER_ID, {})
                
                # Get LDAP Config and store in dictionary
                ldap_records = env['res.company.ldap'].search([])
                ldap_dict = {}
                for record in ldap_records:
                    ldap_dict[record.id] = record.read()

                # Use LDAP Config to change password
                if ldap_dict:
                    first_ldap_id = next(iter(ldap_dict))
                    ldap_config = env['res.company.ldap'].browse(first_ldap_id)
                else:
                    ldap_config = None
                
                if ldap_config:
                    sn = qcontext['last_name']
                    fn = qcontext['first_name']
                    rotaryId = str(generate_random_number(5,8))
                    login = sn + rotaryId
                    cn = fn + ' ' + sn
                    dn = "uid=" + login + ", " + ldap_config.ldap_base  
                    
                    attrs = {
                        "uid": [login.encode()],
                        "givenname": [fn.encode()],
                        "cn": [cn.encode()],
                        "sn": [sn.encode()],
                        #"ou": [qcontext['rotary_club'].encode()],
                        "employeeNumber": [rotaryId.encode()],
                        "mail": [qcontext['email'].encode()],
                        "userPassword": [qcontext['password'].encode()],
                        "objectclass": [b"top", b"inetOrgPerson"],
                    }
                    
                    ldap_entry = (dn, attrs)
                    user_id, existing_user = ldap_config._get_or_create_user(ldap_config, login, ldap_entry)

                    if (existing_user):
                        return http.request.render('ldap_reset_password.web_error', {'message': 'Error: User already exists.'}) 

                    if isinstance(user_id, int):                       
                        _logger.info('res_user created. Creating LDAP User for: ' + login)

                        created, message = ldap_config._create_ldap_user(ldap_config, dn, attrs)

                        if (created):
                            user = request.env['res.users'].sudo().browse(user_id)                            
                            role = env['res.users.role'].search([('name', '=', 'Guests')])

                            if rotaryId.isdigit():
                                user.partner_id.write({
                                    'rotary_membership_id': str(rotaryId)
                                })
                            else:
                                _logger.info("User %s: provided rotaryId cannot be converted to an integer.", user.login)

                            # Remove Current Role Lines
                            role_lines = env['res.users.role.line'].search([('user_id', '=', user_id)])
                            role_lines.unlink()

                            start_date = date.today()
                            end_date = date(2099, 12, 31)

                            # If the role exists
                            if role:
                                env['res.users.role.line'].create({
                                    'user_id': user.id,
                                    'role_id': role.id,
                                    'date_from': start_date,
                                    'date_to': end_date
                                })
                                user.set_groups_from_roles()

                            return http.request.render('ldap_reset_password.web_thanks', {'message': 'You have created user: {}'.format(login)})
                        else:
                            # Delete user if LDAP fails
                            delete_user = self.env['res.users'].browse(user_id)
                            delete_user.unlink()

                            return http.request.render('ldap_reset_password.web_error', {'message': message + '.'}) 

                    elif isinstance(user_id, str):
                        qcontext['error'] = _("Could not create a new account. " + str(user_id))

            except Exception as e:
                _logger.error("%s", e)
                qcontext['error'] = _("Could not create account. " + str(e))

        response = request.render('ldap_reset_password.signup_non_member', qcontext)
        response.headers['X-Frame-Options'] = 'DENY'
        return response

    @http.route('/web/signup', type='http', auth='public', website=True, sitemap=False)
    def web_auth_signup(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()

        partners_club_name_not_empty = request.env['res.partner'].sudo().search([('club_name', '!=', '')])
        clubs = []
        #notclubs = []

        for partner in partners_club_name_not_empty:
            if partner.club_name is not None and partner.club_name != '':
                clubs.append(partner)
                #_logger.info("Added to clubs: Partner ID: %s, Club Name: %s", partner.id, partner.club_name)
            #else:
                #notclubs.append(partner)
                #_logger.info("Added to notclubs: Partner ID: %s, Club Name: %s", partner.id, partner.club_name or "None")

        qcontext['clubs'] = clubs

        if not qcontext.get('token') and not qcontext.get('signup_enabled'):
            raise werkzeug.exceptions.NotFound()

        if 'error' not in qcontext and request.httprequest.method == 'POST':            
            try:
                # Register LDAP
                env = api.Environment(http.request.cr, SUPERUSER_ID, {})
                
                # Get LDAP Config and store in dictionary
                ldap_records = env['res.company.ldap'].search([])
                ldap_dict = {}
                for record in ldap_records:
                    ldap_dict[record.id] = record.read()

                # Use LDAP Config to change password
                if ldap_dict:
                    first_ldap_id = next(iter(ldap_dict))
                    ldap_config = env['res.company.ldap'].browse(first_ldap_id)
                else:
                    ldap_config = None
                
                if ldap_config:
                    sn = qcontext['last_name']
                    fn = qcontext['first_name']
                    rotaryId = qcontext['rotary_id']
                    login = sn + rotaryId
                    cn = fn + ' ' + sn
                    dn = "uid=" + login + ", " + ldap_config.ldap_base  
                    
                    rotary_club_id = int(qcontext['rotary_club_id'])

                    attrs = {
                        "uid": [login.encode()],
                        "givenname": [fn.encode()],
                        "cn": [cn.encode()],
                        "sn": [sn.encode()],
                        "ou": [str(rotary_club_id).encode()],
                        "employeeNumber": [qcontext['rotary_id'].encode()],
                        "mail": [qcontext['email'].encode()],
                        "userPassword": [qcontext['password'].encode()],
                        "objectclass": [b"top", b"inetOrgPerson"],
                    }
                    
                    ldap_entry = (dn, attrs)
                    user_id, existing_user = ldap_config._get_or_create_user(ldap_config, login, ldap_entry)
                    
                    if (existing_user):
                        return http.request.render('ldap_reset_password.web_error', {'message': 'Error: User already exists.'}) 
                    
                    # If we have new_user.id
                    if isinstance(user_id, int):
                        _logger.info('res_user created. Creating LDAP User for: ' + login)
                        
                        created, message = ldap_config._create_ldap_user(ldap_config, dn, attrs)

                        if (created):
                            user = request.env['res.users'].sudo().browse(user_id)
                            
                            if rotaryId.isdigit():
                                user.partner_id.write({
                                    'rotary_club_id': rotary_club_id,
                                    'rotary_membership_id': str(rotaryId)
                                })
                            else:
                                user.partner_id.write({'rotary_club_id': rotary_club_id})
                                _logger.info("User %s: provided rotaryId cannot be converted to an integer.", user.login)

                            # Clear the groups
                            #user.groups_id = env['res.groups']
                            
                            # Search for the role with the name "Members"
                            role = env['res.users.role'].search([('name', '=', 'Members')])

                            start_date = date.today()
                            end_date = date(2099, 12, 31)

                            # Remove Current Role Lines
                            role_lines = env['res.users.role.line'].search([('user_id', '=', user_id)])
                            role_lines.unlink()

                            # If the role exists
                            if role:
                                env['res.users.role.line'].create({
                                    'user_id': user.id,
                                    'role_id': role.id,
                                    'date_from': start_date,
                                    'date_to': end_date
                                })
                                user.set_groups_from_roles()

                            return http.request.render('ldap_reset_password.web_thanks', {'message': 'You have created user: {}'.format(login)})
                        else:
                            # Delete user if LDAP fails
                            delete_user = self.env['res.users'].browse(user_id)
                            delete_user.unlink()

                            return http.request.render('ldap_reset_password.web_error', {'message': message + '.'}) 

                    elif isinstance(user_id, str):                                           
                        qcontext['error'] = _("Could not create a new account. " + str(user_id))

            except Exception as e:
                _logger.error("%s", e)
                qcontext['error'] = _("Could not create account. " + str(e))

        response = request.render('ldap_reset_password.signup', qcontext)
        response.headers['X-Frame-Options'] = 'DENY'
        return response

    def get_auth_signup_qcontext(self):
        """ Shared helper returning the rendering context for signup and reset password """
        qcontext = {k: v for (k, v) in request.params.items() if k in SIGN_UP_REQUEST_PARAMS}
        qcontext.update(self.get_auth_signup_config())
        if not qcontext.get('token') and request.session.get('auth_signup_token'):
            qcontext['token'] = request.session.get('auth_signup_token')
        if qcontext.get('token'):
            try:
                # retrieve the user info (name, login or email) corresponding to a signup token
                token_infos = request.env['res.partner'].sudo().signup_retrieve_info(qcontext.get('token'))
                for k, v in token_infos.items():
                    qcontext.setdefault(k, v)
            except:
                qcontext['error'] = _("Invalid signup token")
                qcontext['invalid_token'] = True
        return qcontext

class CompanyLDAP(models.Model):
    _name = 'res.company.ldap'
    _description = 'Company LDAP configuration'
    _inherit = 'res.company.ldap'
    _order = 'sequence'
    _rec_name = 'ldap_server'

    sequence = fields.Integer(default=10)
    company = fields.Many2one('res.company', string='Company', required=True, ondelete='cascade')
    ldap_server = fields.Char(string='LDAP Server address', required=True, default='127.0.0.1')
    ldap_server_port = fields.Integer(string='LDAP Server port', required=True, default=389)
    ldap_binddn = fields.Char('LDAP binddn',
        help="The user account on the LDAP server that is used to query the directory. "
             "Leave empty to connect anonymously.")
    ldap_password = fields.Char(string='LDAP password',
        help="The password of the user account on the LDAP server that is used to query the directory.")
    ldap_filter = fields.Char(string='LDAP filter', required=True)
    ldap_base = fields.Char(string='LDAP base', required=True)
    user = fields.Many2one('res.users', string='Template User',
        help="User to copy when creating new users")
    create_user = fields.Boolean(default=True,
        help="Automatically create local user accounts for new users authenticating via LDAP")
    ldap_tls = fields.Boolean(string='Use TLS',
        help="Request secure TLS/SSL encryption when connecting to the LDAP server. "
             "This option requires a server with STARTTLS enabled, "
             "otherwise all authentication attempts will fail.")

   
    def _get_entry(self, conf, login):
        filter, dn, entry = False, False, False
        try:
            filter = filter_format(conf['ldap_filter'], (login,))
        except TypeError:
            _logger.warning('Could not format LDAP filter. Your filter should contain one \'%s\'.')

        if filter:
            results = self._query(conf, tools.ustr(filter))
            # Get rid of (None, attrs) for searchResultReference replies
            results = [i for i in results if i[0]]

            # Find the first entry with only one uid attribute
            for result in results:
                if len(result[1].get('uid', [])) == 1:
                    entry = result
                    dn = result[0]
                    break

            if entry:
                _logger.info("Found matching LDAP entry: %s", entry)
            else:
                _logger.warning("No matching LDAP entries found for filter: %s", filter)
        else:
            _logger.warning("No LDAP filter available. Unable to perform query.")
            
        return dn, entry

    def _change_password_admin_exceptions(self, conf, login, new_passwd):
        changed = False
        message = ""

        dn, entry = self._get_entry(conf, login)
        _logger.info('DN: %s, Entry: %s', dn, entry)  # Log the results from _get_entry


        admindn = conf.ldap_binddn
        adminpw = conf.ldap_password

        if not dn:
            _logger.info('User not found in LDAP directory, creating...')  # Log that user is not found

            # Get res.user associated 
            env = api.Environment(http.request.cr, SUPERUSER_ID, {})       
            user = env['res.users'].search([('login', '=', login)], limit=1)

            if user:
                full_name = user.partner_id.name.strip()
                parts = full_name.split()

                if len(parts) == 1:
                    first_name = parts[0]
                    last_name = ''
                elif len(parts) == 2:
                    first_name, last_name = parts
                else:
                    # Assume the last part is the last name, and everything else is the first name
                    first_name = ' '.join(parts[:-1])
                    last_name = parts[-1]

                first_name = first_name or 'Default First Name'
                last_name = last_name or 'Default Last Name'

                attrs = {
                    "uid": [login.encode()],
                    "givenname": [first_name.encode()],
                    "cn": [full_name.encode()],
                    "sn": [last_name.encode()],
                    "userPassword": [new_passwd.encode()],
                    "objectclass": [b"top", b"inetOrgPerson"],
                }

                email = getattr(user.partner_id,'email', None)
                if email:
                    attrs["mail"] = [email.encode()]

                # Handle differently, so if they have a rotary_club_id you need to look up the partner and grab the club_id and use that one otherwise leave blank
                ou = getattr(user.partner_id, 'rotary_club_id', None)
                if ou and ou.club_id:
                    attrs["ou"] = [ou.club_id.encode()]

                # Extract Rotary ID from login
                rotary_id = extract_rotary_id(login, last_name)
                if rotary_id:
                    attrs["employeeNumber"] = [rotary_id.encode()]

                dn = 'UID=' + login + ', ' + self.ldap_base
                
                created, message = self._create_ldap_user(conf, dn, attrs)

                if (created):
                    return True, message
                else:
                    return False, message               
            else:

                return False, "User not found in LDAP directory."
        try:
            conn = self._connect(conf)
            conn.simple_bind_s(admindn, adminpw)
            conn.passwd_s(dn, None, new_passwd)
            changed = True
            message = 'Success'
            conn.unbind()
        except ldap.INVALID_CREDENTIALS as e:
            _logger.error('An LDAP exception occurred: %s', e)
            message = 'An LDAP exception occurred: ' + str(e)
            pass
        except ldap.LDAPError as e:
            _logger.error('An LDAP exception occurred: %s', e)
            message = 'An LDAP exception occurred: ' + str(e)
        return changed, message
   
    # Below functions unchanged from default res.company.ldap but inherited to allow for changes later if required.

    def _get_or_create_user(self, conf, login, ldap_entry):
        """
        Retrieve an active resource of model res_users with the specified
        login. Create the user if it is not initially found.

        :param dict conf: LDAP configuration
        :param login: the user's login
        :param tuple ldap_entry: single LDAP result (dn, attrs)
        :return: res_users id
        :rtype: int
        """
        
        existing_user = False

        login = tools.ustr(login.lower().strip())
        self.env.cr.execute("SELECT id, active FROM res_users WHERE lower(login)=%s", (login,))
        res = self.env.cr.fetchone()
        _logger.debug("Fetched user: %s", res)
        
        # If they exist
        if res:
            # if active == true
            if res[1]:
                # return the id
                existing_user = True
                return res[0], existing_user

        elif conf['create_user']:

            _logger.debug("Creating new Flectra user \"%s\" from LDAP" % login)
            values = self._map_ldap_attributes(conf, login, ldap_entry)
            SudoUser = self.env['res.users'].sudo().with_context(no_reset_password=True)
            
            if conf['user']:
                values['active'] = True
                user_id = SudoUser.browse(conf['user'][0]).copy(default=values).id
                _logger.debug("Created new user from existing user: %s", user_id)
                return user_id, existing_user
            else:
                user_id = SudoUser.create(values).id
                _logger.debug("Created new user: %s", user_id)
                return user_id, existing_user
        raise AccessDenied(_("No local user found for LDAP login and not configured to create one"))

    def _create_ldap_user(self, conf, user_dn, attributes):
        created = False
        message = ""

        admindn = conf.ldap_binddn
        adminpw = conf.ldap_password

        try:
            conn = self._connect(conf)
            conn.simple_bind_s(admindn, adminpw)

            # Add the user entry
            modlist_data = modlist.addModlist(attributes)
            conn.add_s(user_dn, modlist_data)

            created = True
            message = 'Success'
            conn.unbind()
        except ldap.INVALID_CREDENTIALS as e:
            _logger.error('An LDAP exception occurred: %s', e)
            message = 'An LDAP exception occurred: ' + str(e)
        except ldap.LDAPError as e:
            if e.args and 'desc' in e.args[0] and e.args[0]['desc'] == 'Already exists':
                _logger.warning('The LDAP entry already exists: %s', e)
                message = 'The LDAP entry already exists: ' + str(e)
            else:           
                _logger.error('An LDAP exception occurred: %s', e)
                message = 'An LDAP exception occurred: ' + str(e)

        return created, message

    def _map_ldap_attributes(self, conf, login, ldap_entry):
        # Call the original method using super()
        values = super()._map_ldap_attributes(conf, login, ldap_entry)

        # Modify the values to return the company's ID instead of the company object
        values['company_id'] = conf['company'].id

        # Return the modified values
        return values

class CustomerPortal(Controller):

    MANDATORY_BILLING_FIELDS = ["name", "phone", "email", "street", "city", "country_id"]
    OPTIONAL_BILLING_FIELDS = ["zipcode", "state_id", "vat", "company_name"]

    _items_per_page = 20

    def _prepare_portal_layout_values(self):
        """Values for /my/* templates rendering.

        Does not include the record counts.
        """
        # get customer sales rep
        sales_user = False
        partner = request.env.user.partner_id
        if partner.user_id and not partner.user_id._is_public():
            sales_user = partner.user_id

        return {
            'sales_user': sales_user,
            'page_name': 'home',
        }

    @route('/my/security', type='http', auth='user', website=True, methods=['GET', 'POST'])
    def security(self, **post):
        env = request.env
        values = self._prepare_portal_layout_values()
        values['get_error'] = get_error
        result = ''

        if request.httprequest.method == 'POST':        
            username = ""
            user_id = env.user.id
            user = env['res.users'].browse(user_id)
            username = user.login

            result = self._update_password(
                post['old'].strip(), 
                post['new1'].strip(), 
                post['new2'].strip(), 
                username)
                       
        if len(result) > 0:
            success = result.get('success')

            if success is not None and len(success) > 0:
                # update session token so the user does not get logged out (cache cleared by passwd change)
                new_token = request.env.user._compute_session_token(request.session.sid)
                request.session.session_token = new_token
                
                return http.request.render('ldap_reset_password.portal_thanks', {'message': 'Password reset has succeeded for {}'.format(username)})
            
            state = result.get('error', {}).get('state')

            if state == 'invalid':
                return http.request.render('ldap_reset_password.portal_error', {'message': 'Invalid old password.'})
            elif state == 'refused':
                return http.request.render('ldap_reset_password.portal_error', {'message': 'Password change refused by LDAP server.'})
            elif state == 'misc':
                message = result.get('error', {}).get('message')
                return http.request.render('ldap_reset_password.portal_error', {'message': 'Uncommon Error: ' + message + '.'})
            elif state == 'unknown':
                message = result.get('error', {}).get('message')
                return http.request.render('ldap_reset_password.portal_error', {'message': 'Unknown Error: ' + message + '.'})
        
        return request.render('portal.portal_my_security', values, headers={
            'X-Frame-Options': 'DENY'
        })

    def _update_password(self, old, new1, new2, username):
        for k, v in [('old', old), ('new1', new1), ('new2', new2)]:
            if not v:
                return {'errors': {'password': {k: _("You cannot leave any password empty.")}}}

        if new1 != new2:
            return {'errors': {'password': {'new2': _("The new password and its confirmation must be identical.")}}}

        old_passwd = old
        new_passwd = new1

        _logger.info("Calling LDAPAPI. Updating LDAP Password for %s!", username)

        # Get LDAP Config and store in dictionary
        env = api.Environment(http.request.cr, SUPERUSER_ID, {})
        ldap_records = env['res.company.ldap'].search([])
        ldap_dict = {}
        for record in ldap_records:
            ldap_dict[record.id] = record.read()

        # Use LDAP Config to change password
        if ldap_dict:
            first_ldap_id = next(iter(ldap_dict))
            ldap_config = env['res.company.ldap'].browse(first_ldap_id)
        else:
            ldap_config = None
        if ldap_config:
            changed, message = ldap_config._change_password_exceptions(ldap_config, username, old_passwd, new_passwd)

            if changed:
                _logger.info("Password reset has succeeded for: " + username + ".")

                # Get User by login
                user = env['res.users'].search([('login', '=', username)])
                if user:
                    user.password = ''
                    user._set_password()
                    #user.sudo().write({'password': ''})
                    user.invalidate_cache(['password'], [user.id])
                return { 'success': { 'state': 'changed' } }
                           
            elif not changed and "INVALID_CREDENTIALS" in message:
                _logger.error("Password reset has failed for: " + username + ". Invalid old password.")
                return { 'error': { 'state': 'invalid' } }

            elif not changed and "UNWILLING_TO_PERFORM" in message:
                _logger.error("Password reset has failed for: " + username + ". Password change refused by LDAP server.")
                return { 'error': { 'state': 'refused' } }

            elif not changed and "Success" not in message:
                _logger.error("Password reset has failed for: " + username + ". LDAP error: " + message)
                return { 'error': {
                            'state': 'misc',
                            'message': str(message) } }

            else:
                _logger.error("Password reset has failed for: " + username + ". Unhandled Error: " + message)
                return { 'error': {
                            'state': 'unknown',
                            'message': str(message) } }

def extract_rotary_id(login, last_name):
    # Convert both login and last_name to lowercase
    login = login.lower()
    last_name = last_name.lower()

    # Remove the last_name from the login
    potential_id = login.replace(last_name, '')

    # Now, potential_id should be a sequence of digits.
    # If it's length is between 5 and 8, return it, otherwise return None
    if 5 <= len(potential_id) <= 8:
        return potential_id
    else:
        return None

def get_error(e, path=''):
    """ Recursively dereferences `path` (a period-separated sequence of dict
    keys) in `e` (an error dict or value), returns the final resolution IIF it's
    an str, otherwise returns None
    """
    for k in (path.split('.') if path else []):
        if not isinstance(e, dict):
            return None
        e = e.get(k)

    return e if isinstance(e, str) else None

def generate_random_number(min_length, max_length):
    min_value = 10 ** (min_length - 1)
    max_value = (10 ** max_length) - 1
    return random.randint(min_value, max_value)