{
    'name': 'LDAP Reset Password',
    'summary': 'Add LDAP Reset Password functionality',
    'description': 'A module to allow for a User to reset their password in LDAP from the reset password form.',
    'version': '1.0',
    'author': 'Nathan Stocking',
    'depends': ['auth_ldap','base', 'membership', 'rotary_project_map'],
    'data': [
        'reset_ldap_password.xml',
    ],
    'installable': True,
    'auto_install': False,
}
