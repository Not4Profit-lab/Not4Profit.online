{
    'name': 'Public Helpdesk',
    'version': '1.0',
    'author': 'Verinsure',
    'category': 'Helpdesk',
    'summary': 'Public access to helpdesk form',
    'website': '',
    'description': """
Public Helpdesk
===============
This module allows public users to submit helpdesk tickets.

Please install python-magic before installing this module.

pip install python-magic

python-magic is a wrapper around the libmagic file type identification library.
If you're on a system that doesn't already have libmagic, you'll need to install it as well.

sudo apt-get install libmagic1
""",
    'depends': ['helpdesk_basic','website_helpdesk'],
    'data': [
        'security/ir.model.access.csv',
        'views/views.xml',
    ],
    'installable': True,
}
