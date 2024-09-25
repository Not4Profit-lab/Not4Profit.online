# -*- coding: utf-8 -*-
# Part of BrowseInfo. See LICENSE file for full copyright and licensing details.

{
    "name": "SMS Client",
    "version": "17.0.0.0",
    'category': "Extra Tools",
    'summary': "SMS Client Odoo App provides functionality to send SMS to customer's mobile based on configuration of SMS Gateway. This app helps to configure sms templates for each action so users can manage the content of messages sent to customers.",
    "description": """
SMS Client module provides:
-------------
Sending SMSs very easily, individually or collectively.

*Generalities

OpenERP does not directly generate the SMS you will have to subscribe to an operator with a web interface (Type OVH) or via a URL generation.
If you want to use a 'SMPP Method' you must have to install the library "Soap" which can be installed with: apt-get install python-soappy.
You can find it on https://pypi.python.org/pypi/SOAPpy/
You don't need it if you use a "HTTP Method' to send the SMS.

*Use Multiple Gateways.

The Gateway configuration is performed directly in the configuration menu. For each gateway, you have to fill in the information for your operator.

To validate Gateway, code is send to a mobile phone, when received enter it to confirm SMS account.

This Module was developped by SYLEAM and OpenERP SA in a first place.
Then, it was updated to the 7.0 version by Julius Network Solutions.
    """,
    "author": "BrowseInfo",
    "website" : "https://www.browseinfo.com",
    "price": 000,
    "currency": 'EUR',
    'license': 'LGPL-3',
    "depends": ["base","mail","partner_autocomplete"],
    "demo": [],
    "data": [
        "security/groups.xml",
        "security/ir.model.access.csv",
        "views/smsclient_view.xml",
        "views/serveraction_view.xml",
        "views/smsclient_data.xml",
        "views/partner_sms_send_view.xml",
        "views/smstemplate_view.xml",
        "wizard/mass_sms_view.xml",
    ],
    "auto_install": False,
    "installable": True,
    "live_test_url":'https://youtu.be/xK2U9TESNe0',
    "images":['static/description/Banner.png'],
}

# vim:expandtab:smartindent:tabstop=4:softtabstop=4:shiftwidth=4:
