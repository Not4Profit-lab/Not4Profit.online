{
    'name': 'Payment Provider: Windcave',
    'version': '17.0.0.0',
    'author': 'Windcave Limited',
    'website': 'https://www.windcave.com',
    'category': 'Accounting/Payment Providers',
    'sequence': 380,
    'license': 'LGPL-3',
    'summary': 'Easily accept payments in 40+ currencies in more than 30 regions around the world.',
    'description': """

Windcave offers integrated payment solutions for online, in-store, and unattended transactions, enhancing efficiency and security across a broad range of payment methods. Our platform streamlines your payment process, providing a flexible and reliable system tailored to fit your business needs, ensuring smooth and secure transactions for you and your customers.

- Windcave hosted payment page (PCI - SAQ -A compliant)
- In-built SSL cert using the latest TLS 1.2 technology on fully hosted solution.
- All major card schemes supported - Visa/Mastercard/UnionPay/Amex/Diners/Discover
""",
    'depends': ['payment'],
    'data': [
        'security/ir.model.access.csv',

        'views/payment_views.xml',
        'views/payment_windcave_templates.xml',
        'views/portal_templates.xml',

        'data/payment_provider_data.xml',
        'data/windcave_method_data.xml',

        'wizard/windcave_transaction_refund_wizard_views.xml',
    ],
    'images': ['static/description/icon.png'],
    'installable': True,
    'application': True,
    'post_init_hook': 'post_init_hook',
    'uninstall_hook': 'uninstall_hook',
}
