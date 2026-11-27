# Part of Fivenines Monitoring. License LGPL-3.
{
    'name': 'Fivenines Monitoring',
    'summary': 'Push this instance\'s metrics (requests, errors, scheduled actions, '
               'database, system) to Fivenines every minute',
    'description': """
Fivenines Monitoring
====================

Monitors the inside of each Odoo instance and pushes the metrics to Fivenines
every minute over HTTPS: requests per minute and latency, SQL per request,
errors by fingerprint, late or stuck scheduled actions, database size and
connections, CPU / memory / disk (container aware), restarts.

Install it, paste your Fivenines enrollment key in Settings > Fivenines
Monitoring (or put it in the Odoo config file / an environment variable), done.
Nothing to open on the firewall: the instance pushes, Fivenines never pulls.
""",
    # ONE tree (and one release zip) for every serie: keep the version serie-free
    # and in TWO parts, x.y. Odoo prefixes its serie at load time (16.0.1.0 ...);
    # a serie-prefixed version is refused by the other series, and Odoo 16 never
    # runs a migration of a three-part x.y.z version (it takes x.y.z for a full
    # serie version). Each release bumps y; migrations go in migrations/x.y/.
    # The publish workflow prefixes the serie on the Apps Store branches.
    'version': '1.0',
    'category': 'Administration',
    'author': 'Fivenines',
    'website': 'https://fivenines.io',
    'license': 'LGPL-3',
    'depends': ['base', 'web'],
    'external_dependencies': {'python': ['psutil', 'requests']},
    'data': [
        'data/ir_cron.xml',
        'views/res_config_settings_views.xml',
    ],
    'uninstall_hook': 'uninstall_hook',
    'installable': True,
    'application': False,
}
