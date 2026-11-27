# Part of Fivenines Monitoring. License LGPL-3.
from . import models


def uninstall_hook(*args):
    """Stop counting for this database in the current process.

    Odoo 16 calls uninstall hooks with (cr, registry), 17+ with (env).
    """
    from .lib.collector import COLLECTOR
    first = args[0] if args else None
    dbname = getattr(getattr(first, 'cr', first), 'dbname', None)
    if dbname:
        COLLECTOR.unregister_db(dbname)
