-- Part of Fivenines Monitoring. License LGPL-3.
-- Run by Odoo's neutralization (odoo-bin neutralize, neutralized duplicates and
-- restores). A neutralized database is a copy: never let it report with the
-- secret of the instance it was copied from. The enrollment key is kept, so if
-- an administrator re-activates the "Fivenines: push metrics" scheduled action
-- (neutralization deactivates all crons), the copy enrolls as a new instance.
DELETE FROM ir_config_parameter
 WHERE key IN ('fivenines.instance_secret', 'fivenines.instance_id', 'fivenines.fingerprint',
               'fivenines.enrolled_at', 'fivenines.status', 'fivenines.server_identity');
