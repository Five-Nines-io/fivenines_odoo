-- Part of Fivenines Monitoring. License LGPL-3.
-- Run by Odoo's neutralization (odoo-bin neutralize, neutralized duplicates and
-- restores). A neutralized database is a copy: never let it report with the
-- secret of the instance it was copied from. The instance id is kept under
-- fivenines.copied_from, so if an administrator re-activates the "Fivenines:
-- push metrics" scheduled action (neutralization deactivates all crons), the
-- copy enrolls as a new instance with reason "neutralized_copy", linked to the
-- original. Settings (enrollment key, pause, API URL) are kept.
DELETE FROM ir_config_parameter
 WHERE key = 'fivenines.copied_from'
   AND EXISTS (SELECT 1 FROM ir_config_parameter WHERE key = 'fivenines.instance_id');
UPDATE ir_config_parameter SET key = 'fivenines.copied_from' WHERE key = 'fivenines.instance_id';
DELETE FROM ir_config_parameter
 WHERE key LIKE 'fivenines.%'
   AND key NOT IN ('fivenines.enrollment_key', 'fivenines.paused', 'fivenines.api_url',
                   'fivenines.copied_from');
