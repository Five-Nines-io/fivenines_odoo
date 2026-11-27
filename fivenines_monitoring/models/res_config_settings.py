# Part of Fivenines Monitoring. License LGPL-3.
from datetime import datetime, timezone

from odoo import _, api, fields, models
from odoo.exceptions import AccessError

from .fivenines_monitor import P_API_URL, P_KEY, P_MESSAGES_OFF, P_PAUSED, icp_get, icp_set


def _fmt_ts(ts):
    if not ts:
        return False
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    fivenines_enrollment_key = fields.Char(
        string='Fivenines enrollment key', config_parameter=P_KEY,
        help='The enrollment key of your Fivenines organization. It is used once: Fivenines '
             'answers with a secret for this database only, and the key is then removed from this '
             'database. It can also come from the Odoo config file (fivenines_enrollment_key) or '
             'the FIVENINES_ENROLLMENT_KEY environment variable, where it stays.')
    fivenines_paused = fields.Boolean(
        string='Pause monitoring', config_parameter=P_PAUSED,
        help='Stop sending metrics from this database, without forgetting its enrollment.')
    fivenines_api_url = fields.Char(
        string='Fivenines API URL', config_parameter=P_API_URL,
        help='Leave empty for https://api.fivenines.io. Can also be set with fivenines_api_url in '
             'the Odoo config file or the FIVENINES_API_URL environment variable.')
    fivenines_send_error_messages = fields.Boolean(
        string='Send error messages', default=True,
        help='Send the latest message and traceback of each error group (passwords, tokens and '
             'API keys are always masked). Off: only the error groups and their counts are sent.')
    fivenines_key_source = fields.Char(string='Key source', compute='_compute_fivenines_status')
    fivenines_state = fields.Char(string='State', compute='_compute_fivenines_status')
    fivenines_instance_id = fields.Char(string='Instance', compute='_compute_fivenines_status')
    fivenines_last_push = fields.Char(string='Last push', compute='_compute_fivenines_status')
    fivenines_last_error = fields.Char(string='Last error', compute='_compute_fivenines_status')

    @api.model
    def get_values(self):
        res = super().get_values()
        off = icp_get(self.env['ir.config_parameter'].sudo(), P_MESSAGES_OFF)
        res['fivenines_send_error_messages'] = (off or '').lower() not in ('1', 'true')
        return res

    def set_values(self):
        super().set_values()
        # stored inverted: a False boolean parameter cannot be stored on 16-19
        icp_set(self.env['ir.config_parameter'].sudo(), P_MESSAGES_OFF,
                None if self.fivenines_send_error_messages else 'True')

    @api.depends('fivenines_enrollment_key', 'fivenines_paused')
    def _compute_fivenines_status(self):
        status = self.env['fivenines.monitor']._fn_status()
        labels = {
            'settings': _('Settings (this database)'),
            'odoo.conf': _('Odoo config file'),
            'environment': _('Environment variable'),
        }
        name = status.get('name') or _('this database')
        if not status['cron_active']:
            state = (_('This database is a neutralized copy: monitoring is off. Click "Turn it on" '
                       'to monitor it; it is then proposed in Fivenines, waiting for approval.')
                     if status['neutralized'] else
                     _('The "Fivenines: push metrics" scheduled action is off: monitoring is off. '
                       'Click "Turn it on" to start it again.'))
        elif status['paused']:
            state = _('Paused')
        elif status['status'] == 'pending':
            state = _('Waiting for approval in Fivenines as "%s": choose Monitor for it in Fivenines '
                      'to start monitoring (checked every few minutes, "Send now" checks at once).') % name
        elif status['status'] == 'ignored':
            state = _('Not monitored: ignored in Fivenines. To monitor this database after all, paste '
                      'an enrollment key and click "Re-enroll": it is proposed again.')
        elif status['status'] == 'copy_needs_key':
            state = _('This database is a copy, and the secret it carries was revoked: paste an '
                      'enrollment key to enroll it.')
        elif status['status'] == 'revoked':
            state = _('Refused by Fivenines (revoked?): retried once a day; click "Re-enroll" to start over')
        elif status['status'] == 'enrollment_refused':
            state = _('Enrollment key refused by Fivenines')
        elif status['enrolled']:
            state = _('Enrolled (the enrollment key was used once and is not kept)')
            if status['failures']:
                state = _('Enrolled, %s failed push(es), next attempt %s') % (
                    status['failures'], _fmt_ts(status['next_attempt_at']) or '-')
        elif status['key_source']:
            state = _('Waiting for the first run (within a minute)')
        else:
            state = _('Not configured: paste your enrollment key')
        if status['request_capture'] == 'disabled':
            state += _(' (request metrics unavailable: werkzeug logging is disabled)')
        last = status['last_success'] or {}
        summary = last.get('summary') or {}
        error = status['last_error'] or {}
        for rec in self:
            source = 'settings' if rec.fivenines_enrollment_key else (
                status['key_source'] if status['key_source'] != 'settings' else None)
            rec.fivenines_key_source = labels.get(source, _('None'))
            rec.fivenines_state = state
            rec.fivenines_instance_id = status['instance_id'] or False
            rec.fivenines_last_push = (_('%s (%s requests, %s errors, %s worker(s))') % (
                _fmt_ts(last.get('at')), summary.get('requests'), summary.get('errors'),
                summary.get('workers'))) if last.get('at') else False
            rec.fivenines_last_error = ('%s: %s %s' % (
                _fmt_ts(error.get('at')), error.get('status') or error.get('kind') or '',
                error.get('message') or '')).strip() if error.get('at') else False

    def _fivenines_check_admin(self):
        if not self.env.user.has_group('base.group_system'):
            raise AccessError(_('Only administrators can manage Fivenines Monitoring.'))

    def _fivenines_notify(self, outcome):
        result = outcome.get('result')
        messages = {
            'pushed': (_('Metrics sent to Fivenines.'), 'success'),
            'enrolled': (_('Enrolled.'), 'success'),
            'no_key': (_('No enrollment key: paste one first.'), 'warning'),
            'paused': (_('Monitoring is paused.'), 'warning'),
            'busy': (_('A push is already running, try again in a few seconds.'), 'warning'),
            'revoked': (_('Fivenines refused this database\'s secret (revoked?): it is retried once '
                          'a day; click "Re-enroll" to start over.'), 'danger'),
            'pending': (_('Waiting for approval in Fivenines as "%s".') % (
                outcome.get('name') or _('this database')), 'warning'),
            'ignored': (_('Ignored in Fivenines: nothing is sent from this database.'), 'warning'),
            'enrollment_refused': (_('Fivenines refused the enrollment key.'), 'danger'),
            'backoff': (_('Fivenines is unreachable, the next attempt is scheduled.'), 'warning'),
            'config_error': (_('Configuration error: %s') % (outcome.get('message') or ''), 'warning'),
            'error': (_('The push failed on this server: %s') % (outcome.get('message') or ''), 'danger'),
        }
        if result == 'conflict':
            # the secret was in use elsewhere: this database announced itself as a copy
            if outcome.get('enroll') == 'enrolled':
                message, kind = (
                    (_('Another database (probably the original of this copy) uses this secret: '
                       'this database was proposed in Fivenines as a new one, waiting for approval.'),
                     'warning') if outcome.get('state') == 'pending' else
                    (_('Another database (probably the original of this copy) uses this secret: '
                       'this database enrolled as a new one.'), 'success'))
            else:
                message, kind = (_('Another database (probably the original of this copy) uses this '
                                   'secret; enrolling this one as a new database failed, it will '
                                   'retry.'), 'warning')
        else:
            # never echo the server's own text here: the URL may not be Fivenines
            message, kind = messages.get(result, (
                _('Fivenines answered: %s') % ' '.join(
                    str(v) for v in (('HTTP %s' % outcome['status']) if outcome.get('status') else None,
                                     outcome.get('kind')) if v),
                'danger'))
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Fivenines Monitoring'),
                'message': message,
                'type': kind,
                'sticky': False,
                'next': {'type': 'ir.actions.client', 'tag': 'reload'},
            },
        }

    def action_fivenines_push_now(self):
        self._fivenines_check_admin()
        self.set_values()
        outcome = self.env['fivenines.monitor'].sudo()._fn_run(trigger='manual', force=True)
        return self._fivenines_notify(outcome)

    def action_fivenines_turn_on(self):
        """Re-activate the push scheduled action (e.g. on a neutralized copy)."""
        self._fivenines_check_admin()
        self.set_values()
        self.env['fivenines.monitor'].sudo()._fn_turn_on()
        outcome = self.env['fivenines.monitor'].sudo()._fn_run(trigger='manual', force=True)
        return self._fivenines_notify(outcome)

    def action_fivenines_reenroll(self):
        self._fivenines_check_admin()
        self.set_values()
        outcome = self.env['fivenines.monitor'].sudo()._fn_run(
            trigger='manual', force=True, reenroll=True)
        return self._fivenines_notify(outcome)
