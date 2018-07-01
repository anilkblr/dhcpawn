# project.py

import gossip
from .ldap_utils import ldap_init
import logbook
import os
from raven.contrib.flask import Sentry
from cob.project import get_project

@gossip.register('cob.after_configure_app')
def after_configure_app(app):

    level = get_project().config.get('LOG_LEVEL', logbook.INFO)
    log_handler = logbook.FileHandler('dhcpawn.log', mode='a', level=int(level))
    log_handler.format_string = '[{record.time:%Y-%m-%d %H:%M:%S.%f%z}] {record.level_name}: {record.channel}: {record.func_name}: {record.lineno}:  {record.message}'
    log_handler.push_application()
    app.ldap_obj = ldap_init()
    if not app.config['DEBUG'] and not app.config['TESTING']:
        app.config['SENTRY_DSN'] = get_project().config.get('SENTRY_DSN')
        sentry_inst = Sentry(app)
        if os.getenv('HOSTNAME'):
            sentry_inst.client.name = os.getenv('HOSTNAME')
        else:
            sentry_inst.client.name = 'dhcpawn-unset-server'
