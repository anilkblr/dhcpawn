# project.py

import gossip
from .ldap_utils import ldap_init
import logbook
import os
from raven.contrib.flask import Sentry


@gossip.register('cob.after_configure_app')
def after_configure_app(app):

    level = os.environ.get('_DHCPAWN_LOG_LEVEL', logbook.INFO)
    log_handler = logbook.FileHandler('dhcpawn.log', mode='a', level=int(level))
    log_handler.format_string = '[{record.time:%Y-%m-%d %H:%M:%S.%f%z}] {record.level_name}: {record.channel}: {record.func_name}: {record.lineno}:  {record.message}'
    log_handler.push_application()
    app.ldap_obj = ldap_init()

    # Sentry
    app.config['SENTRY_DSN'] = 'http://1798f04a5bc749e7a99ba63eb8346e60:4560f83a51764b7b8f4fc400aa4b0b8e@sentry.infinidat.com/51'
    Sentry(app)
