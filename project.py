# project.py

import gossip
from .ldap_utils import ldap_init
import logbook
import os


@gossip.register('cob.after_configure_app')
def after_configure_app(app):

    level = os.environ.get('_DHCPAWN_LOG_LEVEL', logbook.INFO)
    log_handler = logbook.FileHandler(app.config['LOGGER_NAME']+'.log', mode='a', level=int(level))
    log_handler.format_string = '[{record.time:%Y-%m-%d %H:%M:%S.%f%z}] {record.level_name}: {record.channel}: {record.func_name}: {record.lineno}:  {record.message}'
    log_handler.push_application()
    app.ldap_obj = ldap_init()
