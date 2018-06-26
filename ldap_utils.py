import os
import ldap
from cob.project import get_project
import logbook


_logger = logbook.Logger(__name__)
ldap_config = get_project().config['ldap_config']

def ldap_init():

    if get_project().config.get('production'):
        _logger.info("Initializing production LDAP connection")
    else:
        _logger.info("Initializing local testing LDAP connection")

    ldap_obj = ldap.initialize(ldap_config.get('_LDAP_URI'))
    ldap_obj.set_option(ldap.OPT_REFERRALS, 0)
    ldap_obj.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    ldap_obj.set_option(ldap.OPT_TIMEOUT, 10.0)
    ldap_obj.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
    ldap_obj.set_option(ldap.OPT_X_TLS_DEMAND, False)
    ldap_obj.set_option(ldap.OPT_DEBUG_LEVEL, 255)
    _logger.info("BIND_CN = %s" % ldap_config.get('_BIND_CN'))
    ldap_obj.bind_s(ldap_config.get('_BIND_CN'), ldap_config.get('_LDAP_PW'), ldap.AUTH_SIMPLE)
    return ldap_obj



def server_dn():

    return ldap_config.get('LDAP_DN')
