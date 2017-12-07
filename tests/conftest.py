from .. import ldap_utils
import os
import pytest

@pytest.fixture
def ldap():
    os.environ['LDAP_PRODUCTION_SERVER'] = 'False'
    ldap_init()
