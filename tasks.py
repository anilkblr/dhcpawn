# cob: type=tasks
import json
import logbook
import ldap
import os
import sys
# from celery.contrib import rdb
from cob import task, db
from cob.project import get_project
from .models import Host, Group, Req, db, Dtask, IP, deploy_hosts, deploy_skeleton, LDAPModel, Duplicate, User, help_func_daily_sanity
from .models import Sync as NewSyncModel
from .help_functions import *
from celery import chain
from celery.exceptions import WorkerLostError, TimeLimitExceeded
from celery.schedules import crontab
from ldap import LDAPError, TIMEOUT, ALREADY_EXISTS, LOCAL_ERROR, DECODING_ERROR, NO_SUCH_OBJECT, SERVER_DOWN
from sqlalchemy.exc import IntegrityError
from sqlalchemy import desc
from raven import Client
from raven.contrib.celery import register_signal, register_logger_signal
import logging

config = get_project().config

_logger = logbook.Logger(__name__)
# _logger = logbook.StreamHandler(sys.stdout, bubble=True).push_application()

# enable Sentry in celery workers
# taken from https://docs.sentry.io/clients/python/integrations/celery/
if not config.get('DEBUG'):
    _logger.info("Activating Sentry")
    client = Client(config.get('SENTRY_DSN'))
    register_logger_signal(client)
    register_logger_signal(client, loglevel=logging.INFO)
    register_signal(client)
    register_signal(client, ignore_expected=True)
    if os.getenv('HOSTNAME'):
        client.name = os.getenv('HOSTNAME')
    else:
        client.name = 'dhcpawn-unset-server'


__all__ = [ 'task_single_input_registration','task_single_input_deletion', 'task_update_drequest', 'task_send_postreply', 'task_deploy', 'task_new_sync', 'task_daily_sanity']

sync_config = config.get('sync_config')
sync_every = sync_config.get('every')
sync_max_records_to_keep = sync_config['max_records_to_keep']
sync_delete_ldap_entries = sync_config.get('sync_delete_ldap_entries', False)
sync_copy_ldap_entries_to_db = sync_config.get('sync_copy_ldap_entries_to_db', True)

ldap_sanity = config.get('ldap_sanity')
ldap_sanity_every = ldap_sanity.get('every')
daily_sanity = config.get('daily_sanity')

@task(bind=True, every=sync_every, use_app_context=True)
def task_new_sync(self, **kwargs):

    s = NewSyncModel()
    _logger.debug(kwargs.get('sender','dhcpawn task'))
    drequest_id = s.run_new_sync(**{'sender': kwargs.get('sender','dhcpawn task')})
    NewSyncModel.purge(sync_max_records_to_keep)

    return f"Sync request: {s.id} finished. Drequest id: {drequest_id}. Celery task id: {self.request.id}"

@task(bind=True, every=ldap_sanity_every, use_app_context=True)
def task_run_ldap_sanity(self):
    drequest_id, _ = LDAPModel.run_ldap_sanity(**{'sender':'Celery periodic task'})
    return f"Ldap sanity request finished. Drequest id: {drequest_id}. Celery task id: {self.request.id}"
@task(bind=True, every=crontab(hour=daily_sanity['hour'], minute=daily_sanity['minute'], day_of_week=daily_sanity['day_of_week']), use_app_context=True)
def task_daily_sanity(self):

    res = help_func_daily_sanity()
    return res
    # _logger.debug('Task: Daily sanity')
    # self.drequest = Req()
    # # run sync
    # s = NewSyncModel()
    # s.run_new_sync(**{'dreq': self.drequest, 'sender':'dhcpawn task'})
    # last_sync = NewSyncModel.query.order_by(desc('id')).all()[0]
    # # run ldap sanity
    # _, ldap_issues = LDAPModel.run_ldap_sanity(**{'dreq':self.drequest, 'sender':'manual rest for testing'})
    # # send email with results
    # email_daily_sanity(**{'emails':[user.email for user in User.query.all()],
    #                       'ldap_issues':ldap_issues,
    #                       'last_sync':last_sync})

@task(bind=True, use_app_context=True)
def task_update_drequest(self, *args, **kwargs):
    req = Req.query.get(kwargs.get('dreq_id'))
    req.refresh_status()

@task(bind=True, use_app_context=True)
def task_send_postreply(self, *args, **kwargs):
    _logger.debug(f"Task: send postreply {self}")
    req = Req.query.get(kwargs.get('dreq_id'))
    try:
        req.postreply()
    except DhcpawnError as e:
        _logger.debug("Trying postreply again")
        self.retry(countdown=15, exc=e, max_retries=10)

@task(bind=True, use_app_context=True)
def task_single_input_registration(self, *args, **kwargs):
    kwargs.update({'celery_task_id':self.request.id})
    try:
        Host.single_host_register_track(*args, **kwargs)
    except (ValidationError, IntegrityError, LDAPError, IPAlreadyExists) as e:
        _logger.error(f"Failed single register track {e.__str__()}")

@task(bind=True, use_app_context=True)
def task_single_input_deletion(self, *args, **kwargs):
    kwargs.update({'celery_task_id':self.request.id})
    try:
        Host.single_host_delete_track(*args, **kwargs)
    except (ValidationError, IntegrityError, LDAPError, ConflictingParamsError, IPAlreadyExists) as e:
        _logger.error(f"Failed single delete track {e.__str__()}")

@task(bind=True, use_app_context=True)
def task_deploy(self, include_hosts):
    try:
        deploy_skeleton()
    except ldap.NO_SUCH_OBJECT as e:
        _logger.debug(f"Failed skeleton deployment {e.__str__()}")
        raise
    try:
        if include_hosts:
            deploy_hosts()
    except ldap.NO_SUCH_OBJECT as e:
        _logger.debug(f"Failed hosts deployment {e.__str__()}")
        raise

    _logger.info("Finished Deployment Stage")
