# cob: type=tasks
import json
import logbook
import ldap
import os
# from celery.contrib import rdb
from cob import task, db
from cob.project import get_project
from .models import Host, Group, Req, db, Dtask, IP, deploy_hosts, deploy_skeleton
from .help_functions import *
from celery import chain
from celery.exceptions import WorkerLostError, TimeLimitExceeded
from ldap import LDAPError, TIMEOUT, ALREADY_EXISTS, LOCAL_ERROR, DECODING_ERROR, NO_SUCH_OBJECT, SERVER_DOWN
from sqlalchemy.exc import IntegrityError
from raven import Client
from raven.contrib.celery import register_signal, register_logger_signal
import logging

dhcpawn_project = get_project()

# enable Sentry in celery workers
# taken from https://docs.sentry.io/clients/python/integrations/celery/
client = Client(dhcpawn_project.config['sentry_config'].get('SENTRY_DSN'))
register_logger_signal(client)
register_logger_signal(client, loglevel=logging.INFO)
register_signal(client)
register_signal(client, ignore_expected=True)


__all__ = [ 'task_single_input_registration','task_single_input_deletion', 'task_update_drequest', 'task_send_postreply', 'task_deploy']
if get_project().config.get('sync_config'):
    sync_every = dhcpawn_project.config['sync_config']['group_sync_every']
    stat_every = dhcpawn_project.config['sync_config']['sync_stat_every']
    sync_delete_ldap_entries = dhcpawn_project.config['sync_config'].get('sync_delete_ldap_entries', os.getenv('_DHCPAWN_SYNC_DELETE_LDAP_ENTRIES', False))
    sync_copy_ldap_entries_to_db = dhcpawn_project.config['sync_config'].get('sync_copy_ldap_entries_to_db', os.getenv('_DHCPAWN_SYNC_COPY_LDAP_ENTRIES_TO_DB', True))
else:
    sync_every = 600
    stat_every = 300
    sync_delete_ldap_entries = False
    sync_copy_ldap_entries_to_db = True

_logger = logbook.Logger(__name__)

# @task(every=stat_every, use_app_context=True)
def task_get_sync_stat():
    # get sync stat for all groups
    return Group.get_sync_stat_for_all_groups()

@task(bind=True, use_app_context=True)
def task_sync_per_group(self, *args, **kwargs):
    gr_name = kwargs.get('gr_name')
    gr = Group.validate_by_name(gr_name)
    _logger.debug(f"Start syncing group {gr}")
    try:
        kwargs.update({'sync_delete_ldap_entries':sync_delete_ldap_entries})
        kwargs.update({'sync_copy_ldap_entries_to_db':sync_copy_ldap_entries_to_db})
        tmpd, host_stat_dict = gr.group_sync(**kwargs)
        return tmpd

    except (LDAPError, DhcpawnError) as e:
            _logger.error(f"failed group {gr} sync {e.__str__()}")
    # else:
    #     if host_stat_dict:
    #         return host_stat_dict
    #     else:
    #         return tmpd

@task(bind=True, every=sync_every, use_app_context=True)
def task_sync_new(self):

    if not Group.query.all():
        # probably need to deploy skeleton
        _logger.debug("Detected empty DB - no skeleton - populating from LDAP to DB.")
        deploy_skeleton()
        return jsonify("Synced LDAP Skeleton to DB. next time will update hosts per group.")

    sync_tasks_group = []
    for gr in Group.query.all():

        sync_tasks_group.append(task_sync_per_group.si(**{'gr_name': gr.name}))

    sync_chain = chain(sync_tasks_group)
    sync_chain.apply_async()

@task(bind=True)
def task_get_group_sync_stat(self, group_name, dtask_id):
    current_tid = self.request.id
    dtask = Dtask.query.get(dtask_id)

    gr = Group.validate_by_name(group_name)

    try:
        stat = gr.get_sync_stat()
    except ldap.SERVER_DOWN:
        dtask.update(
            status='failed',
            err_str='Group (%s) get sync stat failed due to LDAP server down issue' % gr.name,
            desc='Get sync stat for group %s' % gr.name,
            celery_task_id=current_tid
        )
    else:
        dtask.update(
            status= 'succeeded',
            desc= 'Get sync stat for group %s' % gr.name,
            celery_task_id= current_tid
        )

        dreq = Req.query.get(dtask.dreq_id)
        dreq.drequest_result = json.dumps(stat)
        db.session.add(dreq)
        db.session.commit()
        dreq.refresh_status()

    return "%s - %s" % (dtask.desc, dtask.status)

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

# @task(bind=True, use_app_context=True)
# # def task_host_ldap_add(self, hid, dtask_id, *args):
# def task_host_ldap_add(self, *args, **kwargs):
#     ''' after creating new host in db
#     run async task to udpate LDAP
#     hid = host id
#     dreq_id = the related dhcpawn request id
#     '''
#     current_tid = self.request.id # task_id of the task we are in
#     hid = kwargs.get('hid')
#     dtask_id = kwargs.get('dtask_id')
#     try:
#         return Host.drequest_ldap_add(hid, dtask_id, current_tid)
#     except LDAPError as e:
#         _logger.debug(e.__str__())
#         raise self.retry(countdown=10, exc=e, max_retries=1)
#     else:
#         _logger.warning("In task after retry {current_id}")

# @task(bind=True, use_app_context=True)
# # def task_host_ldap_delete(self, hid, dtask_id):
# def task_host_ldap_delete(self, *args, **kwargs):
#     '''
#     just delete LDAP entry for a specific host
#     hid = host id
#     '''
#     current_tid = self.request.id # task_id from this task instance
#     hid = kwargs.get('hid')
#     dtask_id = kwargs.get('dtask_id')
#     try:
#         return Host.drequest_ldap_delete(hid, dtask_id, current_tid)
#     except LDAPError as e:
#         _logger.debug(e.__str__())
#         raise self.retry(countdown=10, exc=e, max_retries=1)
#     else:
#         _logger.warning("In task after retry {current_id}")

    # host = Host.query.get(hid)
    # dtask = Dtask.query.get(dtask_id)
    # err_str = ''
    # try:
    #     host.ldap_delete()
    # except DhcpawnError as e:
    #     err_str = f"Ldap delete for host {host.name} with host_id {hid} failed due to: {e.__str__()}"
    #     _logger.error(err_str)
    #     dtask.update(
    #         status='failed',
    #         err_str= err_str,
    #         desc='ldap delete host %s' % host.name,
    #         celery_task_id=current_tid
    #     )
    # else:
    #     _logger.debug('Host (%s) was also be deleted from DB', host.name)
    #     if host.ip:
    #         db.session.delete(host.ip)
    #     db.session.delete(host)
    #     db.session.commit()

    #     dtask.update(
    #         status='succeeded',
    #         desc='DB delete host %s' % host.name,
    #         celery_task_id=current_tid
    #     )
    #     dreq = Req.query.get(dtask.dreq_id)
    #     dreq.refresh_status()

    # return "%s - %s - %s" % (dtask.desc, dtask.status, err_str)
