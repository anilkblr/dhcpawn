# cob: type=tasks
import json
import logbook
import ldap
import os
# from celery.contrib import rdb
from cob import task, db
from cob.project import get_project
from .models import Host, Group, Req, db, Dtask, IP
from .help_functions import *
from celery.exceptions import WorkerLostError, TimeLimitExceeded
from ldap import LDAPError, TIMEOUT, ALREADY_EXISTS, LOCAL_ERROR, DECODING_ERROR, NO_SUCH_OBJECT, SERVER_DOWN
from sqlalchemy.exc import IntegrityError

__all__ = [ 'task_single_input_registration','task_single_input_deletion', 'task_update_drequest', 'task_send_postreply']
if get_project().config.get('sync_config'):
    sync_every = get_project().config['sync_config']['group_sync_every']
    stat_every = get_project().config['sync_config']['sync_stat_every']
    sync_delete_ldap_entries = get_project().config['sync_config'].get('sync_delete_ldap_entries', os.getenv('_DHCPAWN_SYNC_DELETE_LDAP_ENTRIES', False))
else:
    sync_every = 600
    stat_every = 300
    sync_delete_ldap_entries = False

_logger = logbook.Logger(__name__)

@task(every=stat_every, use_app_context=True)
def task_get_sync_stat():
    # get sync stat for all groups

    return Group.get_sync_stat_for_all_groups()
    # stat = dict()
    # for gr in Group.query.all():
    #     try:
    #         stat.update(gr.get_sync_stat())
    #     except DhcpawnError:
    #         pass
    # groups = {}
    # returned = {'synced':{}, 'not synced':{}}
    # for g in Group.query.all():
    #     try:
    #         groups.update(g.get_sync_stat())
    #     except NO_SUCH_OBJECT as e:
    #         _logger.info(f"Not calculating diffs per group {g}")
    #         groups.update({g.name: {'info': f"Looks like this group is not in LDAP but can be found in DB ({e.__str__()})",
    #                                 'group is synced': False}})
    #         continue

    # for g in groups:
    #     if groups[g]['group is synced']:
    #         returned['synced'].update({g:groups[g]})
    #     else:
    #         returned['not synced'].update({g:groups[g]})
    # return returned

    # return stat

@task(every=sync_every, use_app_context=True)
def task_sync():
    # run sync on all groups
    return Group.sync_all_groups()
    # stat = dict()
    # post_sync = dict([('groups', {})])

    # for gr in Group.query.all():
    #     try:
    #         tmpd, host_stat_dict = gr.group_sync()
    #         stat.update(tmpd)
    #         if host_stat_dict:
    #             post_sync['groups'].update(host_stat_dict)
    #     except DhcpawnError:
    #         pass

    # if post_sync['groups']:
    #     return {'pre sync': {k:v for k,v in stat.items() if not v['group is synced']},
    #             'post sync': {k:v for k,v in post_sync.items() if v} }
    # else:
    #     return stat

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

# @task(bind=True)
# def task_host_ldap_modify(self,hid, dtask_id, **kwargs):
#     ''' modify will run ldap delete and ldap add '''
#     current_tid = self.request.id # task_id of the task we are in
#     host = Host.query.get(hid)
#     dtask = Dtask.query.get(dtask_id)
#     _logger.debug("inside modify task")
#     try:
#         host.ldap_delete()
#     except DhcpawnError as e:
#         _logger.error(e.__str__())
#         dtask.update(
#             status='failed',
#             err_str= 'Ldap modify (delete part) failed (%s)' % e.__str__(),
#             desc= 'ldap modify host %s' % host.name,
#             celery_task_id=current_tid )
#         # release the new ip if we allocated new one
#         # and only in cases where the value is not 'clear' which means
#         # this modify will just delete an ip after disconnecting it from the host
#         if kwargs.get('new_address_id') and not kwargs.get('new_address_id') == 'clear':
#             db.session.delete(IP.query.get(kwargs.get('new_address_id')))

#     else:
#         _logger.debug("Old host was removed from LDAP")
#         if kwargs.get('new_group_id'):
#             host.group_id = kwargs.get('new_group_id')
#         next_ip = kwargs.get('new_address_id')
#         if next_ip:
#             prev_ip = host.ip
#             if next_ip == 'clear':
#                 host.ip = None
#             else:
#                 host.ip = IP.query.get(kwargs.get('new_address_id'))
#             _logger.info("deleteing old ip %s" % prev_ip.address)
#             db.session.delete(prev_ip)
#         db.session.add(host)
#         try:
#             host.ldap_add()
#         except DhcpawnError as e:
#             _logger.error(e.__str__())
#             dtask.update(
#                 status='failed',
#                 err_str= 'Ldap modify (add part) failed (%s)' % e.__str__()[:245],
#                 desc= 'ldap modify host %s' % host.name,
#                 celery_task_id=current_tid )
#         else:
#             db.session.commit()
#             dtask.update(
#                 status='succeeded',
#                 desc= 'ldap modify host for %s and DB updated' % host.name,
#                 celery_task_id=current_tid )
#         # update host db instance
#         # ldap add new host
#         # commit new host
#     finally:
#         dreq = Req.query.get(dtask.dreq_id)
#         dreq.refresh_status()

#     return "%s - %s" % (dtask.desc ,dtask.status)

# @task(bind=True, use_app_context=True, reject_on_worker_lost=True,
#       autoretry_for=(ldap.TIMEOUT,ldap.SERVER_DOWN, DhcpawnError), retry_kwargs={'max_retries': 3}, default_retry_delay=120)
# @task(bind=True, use_app_context=True, time_limit=60,
      # reject_on_worker_lost=True, autoretry_for=(WorkerLostError,DhcpawnError, TimeLimitExceeded), acks_late=True )
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
        self.retry(countdown=5, exc=e, max_retries=10)

@task(bind=True, use_app_context=True)
def task_single_input_registration(self, *args, **kwargs):
    kwargs.update({'celery_task_id':self.request.id})
    try:
        Host.single_host_register_track(*args, **kwargs)
    except (ValidationError, IntegrityError, LDAPError):
        pass

@task(bind=True, use_app_context=True)
def task_single_input_deletion(self, *args, **kwargs):
    kwargs.update({'celery_task_id':self.request.id})
    try:
        Host.single_host_delete_track(*args, **kwargs)
    except (ValidationError, IntegrityError, LDAPError, ConflictingParamsError):
        pass

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
