# cob: type=tasks
import json
import logbook
import ldap
import os
# from celery.contrib import rdb
from cob import task, db
from cob.project import get_project
from .models import Host, Group, Req, db, Dtask
from .help_functions import DhcpawnError, ValidationError, ConflictingParamsError
from ldap import LDAPError
from sqlalchemy.exc import IntegrityError

__all__ = [ 'task_single_input_registration',
            'task_single_input_deletion',
            'task_update_drequest',
            'task_send_postreply']

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

@task(every=sync_every, use_app_context=True)
def task_sync():
    # run sync on all groups
    return Group.sync_all_groups()

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
        Host.single_host_register_track(**kwargs)
    except (ValidationError, IntegrityError, LDAPError):
        pass

@task(bind=True, use_app_context=True)
def task_single_input_deletion(self, *args, **kwargs):
    kwargs.update({'celery_task_id':self.request.id})
    try:
        Host.single_host_delete_track(**kwargs)
    except (ValidationError, IntegrityError, LDAPError, ConflictingParamsError):
        pass
