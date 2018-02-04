# cob: type=tasks
import json
import logbook
import ldap
import os
# from celery.contrib import rdb
from cob import task, db
from cob.project import get_project
from .models import Host, Group, Req, db, Dtask, IP
from .help_functions import DhcpawnError

if get_project().config.get('sync_config'):
    sync_every = get_project().config['sync_config']['group_sync_every']
    stat_every = get_project().config['sync_config']['sync_stat_every']
    sync_delete_ldap_entries = get_project().config['sync_config'].get('sync_delete_ldap_entries', os.getenv('DHCPAWN_SYNC_DELETE_LDAP_ENTRIES', False))
else:
    sync_every = 600
    stat_every = 300
    sync_delete_ldap_entries = False

_logger = logbook.Logger(__name__)

# @task(every=stat_every, use_app_context=True)
def task_get_sync_stat():
    # get sync stat for all groups
    stat = dict()
    for gr in Group.query.all():
        try:
            stat.update(gr.get_sync_stat())
        except DhcpawnError as e:
            pass

    return stat

# @task(every=sync_every, use_app_context=True)
def task_sync():
    # run sync on all groups
    stat = dict()
    post_sync = dict([('groups', {})])

    for gr in Group.query.all():
        try:
            tmpd, host_stat_dict = gr.group_sync(sync_delete_ldap_entries=sync_delete_ldap_entries)
            stat.update(tmpd)
            if host_stat_dict:
                post_sync['groups'].update(host_stat_dict)
        except DhcpawnError as e:
            pass

    if post_sync['groups']:
            return {'pre sync': {k:v for k,v in stat.items() if not v['group is synced']},
                    'post sync': {k:v for k,v in post_sync.items() if v} }
    else:
        return stat

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

@task(bind=True)
def task_host_ldap_modify(self,hid, dtask_id, **kwargs):
    ''' modify will run ldap delete and ldap add '''
    current_tid = self.request.id # task_id of the task we are in
    host = Host.query.get(hid)
    dtask = Dtask.query.get(dtask_id)
    _logger.debug("inside modify task")
    try:
        host.ldap_delete()
    except DhcpawnError as e:
        _logger.error(e.__str__())
        dtask.update(
            status='failed',
            err_str= 'Ldap modify (delete part) failed (%s)' % e.__str__(),
            desc= 'ldap modify host %s' % host.name,
            celery_task_id=current_tid )
        # release the new ip if we allocated new one
        # and only in cases where the value is not 'clear' which means
        # this modify will just delete an ip after disconnecting it from the host
        if kwargs.get('new_address_id') and not kwargs.get('new_address_id') == 'clear':
            db.session.delete(IP.query.get(kwargs.get('new_address_id')))

    else:
        _logger.debug("Old host was removed from LDAP")
        if kwargs.get('new_group_id'):
            host.group_id = kwargs.get('new_group_id')
        next_ip = kwargs.get('new_address_id')
        if next_ip:
            prev_ip = host.ip
            if next_ip == 'clear':
                host.ip = None
            else:
                host.ip = IP.query.get(kwargs.get('new_address_id'))
            _logger.info("deleteing old ip %s" % prev_ip.address)
            db.session.delete(prev_ip)
        db.session.add(host)
        try:
            host.ldap_add()
        except DhcpawnError as e:
            _logger.error(e.__str__())
            dtask.update(
                status='failed',
                err_str= 'Ldap modify (add part) failed (%s)' % e.__str__()[:245],
                desc= 'ldap modify host %s' % host.name,
                celery_task_id=current_tid )
        else:
            db.session.commit()
            dtask.update(
                status='succeeded',
                desc= 'ldap modify host for %s and DB updated' % host.name,
                celery_task_id=current_tid )
        # update host db instance
        # ldap add new host
        # commit new host
    finally:
        dreq = Req.query.get(dtask.dreq_id)
        dreq.refresh_status()
        return "%s - %s" % (dtask.desc ,dtask.status)

@task(bind=True, use_app_context=True, reject_on_worker_lost=True,
      autoretry_for=(ldap.TIMEOUT,ldap.SERVER_DOWN, ), retry_kwargs={'max_retries': 1}, default_retry_delay=60)
def task_host_ldap_add(self, hid, dtask_id):
    ''' after creating new host in db
    run async task to udpate LDAP
    hid = host id
    dreq_id = the related dhcpawn request id
    '''
    current_tid = self.request.id # task_id of the task we are in
    host = Host.query.get(hid)
    dtask = Dtask.query.get(dtask_id)
    err_str = ''
    try:
        host.ldap_add()
    except DhcpawnError as e:
        err_str = f"Ldap add for host {host.name} with host_id {hid} failed due to: {e.__str__()}"
        _logger.error(err_str)
        try:
            host.delete()
        except:
            pass
        dtask.update(
            status='failed',
            err_str= err_str,
            desc= 'ldap add host %s' % host.name,
            celery_task_id=current_tid
            )
    else:
        dtask.update(
            status= 'succeeded',
            desc= 'ldap add host %s' % host.name,
            celery_task_id= current_tid
        )

    dreq = Req.query.get(dtask.dreq_id)
    dreq.refresh_status()

    return "%s - %s - %s" % (dtask.desc ,dtask.status, err_str)

@task(bind=True, use_app_context=True)
def task_host_ldap_delete(self, hid, dtask_id):
    '''
    just delete LDAP entry for a specific host
    hid = host id
    '''
    current_tid = self.request.id # task_id from this task instance
    host = Host.query.get(hid)
    dtask = Dtask.query.get(dtask_id)
    err_str = ''
    try:
        host.ldap_delete()
    except DhcpawnError as e:
        err_str = f"Ldap delete for host {host.name} with host_id {hid} failed due to: {e.__str__()}"
        _logger.error(err_str)
        dtask.update(
            status='failed',
            err_str= err_str,
            desc='ldap delete host %s' % host.name,
            celery_task_id=current_tid
        )
    else:
        _logger.debug('Host (%s) was also be deleted from DB', host.name)
        if host.ip:
            db.session.delete(host.ip)
        db.session.delete(host)
        db.session.commit()

        dtask.update(
            status='succeeded',
            desc='DB delete host %s' % host.name,
            celery_task_id=current_tid
        )
        dreq = Req.query.get(dtask.dreq_id)
        dreq.refresh_status()

    return "%s - %s - %s" % (dtask.desc, dtask.status, err_str)
