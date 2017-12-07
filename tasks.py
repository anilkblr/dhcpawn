# cob: type=tasks
from time import sleep
from cob import task, db
from flask import jsonify, current_app
from cob.app import build_app
from cob.celery.app import celery_app
from cob.project import get_project
from celery import group
from .help_functions import DhcpawnError
from .models import Host, Group, Subnet, Req, db, Dtask, IP
import json
import logbook
import ldap
from celery.contrib import rdb

_logger = logbook.Logger(__name__)
@task()
def task_get_sync_stat():
    from . import methodviews as mv
    # with build_app().app_context():
    sync = mv.Sync()
    return sync.get()


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
    except Exception as e:
        dtask.update(
            status='failed',
            err_str='Group (%s) get sync stat failed unexpectedly (%s)' % (gr.name,e.__str__()),
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
    ''' modify will be ldap delete and ldap add '''
    current_tid = self.request.id # task_id of the task we are in
    host = Host.query.get(hid)
    dtask = Dtask.query.get(dtask_id)
    _logger.debug("inside modify task")
    try:
        host.ldap_delete()
    except Exception as e:
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
        _logger.info("3.2")
        db.session.add(host)
        _logger.info("3.3")
        try:
            _logger.info("inside modify task 4")
            host.ldap_add()
        except Exception as e:
            _logger.info("inside modify task 5")
            _logger.error(e.args[0])
            dtask.update(
                status='failed',
                err_str= 'Ldap modify (add part) failed (%s)' % e.args[0][:245],
                desc= 'ldap modify host %s' % host.name,
                celery_task_id=current_tid )
        else:
            _logger.info("inside modify task 6")

            db.session.commit()
            dtask.update(
                status='succeeded',
                desc= 'ldap modify host for %s and DB updated' % host.name,
                celery_task_id=current_tid )
        # update host db instance
        # ldap add new host
        # commit new host
    finally:
        _logger.info("inside modify task 7")
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
        # rdb.set_trace()
        host.ldap_add()
    except ldap.ALREADY_EXISTS:
        err_str = 'Ldap add failed since there is already a host with this name (%s) in LDAP' % host.name,
        _logger.error("LDAP 'Already Exists' exception (%s)" % hid)
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
        host.delete()
    except RuntimeError as e:
        if 'context' in e.__str__():
            err_str = 'Ldap add failed due to application context issue'
        else:
            err_str = 'Ldap add failed with type %s (%s)' % (type(e).__name__, e.__str__())
        _logger.error(e.__str__() + " %s " % hid)
        # try:
        #     host.delete()
        # except:
        #     pass
        dtask.update(
            status='failed',
            err_str= err_str,
            desc= 'ldap add host %s' % host.name,
            celery_task_id=current_tid
            )
    except ldap.TIMEOUT as e:
        err_str = e.__str__() + "timeout !!"
        _logger.error(err_str + " %s " % hid)
        dtask.update(
            status='failed',
            err_str= 'Ldap add failed on timeout',
            desc= 'ldap add host %s' % host.name,
            celery_task_id=current_tid
            )
    except ldap.SERVER_DOWN as e:
        err_str = e.__str__()
        _logger.error("It looks like LDAP server is down (%s)" % hid)
        dtask.update(
            status='failed',
            err_str= 'LDAP server is down (%s)' % err_str,
            desc= 'ldap add host %s' % host.name,
            celery_task_id=current_tid
            )
    except Exception as e:
        err_str = e.__str__()
        _logger.error(e.__str__() + " Exception Type: " + type(e).__name__ + " %s " % hid)
        # try:
            # host.delete()
        # except:
            # pass
        dtask.update(
            status='failed',
            err_str= 'Ldap add failed with type %s (%s)' % (type(e).__name__, e.__str__()),
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
    _logger.info("inside task_host_ldap_delete")
    current_tid = self.request.id # task_id from this task instance
    host = Host.query.get(hid)
    dtask = Dtask.query.get(dtask_id)
    err_str = ''
    try:
        host.ldap_delete()
    except Exception as e:
        err_str = 'Ldap delete failed (%s)' % e.__str__()
        _logger.error(err_str)
        dtask.update(
            status='failed',
            err_str= err_str,
            desc='ldap delete host %s' % host.name,
            celery_task_id=current_tid
        )
    else:
        try:
            if host.ip:
                db.session.delete(host.ip)
            db.session.delete(host)
            db.session.commit()
        except Exception as e:
            err_str = 'DB delete failed (%s)' % e.__str__()
            dtask.update(
            status='failed',
            err_str= err_str,
            desc='DB delete host %s' % host.name,
            celery_task_id=current_tid
        )
        else:
            dtask.update(
            status='succeeded',
            desc='DB delete host %s' % host.name,
            celery_task_id=current_tid
        )
    finally:
        dreq = Req.query.get(dtask.dreq_id)
        dreq.refresh_status()

    return "%s - %s - %s" % (dtask.desc, dtask.status, err_str)
