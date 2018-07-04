# cob: type=blueprint mountpoint=/rest
import logbook
import json
from ldap import LDAPError, NO_SUCH_OBJECT

from flask import Blueprint, jsonify, request, current_app
from cob import db

from .models import Host, Subnet, IP, Dtask, Group, Pool, CalculatedRange, DhcpRange, Sync, Req, LDAPModel, help_func_daily_sanity
from . import methodviews as mv
from .help_functions import get_by_field, extract_skeleton
from .tasks import *

_logger = logbook.Logger(__name__)
api = Blueprint('rest', __name__)


api.add_url_rule('/duplicates/', view_func=mv.DuplicateListAPI.as_view('dhcpawn_duplicate_list_api'), methods=['GET'])
api.add_url_rule('/duplicates/<param>', view_func=mv.DuplicateAPI.as_view('dhcpawn_duplicate_api'), methods=['GET'])

api.add_url_rule('/ldapsanity', view_func=mv.LdapSanityAPI.as_view('dhcpawn_ldapsanity_api'), methods=['GET','POST'])

api.add_url_rule('/requests/', view_func=mv.DRequestListAPI.as_view('dhcpawn_request_list_api'), methods=['GET'])
api.add_url_rule('/requests/<param>', view_func=mv.DRequestAPI.as_view('dhcpawn_request_api'), methods=['GET'])

api.add_url_rule('/dtasks/', view_func=mv.DtaskListAPI.as_view('dhcpawn_dtask_list_api'), methods=['GET'])
api.add_url_rule('/dtasks/<param>', view_func=mv.DtaskAPI.as_view('dhcpawn_dtask_api'), methods=['GET'])

api.add_url_rule('/hosts/', view_func=mv.HostListAPI.as_view('host_list_api'), methods=['GET', 'POST'])

api.add_url_rule('/multiple/', view_func=mv.MultipleAction.as_view('multiple_action'), methods=['POST', 'DELETE'])

api.add_url_rule('/hosts/<param>', view_func=mv.HostAPI.as_view('host_api'), methods=['GET', 'PUT', 'DELETE'])

api.add_url_rule('/hosts/re/<hostname>', view_func=mv.HostReAPI.as_view('host_regex_api'), methods=['GET'])

api.add_url_rule('/groups/', view_func=mv.GroupListAPI.as_view('group_list_api'), methods=['GET','POST'])
api.add_url_rule('/groups/<param>', view_func=mv.GroupAPI.as_view('group_api'), methods=['GET','PUT','DELETE'])

api.add_url_rule('/subnets/', view_func=mv.SubnetListAPI.as_view('subnet_list_api'), methods=['GET','POST'])
api.add_url_rule('/subnets/<param>', view_func=mv.SubnetAPI.as_view('subnet_api'), methods=['GET','PUT','DELETE'])

api.add_url_rule('/ips/', view_func=mv.IPListAPI.as_view('ip_list_api'), methods=['GET','POST'])
api.add_url_rule('/ips/<param>', view_func=mv.IPAPI.as_view('ip_api'), methods=['GET','PUT','DELETE'])

api.add_url_rule('/pools/', view_func=mv.PoolListAPI.as_view('pool_list_api'), methods=['GET','POST'])
api.add_url_rule('/pools/<param>', view_func=mv.PoolAPI.as_view('pool_api'), methods=['GET','PUT','DELETE'])

api.add_url_rule('/dhcpranges/', view_func=mv.DhcpRangeListAPI.as_view('dhcprange_list_api'), methods=['GET', 'POST'])
api.add_url_rule('/calcranges/', view_func=mv.CalculatedLRangeListAPI.as_view('calcrange_list_api'), methods=['GET', 'POST'])

api.add_url_rule('/newsync', view_func=mv.NewSyncListAPI.as_view('newsync_list_api'), methods=['GET', 'POST'])
api.add_url_rule('/newsync/<param>', view_func=mv.NewSync.as_view('newsync'), methods=['GET'])

api.add_url_rule('/clearhosts/', view_func=mv.HostListAPI.as_view('clear_hosts_from_db'), methods=['DELETE'])
api.add_url_rule('/clearips/', view_func=mv.IPListAPI.as_view('clear_ips_from_db'), methods=['DELETE'])


@api.route('/subnet/get_free_ip/<subnet>', methods=['GET'])
def get_free_ip(subnet):
    return jsonify(Subnet.get_free_ips(subnet))

@api.route('/ips/get_ip_subnet/<address>', methods=['GET'])
def get_ip_subnet(address):
    ''' return ip subnet name (from dhcpComments) if exists '''
    ip = get_by_field(IP, 'address', address)
    return jsonify(ip.calculatedrange.subnet.config())

@api.route('/hosts/get_host_ip/<hostname>', methods=['GET'])
def get_host_ip(hostname):
    '''
    return host ip
    '''
    host = get_by_field(Host, 'name', hostname)
    if host.ip:
        return jsonify(host.ip.config())
    return jsonify({})


@api.route('/hosts/delete/<param>', methods=['DELETE'])
def delete_host_by_param(param):
    """
    param can be name or mac address
    """
    host_api = mv.HostAPI()
    if get_by_field(Host, 'name', param):
        host_api.delete(get_by_field(Host, 'name', param).id)
    elif get_by_field(Host, 'mac', param):
        host_api.delete(get_by_field(Host, 'mac', param).id)
    else:
        return jsonify({'result':'error'})

@api.route('/dtasks/cleandb/')
def clean_old_dtasks():
    for dt in Dtask.query.all():
        db.session.delete(dt)
    db.session.commit()
    return jsonify("Removed all dtasks from DB")

@api.route('/deploy/', methods=['POST'])
def deploy_server():
    '''
    deployment consists two steps:
    1. LDAP skeleton (groups, subnets ...) + calcranges..
    2. The hosts info for each group
    '''
    data = request.get_json(force=True)
    _logger.info("before deploying")
    if data.get('hosts'):
        if (data.get('hosts') == "True" or data.get('hosts') == "true"):
            task_deploy.s(True).apply_async()
        else:
            task_deploy.s(False).apply_async()
    else:
        return jsonify(f"Wrong input data {data}")

    return jsonify("Deployement started")


@api.route('/run_new_sync')
def sync_ldap_db():

    s = Sync()
    ret = s.run_new_sync(**{ 'sender':f'manual syncronous ldap-db sync request'})
    return jsonify(f"Sync task sent: {ret}. sync id {s.id}")

@api.route('/run_ldap_sanity')
def run_ldap_sanity():
    ''' run ldap sanity syncronously '''
    drequest_id = LDAPModel.run_ldap_sanity(**{'sender':'Manual syncronous ldap sanity'})
    return f"Ldap sanity request finished. Drequest id: {drequest_id}."


@api.route('/run_daily_sanity')
def daily_sanity():
    ''' manual dispatch of daily sanity'''
    task_daily_sanity.s().apply_async()
    return jsonify("Daily sanity report is being created and a mail will be sent at the end")

@api.route('/refresh_ldap_connection')
def refresh_ldap_connection():
    from .ldap_utils import ldap_init
    current_app.ldap_obj = ldap_init()

    return jsonify("refreshed")
