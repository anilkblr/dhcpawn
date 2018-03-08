# cob: type=blueprint mountpoint=/rest
import logbook
import json

from flask import Blueprint, jsonify, request
from cob import db

from .models import Host, Subnet, IP, Dtask, Group, Pool, CalculatedRange, DhcpRange
from . import methodviews as mv
from .help_functions import get_by_field, extract_skeleton

_logger = logbook.Logger(__name__)
api = Blueprint('rest', __name__)


api.add_url_rule('/duplicates/', view_func=mv.DuplicateListAPI.as_view('dhcpawn_duplicate_list_api'), methods=['GET'])
api.add_url_rule('/duplicates/<param>', view_func=mv.DuplicateAPI.as_view('dhcpawn_duplicate_api'), methods=['GET','POST','DELETE'])

api.add_url_rule('/requests/', view_func=mv.DRequestListAPI.as_view('dhcpawn_request_list_api'), methods=['GET'])
api.add_url_rule('/requests/<param>', view_func=mv.DRequestAPI.as_view('dhcpawn_request_api'), methods=['GET'])

api.add_url_rule('/dtasks/', view_func=mv.DtaskListAPI.as_view('dhcpawn_dtask_list_api'), methods=['GET'])
api.add_url_rule('/dtasks/<param>', view_func=mv.DtaskAPI.as_view('dhcpawn_dtask_api'), methods=['GET'])

api.add_url_rule('/hosts/', view_func=mv.HostListAPI.as_view('host_list_api'), methods=['GET', 'POST'])

api.add_url_rule('/multiple/', view_func=mv.MultipleAction.as_view('multiple_action'), methods=['POST', 'DELETE'])

api.add_url_rule('/hosts/<param>', view_func=mv.HostAPI.as_view('host_api'), methods=['GET', 'PUT', 'DELETE'])

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

api.add_url_rule('/sync/', view_func=mv.Sync.as_view('sync'), methods=['GET', 'POST'])
api.add_url_rule('/sync/group/<group_name>', view_func=mv.Sync.as_view('sync_per_group'), methods=['GET', 'POST'])

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
    # deploy skeleton
    data = request.get_json(force=True)
    skeleton = extract_skeleton()
    deploy_groups(skeleton)
    deploy_subnets(skeleton)
    deploy_pools(skeleton)
    deploy_calcranges(skeleton)
    deploy_dhcpranges(skeleton)

    # deploy hosts info per group
    if data['hosts'] == 'True':
        for gr in Group.query.all():
            gr.deploy()

    return ("Finished Deployment Stage")

@api.route('/get_sync_stat/')
def gss():
    groups = {}
    for g in Group.query.all():
        groups.update(g.get_sync_stat())

    return jsonify(groups)

###
def deploy_groups(skeleton):
    _logger.info("Deploying Groups to DB")
    for gr in skeleton['groups']:
        group = Group(name=gr, options=json.dumps({}), deployed=True)
        db.session.add(group)
    db.session.commit()

def deploy_subnets(skeleton):
    _logger.info("Deploying Subnets to DB")
    for sb in skeleton['subnets']:
        subnet = Subnet(name=sb,
                        netmask=skeleton['subnets'][sb].get('netmask'),
                        options=json.dumps(skeleton['subnets'][sb].get('options',{})),
                        deployed=True)
        db.session.add(subnet)
    db.session.commit()

def deploy_pools(skeleton):
    _logger.info("Deploying Pools to DB")
    for pl in skeleton['pools']:
        pool = Pool(name=pl,
                    subnet_id=Subnet.query.filter_by(name=skeleton['pools'][pl].get('subnet_name')).first().id,
                                                     options=json.dumps(skeleton['pools'][pl].get('options', {})),
                                                     deployed=True)
        db.session.add(pool)
    db.session.commit()

def deploy_calcranges(skeleton):
    _logger.info("Deploying Calcranges to DB")
    for sb in skeleton['calcranges']:
        for cr in skeleton['calcranges'][sb]:
            calcrange = CalculatedRange(
                min=cr.get('min'),
                max=cr.get('max'),
                subnet_id=Subnet.query.filter_by(name=sb).first().id
            )
            db.session.add(calcrange)
    db.session.commit()

def deploy_dhcpranges(skeleton):
    _logger.info("Deploying Dhcpranges to DB")
    for pl in skeleton['dhcpranges']:
        dhcprange = DhcpRange(
            min=skeleton['dhcpranges'][pl].get('min'),
            max=skeleton['dhcpranges'][pl].get('max'),
            pool_id=Pool.query.filter_by(name=pl).first().id,
            deployed=True
            )
        db.session.add(dhcprange)
    db.session.commit()
