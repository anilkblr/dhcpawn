# cob: type=blueprint mountpoint=/rest
import logbook

from ipaddress import IPv4Address, AddressValueError
from werkzeug.exceptions import NotFound
from flask import Blueprint, jsonify, abort, request
from cob import db

from .models import Host, Subnet, IP, Dtask
from . import methodviews as mv
from .help_functions import get_by_id, get_by_field

_logger = logbook.Logger(__name__)

api = Blueprint('rest', __name__)


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




@api.route('/testme/', methods=['GET'])
def testme():
    Subnet.validate_by_name('Data1')

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
        # return jsonify("delete %s" %  get_by_field_or_404(Host, 'name', param).id)
        host_api.delete(get_by_field(Host, 'name', param).id)
        # return redirect(url_for('rest.host_api', host_id=get_by_field_or_404(Host, 'name', param).id))
    elif get_by_field(Host, 'mac', param):
        host_api.delete(get_by_field(Host, 'mac', param).id)
        # return redirect(url_for('rest.host_api', host_id=get_by_field_or_404(Host, 'mac', param).id))
        # return jsonify("delete %s" %  get_by_field_or_404(Host, 'mac', param).id)
    else:
        return jsonify({'result':'error'})

@api.route('/dtasks/cleandb/')
def clean_old_dtasks():
    for dt in Dtask.query.all():
        db.session.delete(dt)
    db.session.commit()
    return jsonify("Removed all dtasks from DB")

@api.route('/ips/delete_single_ip/', methods=['DELETE'])
def delete_ip():
    """ methods removes ip record from DB and updates the host in ldap so that it wont be using
    this ip anymore. the request's data should include the ip string and not an ip_id or something like that.
    so the syntax should simply be: {"ip":"10.10.10.10"}
    """
    _logger.debug("delete ip")
    data = request.get_json(force=True)
    ip_string = data.get("ip")
    if not ip_string:
        abort(400, "Missing 'ip' key in data dictionary")
    try:
        ipobj = IPv4Address(ip_string)
    except AddressValueError as err:
        abort(400, "Encountered a problem with ip address string (%s)" % err)
    try:
        ip = get_by_field(IP, "address", ipobj)
    except NotFound as e:
        abort(404, "IP address %s was not found in DB ( %s )" % (ip_string, e.description))
    # so at this stage we are sure the ip is in DB and we can remove it
    # first we need to update the related host  (in DB and LDAP) and then remove the IP)
    try:
        host = get_by_id(Host, ip.host_id)
    except NotFound as e:
        abort(404, "IP to delete was found in DB but for some reason we cant find the host connected to it ( %s )"
              % e.description)
    ip.ldap_delete()
    db.session.delete(ip)
    db.session.commit()

    return jsonify("IP %s removed and host %s was updated" % (ip_string, host.name))
