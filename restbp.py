# cob: type=blueprint mountpoint=/rest
import subprocess
import json

from sqlalchemy.exc import IntegrityError,InvalidRequestError, SQLAlchemyError
from ldap import SCOPE_SUBTREE
from ipaddress import IPv4Address, AddressValueError
import logbook
from werkzeug.exceptions import BadRequest, NotFound

from flask import Blueprint, jsonify, abort, request, url_for, current_app, render_template, redirect
from .models import Host, Group, Subnet, IP, Pool, CalculatedRange, Dtask
from .tasks import task_get_sync_stat
from . import methodviews as mv
from .help_functions import subnet_get_calc_ranges, get_by_id, get_by_field, _get_or_none, DhcpawnError, gen_resp_deco

from cob import db, route
from cob.project import get_project

_logger = logbook.Logger(__name__)

api = Blueprint('rest', __name__)


api.add_url_rule('/requests/', view_func=mv.DRequestListAPI.as_view('dhcpawn_request_list_api'), methods=['GET'])
api.add_url_rule('/requests/<param>', view_func=mv.DRequestAPI.as_view('dhcpawn_request_api'), methods=['GET'])

api.add_url_rule('/dtasks/', view_func=mv.DtaskListAPI.as_view('dhcpawn_dtask_list_api'), methods=['GET'])
api.add_url_rule('/dtasks/<param>', view_func=mv.DtaskAPI.as_view('dhcpawn_dtask_api'), methods=['GET'])

api.add_url_rule('/hosts/', view_func=mv.HostListAPI.as_view('host_list_api'), methods=['GET', 'POST'])
# api.add_url_rule('/hosts/byid/<int:host_id>', view_func=mv.HostByIdAPI.as_view('host_by_id_api'), methods=['GET', 'PUT', 'DELETE'])
# api.add_url_rule('/hosts/byname/<hostname>', view_func=mv.HostByNameAPI.as_view('host_by_name_api') , methods=['GET', 'PUT','DELETE'])
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

api.add_url_rule('/getsyncstat/', view_func=mv.Sync.as_view('get_sync_stat_all_api'), methods=['GET'])
api.add_url_rule('/getsyncstat/group/<group_name>', view_func=mv.Sync.as_view('get_sync_per_group_name_api'), methods=['GET'])

api.add_url_rule('/clearhosts/', view_func=mv.HostListAPI.as_view('clear_hosts_from_db'), methods=['DELETE'])
api.add_url_rule('/clearips/', view_func=mv.IPListAPI.as_view('clear_ips_from_db'), methods=['DELETE'])




@api.route('/testme/', methods=['GET'])
def testme():
    Subnet.validate_by_name('Data1')
    # import pudb;pudb.set_trace()

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
    host = get_by_field(Host, 'name', hostname )
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
# @api.route("/")
# def index():
#     search = str(current_app.ldap_obj.search_st('dc=dhcpawn,dc=net', SCOPE_SUBTREE))
#     return render_template("index.html", search=search)




######## Multiple Register #########
# class MultipleAction(object):


#     @api.route('/multiple_test/', methods=['GET'])
#     @gen_resp_deco
#     def tryit():
#         self.result = {}
#         self.msg = 'tryit'



# @api.route('/multiple_register/', methods=['POST'])
# def multiple_register():
#     """
#     can take more then one dhcpHost (i.e host or system) and register it in DB/ldap
#     the record must have hostname, mac and group.
#     the record can have subnet, ip  but if not ,then just create the entry without allocating the ip.
#     {h1: {hostname: , mac: , group: ,subnet:, ip: }, h2: {}, ...}
#     --> incase one of the inputs is wrong ,validation fails and the entire request will fail
#     - no ip is allocated.
#      """

#     _logger.debug("multiple register")
#     data = request.get_json(force=True)
#     deploy = False
#     if 'deploy' in data:
#         deploy = data.get('deploy')
#         del data['deploy']

#     if deploy:
#         # this is the day to day part of the code
#         # validation is needed and all the rest of the flow
#         try:
#             validated_host_dict, remove_ips_on_fail = validate_data(data)
#         except NotFound as e:
#             _logger.error(e.description)
#             return err_json("Not Found - Registration Failed - please use the log for debugging")
#         except BadRequest as e:
#             _logger.error(e.description)
#             return err_json("Bad Request - Registration Failed - please use the log for debugging")

#         # if we got here , all entries got their ips and we can commit to DB and
#         # add to LDAP
#         remove_hosts_on_fail = []
#         for su in validated_host_dict.keys():

#             for hst in validated_host_dict[su].keys():
#                 db.session.add(validated_host_dict[su][hst])
#                 remove_hosts_on_fail.append(validated_host_dict[su][hst])
#                 try:
#                     db.session.commit()
#                 except IntegrityError as e:
#                     _logger.error(e.orig)
#                     db.session.rollback()
#                     clear_ips(remove_ips_on_fail)
#                     clear_hosts(remove_hosts_on_fail)
#                     return err_json("Aborted request")
#                 except Exception as e:
#                     _logger.error("Unexpected exception %s" % e.__str__())
#                 validated_host_dict[su][hst].ldap_add()

#     else:
#         _logger.info("Registring entries only in DB ,no LDAP update")
#         # quick registration mode - simply writing all records to DB.
#         # DB-ldap sync will happen later
#         validated_host_dict, _ = register_in_db_no_validation(data)
#         for su in validated_host_dict:
#             for hst in validated_host_dict[su]:
#                 db.session.add(validated_host_dict[su][hst])

#         try:
#             db.session.commit()
#             _logger.info("Finished quick db registration")
#         except Exception as e:
#             _logger.error("Quick mode - got an unexpected error, please check yml syntax and db duplications")
#             return err_json("Failed quick db registration mode")

#     return err_json("Registration Finished Successfully")


#### help funcs

# def get_subnet_from_ip (ipv4_addr_str):
#     """
#      --> used in restbp

#     the function will first check if the ip is free. if True ,the ip will be allocated and then
#     go over all calculated ranges and check which one contains this ip.
#     if ip doesn't belong to any subnet ,ip will be released from DB and an error returned.
#      otherwise the subnet is returned
#     :param ipv4_addr: a string with the desired ip
#     :return: tuple (subnet, ip DB inst) - subnet or None,None
#     """
#     wanted_ip = IPv4Address(ipv4_addr_str)
#     # ip already allocated ?
#     if IP.query.filter_by(address=wanted_ip).first():
#         abort(404, "IP already allocated")

#     cr_id = None
#     found = False
#     for cr in CalculatedRange.query.all():
#         if found:
#             break
#         if cr.contains(wanted_ip):
#             cr_id = cr.id
#             found = True

#     if cr_id:
#         # allocate this ip so no one else allocates it.
#         # ip = IP(
#         #     address=wanted_ip,
#         #     calcrange_id=cr_id,
#         # )
#         # db.session.add(ip)
#         # db.session.commit()

#         return get_or_404(Subnet, cr.subnet_id)

#     else:
#         abort(404, "Could not calculate subnet from provided ip - please check the ip")
#         # _logger.warning("Could not calculate subnet from provided ip - please check the ip")
#         # return None



# def register_in_db_no_validation(data):
#     """
#     function for registering the first large bulk of records taken
#     from production ldap before starting to work with dhcpawn.
#     assumptions:
#         1. yml file is already "human validated"
#         2. all hosts are "new".
#         3. if a record has an ip ,it also has subnet

#     :param data:
#     :return: validated_host_dict and an empty list (instead of list of ips to remove on failure)
#     """
#     validated_host_dict = dict()
#     validated_host_dict['None'] = dict()
#     for su in Subnet.query.all():
#         validated_host_dict[su] = dict()

#     for h in data:
#         hdata = data.get(h)
#         try:
#             hostname = hdata.get('hostname')
#         except:
#             import pudb;pudb.set_trace()
#         mac = hdata.get('mac')
#         group = get_by_field_or_404(Group, 'name', hdata.get('group'))

#         host = Host(
#             name=hostname,
#             mac=mac,
#             group_id=group.id
#         )

#         if 'subnet' in hdata:
#             subnet = get_by_field_or_404(Subnet, 'name', hdata.get('subnet'))
#             ipStr = hdata.get('ip')
#             ip = alloc_single_ip(subnet, ipStr)
#             host.ip = ip
#         else:
#             subnet = 'None'

#         # if subnet not in validated_host_dict:
#         #     validated_host_dict[subnet] = dict()
#         validated_host_dict[subnet][h] = host

#     return validated_host_dict, []


# def validate_data(data):
#     """
#     a wrapper for the validation function. it will go over all hosts in request and
#     return a dict of validated inputs and subnet distribution for optimization reasons..
#     :param data: dictionary provided by the request
#     :return:
#         validated_host_dict - contains all Host instances created according to the data given to the request
#         subnet_hist - subnet distribution
#     """
#     # subnet_hist = dict()
#     validated_host_dict = dict()
#     remove_hosts_on_fail = []
#     remove_ips_on_fail = []
#     for h in data.keys():
#         hdata = data.get(h)
#         try:
#             host, group, subnet, ip = single_input_validation(hdata)
#             # host:
#             #   can be None for new host
#             #   can be Host inst for existing host
#             # subnet:
#             #   can be None if host doesn't require an ip
#             #   can be a one of our subnets
#             # ip:
#             #   can be None for cases the host doesn't require an ip
#             #   can be "allocate" and then we need to allocate a free ip from subnet
#             #   can be address string given in request and we will try allocating it.
#             new_host = False
#             if not host:
#                 new_host = True
#                 host = Host(name=hdata.get('hostname'),
#                             mac=hdata.get('mac'),
#                             group_id=group.id
#                             )

#             # _logger.debug("Adding host %s to remove list" % host.name)
#             remove_hosts_on_fail.append(host)

#             if subnet:
#                 if ip == 'allocate':
#                     ip = alloc_single_ip(subnet)
#                 elif ip:
#                     ip = alloc_single_ip(subnet, ip)
#                 else:
#                     # if subnet exists ,ip can either be a specific address string
#                     # or "allocate" which means we will allocate a free ip if exists.
#                     # ip = none at this stage can only be if subnet is also
#                     # none meaning host will only have mac and group.
#                     abort(400, "what the fuck ? subnet exists (%s) but ip is none ?" % subnet.name)

#                 # _logger.debug("Adding ip %s to remove list" % ip.address)
#                 remove_ips_on_fail.append(ip)
#                 host.ip = ip

#             elif not new_host:
#                 abort(400, "What the fuck ? Nothing to update, record already exists. %s" % hdata)

#             # building a validated hosts dict of Host instances for later ip allocation
#             # the dict should be divided into different subnets
#             if subnet not in validated_host_dict:
#                 validated_host_dict[subnet] = dict()
#             validated_host_dict[subnet][h] = host

#         except NotFound as e:
#             clear_ips(remove_ips_on_fail)
#             clear_hosts(remove_hosts_on_fail)
#             abort(404, e.description + " %s" % hdata)
#         except BadRequest as e:
#             clear_ips(remove_ips_on_fail)
#             clear_hosts(remove_hosts_on_fail)
#             abort(400, e.description + " %s" % hdata)

#     return validated_host_dict, remove_ips_on_fail


# def single_input_validation(req_data):
#     """
#     validate host, subnet, group ,ip given, exist
#     cases to validate:
#     https://drive.google.com/a/infinidat.com/file/d/0B8Y5tT03h19XN1BfRm5ZSUhlSGc/view?usp=sharing

#     :returns
#     host (string), group (object), subnet (object), ip (string)
#     """
#     if any(key not in req_data for key in ['hostname', 'mac', 'group']):
#         abort(400, "hostname, mac or group missing in this record")
#     # hostname exist ?
#     host_by_hostname = Host.query.filter_by(name=req_data.get("hostname")).first()
#     if host_by_hostname:
#         # a host in db with the given hostname already exists
#         host = host_by_hostname
#         its_mac = host_by_hostname.mac
#         if not its_mac == req_data.get('mac'):
#             # abort(400, "hostname (%s) with a different mac (%s) already in DB"
#             #       % (host_by_hostname.name, its_mac))
#             _logger.debug("Host %s exists, updating its mac to be %s" % (host.name, req_data.get('mac')))
#             host.mac = req_data.get('mac')
#         # else:
#         its_group = get_or_404(Group, host_by_hostname.group_id)
#         if not its_group.name == req_data.get('group'):
#             abort(400, "hostname (%s) with a different group (%s) already in DB"
#                   % (host_by_hostname.name, its_group))
#         group = its_group
#     else:
#         host = None
#         # is there a host with the requested mac ?
#         host_by_mac = Host.query.filter_by(mac=req_data.get("mac")).first()
#         if host_by_mac:
#             abort(400, "A host with this mac (%s) already exists (%s)" % (host_by_mac.name, host_by_mac.mac))
#         else:
#             # validate group exists
#             group = get_by_field_or_404(Group, "name", req_data.get('group'))

#     # at this point "must" keys are validated.
#     # now we have two options:
#     # 1. existing host (new_host = False)
#     # 2. new host ( new_host = True )

#     if 'ip' in req_data:
#         req_ip = req_data.get('ip')
#         if get_by_field_or_404(IP, 'address', IPv4Address(req_ip), 'None'):
#             # meaning the ip in the request is taken
#             if host and host.ip == IPv4Address(req_ip):
#                     # meaning we found a host called as the hostname in request
#                     # and it is already related to this ip. so we do nothing.
#                     pass
#             else:
#                 # any other case, host exists or not ,if requested IP
#                 # is taken and cannot be assinged to any other host.
#                 abort(400, "IP already taken %s" % req_ip)
#         calculated_subnet_inst = get_subnet_from_ip(req_data.get('ip'))
#         if 'subnet' in req_data:
#             # make sure subnet name from request is valid.
#             req_subnet = get_by_field_or_404(Subnet, 'name', req_data.get('subnet'))
#             if not calculated_subnet_inst == req_subnet:
#                 print("Provided ip (%s) is not part of the provided subnet (%s)"
#                       % (req_ip, req_subnet.name))
#                 abort(404, "Provided ip (%s) is not part of the provided subnet (%s)"
#                       % (req_ip, req_subnet.name))

#         subnet = calculated_subnet_inst
#         ip = req_data.get('ip')

#     elif 'subnet' in req_data:
#         subnet = get_by_field_or_404(Subnet, 'name', req_data.get('subnet'))
#         ip = 'allocate'

#     else:
#         # meaning we're going to have a host without ip
#         # just mac and group
#         subnet = None
#         ip = None

#     return host, group, subnet, ip


# def alloc_single_ip(su, addr=None):
#     """
#     go over subnet calculated ranges and find a free ip if addr=None
#     or check if the specific address is free to allocate
#     :param su: subnet in which the ip should be
#     :param addr: if a specific address in needed otherwise its find first free ip in subnet
#     :return: ip database inst
#     """
#     for cr_id in subnet_get_calc_ranges(su):
#         try:
#             if addr:
#                 # should be IP().allocate_specific_ip(addr)
#                 # i changed the location of the method
#                 ip = _get_or_none(CalculatedRange, cr_id).allocate_specific_ip(addr)
#             else:
#                 ip = _get_or_none(CalculatedRange, cr_id).allocate_free_ips()

#         except BadRequest as e:
#             _logger.error(e.description)
#             abort(400, "Failed allocating ip %s" % addr)

#         try:
#             db.session.add(ip)
#             db.session.commit()
#         except SQLAlchemyError as e:
#             _logger.error(e.description)
#             abort(500, "Could not allocate ip %s" % ip.address)

#         return ip


# def clear_ips(ips):
#     """
#     function will delete all ips related to current dhcpawn transaction
#     from db before aborting transaction.
#     :param ips: list of ip database insts
#     :return: [] if everything is cleared. [ips not cleared] if something went wrong and
#     """
#     db.session.expire_all()
#     for ip in ips:
#         try:
#             db.session.delete(ip)
#             db.session.commit()
#             # ips.remove(ip)
#         except SQLAlchemyError as e:
#             _logger.error(e.description + " Failed removing %s from DB" % [i.address for i in ips])
#             abort(400, e.description)

#     _logger.debug("Finished removing ips from DB after fail")


# def clear_hosts(hosts):
#     """
#     :param hosts: list of host db entries
#     :return:
#     """
#     db.session.expire_all()
#     for host in hosts:
#         try:
#             db.session.delete(host)
#             db.session.commit()
#             # hosts.remove(host)
#         except SQLAlchemyError:
#             pass
#             # _logger.error("Failed removing %s from DB" % host.name)
#             # _logger.error(e)
#             # abort(400, e.description)

#     _logger.debug("Finished removing hosts from DB after fail")


# # @api.route('/hosts/update_host_group/', methods=['PUT'])
# # def update_host_group():
# #     """ method used for moving a host to a specific group before
# #     rebooting from pxe during host installation. this method follows
# #     same expected arguments as we have today in infinilab BootServer.move_host_group"""
# #     _logger.debug("update_host_group")
# #     data = request.get_json(force=True)
# #     if any(key not in data for key in ["hostname", "mac", "new_group"]):
# #         abort(400, "Missing key/s in data dictionary - method requires: hostname, mac and new_group")
# #     new_group = get_by_field_or_404(Group, "name", data.get("new_group"))
# #     host = Host.query.filter_by(name=data.get("hostname")).first()
# #     if host:
# #         # host with this name exists
# #         if not host.group_id == new_group.id:
# #             # just making sure we're not trying to update to the same group
# #             host.ldap_delete()
# #             host.group = new_group
# #         else:
# #             _logger.debug("Nothing to do - new_group equals the current updated group.")
# #             return jsonify("Nothing to do")
# #     else:
# #         # host doesn't exist
# #         host = Host(name=data.get('hostname'),
# #                     mac=data.get('mac'),
# #                     group_id=new_group.id)
# #         db.session.add(host)

# #     db.session.commit()
# #     host.ldap_add()

# #     return jsonify(host.config())


# # @api.route('/hosts/update_host_name/',methods=['PUT'])
# # def update_host_name():
# #     """ method for updating host name in DB and LDAP """
# #     _logger.debug("update host name")
# #     data = request.get_json(force=True)
# #     if any(key not in data for key in ["current_name", "new_name"]):
# #         abort(400, "Missing key/s in data dictionary - method requires: current_name, new_name")
# #     current_name = data.get("current_name")
# #     new_name = data.get("new_name")
# #     try:
# #         host = get_by_field_or_404(Host, "name", current_name)
# #     except NotFound as e:
# #         abort(404, "Could not find a host with this name (%s) in DB ( %s )" % (current_name, e.description))
# #     host.ldap_delete()
# #     host.name = new_name
# #     db.session.commit()
# #     host.ldap_add()

# #     return jsonify(host.config())


# # @api.route('/hosts/delete_single_host/', methods=['DELETE'])
# # def delete_host():
# #     """ method removes a host from DB and LDAP"""
# #     _logger.debug("delete host")
# #     data = request.get_json(force=True)
# #     hostname = data.get("hostname")
# #     if not hostname:
# #         abort(400, "Missing 'hostname' key in data dictionary")
# #     host = Host.query.filter_by(name=hostname).first()
# #     if not host:
# #         abort(400, "Could not find the requested host - %s - in DB " % hostname)

# #     host.ldap_delete()
# #     db.session.delete(host)
# #     db.session.commit()

# #     return jsonify("Host %s was deleted successfully" % hostname)


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
