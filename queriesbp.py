# cob: type=blueprint mountpoint=/query
import re
import logbook
import json
from ipaddress import IPv4Address

from flask import Blueprint, jsonify, current_app, url_for
from cob.celery.app import celery_app
from cob.project import get_project

from . import methodviews as mv
from .models import Subnet, IP, CalculatedRange
from .help_functions import subnet_get_calc_ranges, _get_or_none, gen_resp_deco


_logger = logbook.Logger(__name__)
api = Blueprint('query', __name__)


######### Different Queries #########

@api.route('/sitemap/', methods=['GET'])
def sitemap():
    links = {}
    for rule in current_app.url_map.iter_rules():
        if rule.arguments:
            bp = url_for(rule.endpoint, **(dict.fromkeys(rule.arguments, 0) or {})).split('/')
            links.setdefault(bp[1], [])
            links[bp[1]].append(
                {url_for(rule.endpoint, **(dict.fromkeys(rule.arguments, 0) or {}), _external=True)
                 :[str(rule.methods), str(rule.arguments)], 'info':bp}
            )
        else:
            bp = url_for(rule.endpoint).split('/')
            links.setdefault(bp[1], [])
            links[bp[1]].append(
                {url_for(rule.endpoint, _external=True): str(rule.methods), 'info':bp}
                )
    return jsonify(links)

@api.route('/general_info/', methods=['GET'])
def general_info():
    config = get_project().config
    broker_connection = re.match('.* (amqp://.*//) at', celery_app.broker_connection().__str__())[1]
    info = {
        'LDAP': {
            'LDAP_PRODUCTION_SERVER': config['PRODUCTION_LDAP'],
            'LDAP_SERVER': config['LDAP_SERVER'],
            'BIND_DN': config['BIND_DN']
            },
        'DB': {
            'SQLALCHEMY_DATABASE_URI': current_app.config.get('SQLALCHEMY_DATABASE_URI'),
            },
        'CELERY': {
            'BROKER': broker_connection
            },
        'SERVER': {
            'LOG LEVEL': _logger.level_name
            }
        }
    return jsonify(info)

@api.route('/clear_info_from_db/', methods=['GET'])
def clear_info_from_db():
    hla = mv.HostListAPI()
    ila = mv.IPListAPI()
    hla.delete()
    ila.delete()
    return jsonify("Cleared Host and IP records from DB")


@api.route('/subnets/query_free_ip_by_subnet_name/<sname>', methods=['GET'])
@gen_resp_deco
def query_free_ip_by_subnet_name(sname):
    """
    the name can be lowercase names as seen in every subnet dhcpComments
    i.e data1 ,data2, lab, gdc data1...

    returns: nubmer of free ips for the given subnet
    """
    _logger.debug("Query Free IPs amount")
    ret = {"errors":None, "result":None}
    subnet = None
    for s in Subnet.query.all():
        if json.loads(s.options)['dhcpComments'][0].lower() == sname:
            subnet = s

    if subnet:
        taken_ips = [ip.address for ip in IP.query.all()]
        counter, free_ips = get_free_ips_per_subnet(subnet, taken_ips)
        ret['result'] = f"Number of free ips in subnet: {counter} ({free_ips[:5]})"
    else:
        ret['errors'] = f"Subnet name {sname} is unknown"
    return ret

# @api.route('/subnets/query_free_ip_amount/', methods=['POST'])
# @gen_resp_deco
# def query_free_ip_amount():
#     """
#     query
#     the way to run it with curl:
#     curl http:/.../ -d '{"subnet":"172.16.32.0"}' -X GET

#     returns: the number of free ips per given subnet

#     """
#     _logger.debug("Query Free IPs amount")
#     ret = {"errors":None, "result":None}
#     data = request.get_json(force=True)
#     subnet = get_by_field(Subnet, 'name', data.get('subnet'))
#     taken_ips = [ip.address for ip in IP.query.all()]
#     counter, free_ips = get_free_ips_per_subnet(subnet, taken_ips)
#     ret['result'] = f"Number of free ips in subnet: {counter}"
#     return ret


@api.route('/subnets/query_all_free_ip_amount/', methods=['GET'])
@gen_resp_deco
def query_all_free_ip_amounts():
    """
    get free_ips for all subnets
    """
    ret = {"errors":None, "result":None}
    free_ips_dict = dict()
    taken_ips = [ip.address for ip in IP.query.all()]
    for subnet in Subnet.query.all():
        count, _ = get_free_ips_per_subnet(subnet, taken_ips)
        free_ips_dict[subnet.name] = (count)

    ret['result'] = free_ips_dict
    return jsonify(ret)


@api.route('/subnets/query_subnet_from_ip/<ip>', methods=['GET'])
@gen_resp_deco
def query_subnet_from_ip(ip):
    """
    this api helps during dhcpawn development, for syncing old ldap entries with current new DB.
    :return:
    """
    _logger.debug("Get subnet name for ip")
    ret = {"errors":None, "result":None}
    ret['result'] = "Subnet not found"
    for cr in CalculatedRange.query.all():
        if cr.contains(IPv4Address(ip)):
            ret['result'] = cr.subnet.config()
            break
    return ret

@api.route('/subnets/query_subnet_options/<sname>', methods=['GET'])
@gen_resp_deco
def query_subnet_options(sname):

    ret = {"errors":None, "result":None}
    try:
        subnet = get_subnet_by_name(sname)
    except ValueError as e:
        ret['errors'] = e.__str__()

    ret['result'] = json.loads(subnet.options)
    return ret

#### Help funcs

def get_free_ips_per_subnet(subnet, taken_ips):
    """
    per subnet ,return a count of free_ips and the list of
    free ips.
    """
    free_ips = []
    counter = 0
    _logger.info(f"checking in subnet {subnet}")
    for cr_id in subnet_get_calc_ranges(subnet):
        cr = _get_or_none(CalculatedRange, cr_id)
        addr = cr.min - 1
        while addr < cr.max:
            addr += 1
            if not addr in taken_ips:
                counter += 1
                free_ips.append(addr.compressed)
    if not counter:
        return None, free_ips
    return counter, free_ips

def get_subnet_names():

    name_list = []
    for s in Subnet.query.all():
        name_list.append(json.loads(s.options)['dhcpComments'][0].lower())
    return name_list

def get_subnet_by_name(sname):
    """
    sname should be something like data1, lab, gdc lab,...
    """
    for s in Subnet.query.all():
        if json.loads(s.options)['dhcpComments'][0].lower() == sname:
            return s
    raise ValueError(f"subnet name {sname} doesn't exist, please provide one of: {get_subnet_names()}")
