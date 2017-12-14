# cob: type=blueprint mountpoint=/query
import re
import logbook
import json
from ipaddress import IPv4Address

from flask import Blueprint, request, jsonify, current_app, url_for
from cob.celery.app import celery_app
from cob.project import get_project

from . import methodviews as mv
from .models import Subnet, IP, CalculatedRange
from .help_functions import subnet_get_calc_ranges, get_by_id, get_by_field, _get_or_none, err_json


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
            'LDAP_PRODUCTION_SERVER': config['LDAP_PRODUCTION_SERVER'],
            'LDAP_SERVER': config['LDAP_SERVER'],
            'BIND_DN': config['BIND_DN']
            },
        'DB': {
            'SQLALCHEMY_DATABASE_URI': current_app.config.get('SQLALCHEMY_DATABASE_URI'),
            },
        'CELERY': {
            'BROKER': broker_connection
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
def query_free_ip_by_subnet_name(sname):
    """
    the name can be lowercase names as seen in every subnet dhcpComments
    i.e data1 ,data2, lab, gdc data1...

    returns: nubmer of free ips for the given subnet
    """
    _logger.debug("Query Free IPs amount")
    subnet = None
    for s in Subnet.query.all():
        if json.loads(s.options)['dhcpComments'][0].lower() == sname:
            subnet = s

    if subnet:
        taken_ips = [ip.address for ip in IP.query.all()]
        counter, free_ips = get_free_ips_per_subnet(subnet, taken_ips)
        return jsonify("Number of free ips in subnet: %s" % (counter))
    else:
        return jsonify("Subnet name %s is unknown" % sname)


@api.route('/subnets/query_free_ip_amount/', methods=['POST'])
def query_free_ip_amount():
    """
    query
    the way to run it with curl:
    curl http:/.../ -d '{"subnet":"172.16.32.0"}' -X GET

    returns: the number of free ips per given subnet

    """
    _logger.debug("Query Free IPs amount")
    data = request.get_json(force=True)
    subnet = get_by_field(Subnet, 'name', data.get('subnet'))
    taken_ips = [ip.address for ip in IP.query.all()]
    counter, free_ips = get_free_ips_per_subnet(subnet, taken_ips)

    return jsonify("Number of free ips in subnet: %s" % (counter))


@api.route('/subnets/query_all_free_ip_amount/', methods=['GET'])
def query_all_free_ip_amounts():
    """
    get free_ips for all subnets
    """
    free_ips_dict = dict()
    taken_ips = [ip.address for ip in IP.query.all()]
    for subnet in Subnet.query.all():
         count, _ = get_free_ips_per_subnet(subnet, taken_ips)
         free_ips_dict[subnet.name] = (count)

    return jsonify(free_ips_dict)


@api.route('/subnets/query_subnet_from_ip/', methods=['GET'])
def query_subnet_from_ip():
    """
    this api helps during dhcpawn development, for syncing old ldap entries with current new DB.
    :return:
    """
    _logger.debug("Get subnet name for ip")
    data = request.get_json(force=True)
    if 'ip' not in data:
        return err_json("Please provide ip")

    cr_id = None
    found = False
    for cr in CalculatedRange.query.all():
        if found:
            break
        if cr.contains(IPv4Address(data.get('ip'))):
            cr_id = cr.id
            found = True

    if found:
        return jsonify(get_by_id(Subnet, cr.subnet_id).name)
    else:
        return err_json("Subnet not found")


@api.route('/subnets/query_subnet_options/<sname>', methods=['GET'])
def query_get_subnet_options(sname):

    try:
        subnet = get_subnet_by_name(sname)
    except ValueError as e:
        return jsonify(e.args)

    return jsonify(json.loads(subnet.options))

#### Help funcs

def get_free_ips_per_subnet(subnet, taken_ips):
    """
    per subnet ,return a count of free_ips and the list of
    free ips.
    """
    free_ips = []
    counter = 0
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
    subnet = None
    for s in Subnet.query.all():
        if json.loads(s.options)['dhcpComments'][0].lower() == sname:
            return s
    raise ValueError("subnet name %s doesn't exist, please provide one of: %s" % (sname, get_subnet_names()))
