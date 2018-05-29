import re
import logbook
import json
import gossip
from sqlalchemy import desc
from sqlalchemy.orm import joinedload
from flask import jsonify, request, url_for
from flask.views import MethodView
from ipaddress import IPv4Address
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import BadRequest
from celery import chain
from cob import db
from raven.contrib.flask import Sentry

from .models import Host, Group, Subnet, IP, Pool, DhcpRange, CalculatedRange, Req, Dtask, Duplicate
from .help_functions import _get_or_none, get_by_id, get_by_field, DhcpawnError, update_req, gen_resp_deco
from .tasks import *


_logger = logbook.Logger(__name__)

patterns = {
    'id': [r'^\d+$'],
    'mac': [r'^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$'],
    'name': [r'^\D+[\da-zA-Z_\-]*$', r'^\d[\d\.]+$'],
    'address': [r'^\d[\d\.]+$'],
    'duptype': [r'mac|ip']
    }

class DhcpawnMethodView(MethodView):
    ''' Used to initiate a dhcpawn Request object '''
    def __init__(self):
        self.drequest = Req()
        self.res = None
        self.data = {}
        self.msg = None
        self.result = None
        self.errors = None
        self.drequest_type = None
        self.drequest_tasks_count = None
        self.drequest_reply_url = None

class DRequestListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        ''' used to get all requests from db '''
        reqs = Req.query.order_by(desc('id')).all()
        self.result = dict(items=[req.config() for req in reqs])
        self.msg = 'get all requests info'

class DRequestBaseAPI(DhcpawnMethodView):
    def get_drequest_by_param(self, param):
        self.patterns = {k: patterns[k] for k in ('id',)}
        req = identify_param(Req, param, self.patterns)
        if req:
            return req
        else:
            raise DhcpawnError(f"Wrong parameter {param} or no dhcpawn request with this parameter")

class DRequestAPI(DRequestBaseAPI):

    @gen_resp_deco
    def get(self, param):
        try:
            req = self.get_drequest_by_param(param)
        except DhcpawnError as e:
            self.msg = 'Please make sure the id exists. to see all requests please use this link: %s' % url_for('rest.dhcpawn_request_list_api', _external=True)
            self.errors = e.__str__()
            return

        self.result = req.config()
        self.msg = 'get info about dhcpawn request number %s' % param

class DtaskListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        ''' used to get all dtasks from db '''
        dtasks = Dtask.query.all()
        self.result = dict(items=[dtask.config() for dtask in dtasks])
        self.msg = 'get all dtasks info'

class DtaskBaseAPI(DhcpawnMethodView):
    def get_dtask_by_param(self, param):
        self.patterns = {k: patterns[k] for k in ('id',)}
        dtask = identify_param(Dtask, param, self.patterns)
        if dtask:
            return dtask
        else:
            raise DhcpawnError('Bad param or no dhcpawn dtask with param %s' % param)

class DtaskAPI(DtaskBaseAPI):

    @gen_resp_deco
    def get(self, param):
        try:
            dtask = self.get_dtask_by_param(param)
        except DhcpawnError as e:
            self.msg = 'Please make sure the id exists. to see all dtasks please use this link: %s' % url_for('rest.dhcpawn_dtask_list_api', _external=True)
            self.errors = e.__str__()
            return

        self.result = dtask.config()
        self.msg = 'get specific dhcpawn dtask info'

### HOST CLASSES
class HostListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        ''' used to get a list of all hosts from database '''
        hosts = Host.query.options(joinedload(Host.ip)).options(joinedload(Host.group)).all()
        self.result = dict(items=[host.config() for host in hosts])
        self.msg = 'get all hosts'

    @gen_resp_deco
    @update_req
    def post(self):
        """ create new host entry in database and ldap - syncronous"""

        try:
            self.data = request.get_json(force=True)
        except BadRequest as e:
            self.errors = e.description
            self.msg = 'check that you actually provided the request info'
            return
        dtasks_group = []
        self.drequest.request_type = "Sync Single Host Creation"
        self.drequest.update_drequest(params=self.data)

        for hkey in self.data:
            dtasks_group.append(Dtask(self.drequest.id))
            tinput = {
                'hkey': hkey,
                'hdata': self.data[hkey],
                'dtask_id': dtasks_group[-1].id
            }
            Host.single_host_register_track(**tinput)

        self.drequest.refresh_status()
        self.msg = 'The Sync Way'

    def delete(self):
        """ Delete all host records from db - only used in development mode """
        for h in Host.query.all():
            db.session.delete(h)
        db.session.commit()
        return jsonify("Cleared all host records from DB")


class HostBaseAPI(DhcpawnMethodView):
    def get_host_by_param(self, param):
        '''
        param can be:
        1. id and will contain only numbers
        2. mac with all possible mac formats (https://tinyurl.com/76ynygq)
        3. name starting with a letter and could contain numbers and some special chars
        '''
        self.patterns = {k: patterns[k] for k in ('id', 'mac', 'name')}
        host = identify_param(Host, param, self.patterns)
        if host:
            return host
        else:
            raise DhcpawnError('Bad param or no host with param %s' % param)

    def update_host(self, host):
        '''
        used to update an existing host's:
        1. ip
        2. group
        3. options
        '''
        try:
            new_group_id, new_address_id = host.update(**self.data)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return

        self.dtask = Dtask(self.drequest.id)
        self.res = task_host_ldap_modify.delay(host.id, self.dtask.id, new_group_id=new_group_id, new_address_id=new_address_id)
        self.msg = "Sent async ldap modify and db update on %s" % host.name
        self.drequest_type = "host update"

    def delete_host(self, host):
        """
        method will receive a host instance
        rather then id or name
        """
        self.dtask = Dtask(self.drequest.id)
        self.res = task_host_ldap_delete.delay(host.id, self.dtask.id)
        self.msg = "Async ldap delete and db delete sent for %s" % host.name
        self.drequest_type = "delete host"

class HostAPI(HostBaseAPI):
    '''
    specific host manipulations
    using regex
    '''
    @gen_resp_deco
    def get(self, param):
        self.msg = 'get specific host'
        try:
            host = self.get_host_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return
        self.result = host.config()

    @gen_resp_deco
    @update_req
    def put(self, param):
        self.drequest_type = 'modify host'
        try:
            host = self.get_host_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
            self.msg = 'did not get to the modify part. failed on getting the host to modify'
            return

        try:
            self.data = request.get_json(force=True)
        except BadRequest as e:
            self.errors = e.description
            self.msg = 'check that you actually provided the request info'
            return
        dtasks_group = []
        self.drequest.request_type = "Sync Single Host Update"
        self.drequest.update_drequest(params=self.data)

        for hkey in self.data:
            dtasks_group.append(Dtask(self.drequest.id))
            tinput = {
                'hkey': hkey,
                'hdata': self.data[hkey],
                'dtask_id': dtasks_group[-1].id
            }
            Host.single_host_register_track(**tinput)

        self.drequest.refresh_status()
        self.msg = 'The Sync Way'
        # self.update_host(host)

    @gen_resp_deco
    @update_req
    def delete(self,param):
        try:
            host = self.get_host_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return

        try:
            self.data = request.get_json(force=True)
        except BadRequest as e:
            self.errors = e.description
            self.msg = 'check that you actually provided the request info'
            return
        dtasks_group = []
        self.drequest.request_type = "Sync Single Host Deletion"
        self.drequest.update_drequest(params=self.data)

        for hkey in self.data:
            dtasks_group.append(Dtask(self.drequest.id))
            tinput = {
                'hkey': hkey,
                'hdata': self.data[hkey],
                'dtask_id': dtasks_group[-1].id
            }
            Host.single_host_delete_track(**tinput)

        self.drequest.refresh_status()
        self.msg = 'The Sync Way'
        # self.delete_host(host)

### GROUP CLASSES

class GroupListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        self.msg = "Get all groups info"
        self.result = {}
        for gr in Group.query.all():
            self.result.update({gr.name:gr.config()})

    @gen_resp_deco
    def post(self):
        self.msg = "Create new group"
        data = request.get_json(force=True)
        if any(key not in data for key in ['name']):
            self.errors = "Please provide group name"
            return
        if Group.query.filter(Group.name == data.get('name')).all():
            self.errors = "A Group with this name already exists"
            return
        group = Group(name=data.get('name'),
                      options=json.dumps(data.get('options', {})),
                      deployed=data.get('deployed'))
        db.session.add(group)
        db.session.commit()
        if group.deployed:
            group.ldap_add()
        self.result = group.config()
        # return jsonify(group.config())

class GroupBaseAPI(DhcpawnMethodView):
    def get_group_by_param(self, param):
        '''
        param can be:
        1. id and will contain only numbers
        2. name starting with a letter and could contain numbers and some special chars
        '''
        self.patterns = {k: patterns[k] for k in ('id', 'name')}
        group = identify_param(Group ,param, self.patterns)
        if group:
            return group
        else:
            raise DhcpawnError('Bad param or no group with param %s' % param)

class GroupAPI(GroupBaseAPI):

    @gen_resp_deco
    def get(self, param):
        self.msg = "Get Specific group info by param %s" % param
        try:
            group = self.get_group_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
        else:
            self.result = {group.name:group.config()}

    @gen_resp_deco
    def put(self, param):
        self.msg = "Modify specific group by param %s" % param
        try:
            group = self.get_group_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return

        data = request.get_json(force=True)
        if group.hosts.all():
            _logger.info("Deleteing all hosts in group %s from LDAP" % group.name)
            for host in group.hosts.all():
                host.ldap_delete()

        group.ldap_delete()
        if 'name' in data:
            group.name = data.get('name')
        if 'options' in data:
            group.options = json.dumps(data.get('options'))
        if 'deployed' in data:
            group.deployed = data.get('deployed')
            if not group.deployed:
                for host in group.hosts.all():
                    host.deployed = False
                    db.session.add(host)
        db.session.add(group)
        db.session.commit()
        group.ldap_add()
        if group.deployed and group.hosts.all():
            _logger.info("Adding all group %s hosts to LDAP" % group.name)
            for host in group.hosts.all():
                host.ldap_add()
        self.result = {group.name:group.config()}

    @gen_resp_deco
    def delete(self, param):
        self.msg = "Delete group by param %s" % param
        try:
            group = self.get_group_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return

        hosts = []
        for host in group.hosts.all():
            host.ldap_delete()
            host.group_id = None
            hosts.append(host)
            db.session.add(host)
        group.ldap_delete()
        db.session.delete(group)
        db.session.commit()
        for host in hosts:
            host.ldap_add()

        self.result = [{group.name:group.config()} for group in Group.query.all()]

# Subnet CLASSES
class SubnetListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        self.msg = "Get all subnets info"
        self.result = {}
        _logger.debug("SubnetListAPI")
        for su in Subnet.query.all():
            self.result.update({su.name:su.config()})

    @gen_resp_deco
    def post(self):
        """ create a new subnet entry in db and ldap"""
        self.msg = "Create new subnet"
        _logger.debug("SubnetListAPI")
        data = request.get_json(force=True)
        if any(key not in data for key in ['name','netmask']):
            self.errors = "Subnet requires name and netmask"
            return
        try:
            Subnet.validate_by_name(data.get('name'))
        except DhcpawnError:
            pass
        else:
            self.errors = "A subnet with this name %s already exists" % data.get('name')
            return

        subnet = Subnet(name=data.get('name'),
                        netmask=data.get('netmask'),
                        options=json.dumps(data.get('options',{})),
                        deployed=data.get('deployed'))
        db.session.add(subnet)
        db.session.commit()
        if subnet.deployed:
            subnet.ldap_add()
        self.result = subnet.config()

class SubnetBaseAPI(DhcpawnMethodView):
    def get_subnet_by_param(self, param):
        '''
        param can be:
        1. id and will contain only numbers
        2. name starting with a letter and could contain numbers and some special chars
        '''
        self.patterns = {k: patterns[k] for k in ('id', 'name')}
        subnet = identify_param(Subnet ,param, self.patterns)
        if subnet:
            return subnet
        else:
            raise DhcpawnError('Bad param or no subnet with param %s' % param)

class SubnetAPI(SubnetBaseAPI):

    @gen_resp_deco
    def get(self, param):
        """ get specific subnet json"""
        self.msg = "Get Specific subnet info by param %s" % param
        _logger.debug("SubnetAPI")
        try:
            subnet = self.get_subnet_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
        else:
            self.result = {subnet.name:subnet.config()}

    @gen_resp_deco
    def put(self, param):
        """ update subnet entry in db and ldap"""
        self.msg = "Modify specific subnet by param %s" % param
        _logger.debug("SubnetAPI")
        try:
            subnet = self.get_subnet_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return
        data = request.get_json(force=True)
        if 'netmask' in data:
            subnet.netmask = data.get('netmask')
        if 'options' in data:
            subnet.options = json.dumps(data.get('options'))
        if 'deployed' in data:
            subnet.deployed = data.get('deployed')
        if subnet.deployed:
            subnet.ldap_modify()
        else:
            # didnt check the next code.
            subnet.deployed = True
            for pool in subnet.pools.all():
                pool.ldap_delete()
                pool.deployed = False
                db.session.add(pool)
            for ip in subnet.ips.all():
                ip.ldap_delete()
                ip.deployed = False
                db.session.add(ip)

            subnet.ldap_delete(subnet.dn())
            db.session.commit()

        db.session.add(subnet)
        db.session.commit()

        self.result = {subnet.name:subnet.config()}

    @gen_resp_deco
    def delete(self, param):
        self.msg = "Delete subnet by param %s" % param
        _logger.debug("SubnetAPI")
        try:
            subnet = self.get_subnet_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return

        for pool in subnet.pools.all():
            pool.ldap_delete()
            if pool.dhcprange:
                db.session.delete(pool.dhcprange)
            db.session.delete(pool)
        for crange in subnet.calcranges.all():
            db.session.delete(crange)
        db.session.commit()
        subnet.ldap_delete()
        db.session.delete(subnet)
        db.session.commit()
        self.result = [{subnet.name:subnet.config()} for subnet in Subnet.query.all()]

# IP CLASSES
class IPListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        self.msg = "Get all ips info"
        self.result = {}
        for ip in IP.query.all():
            self.result.update({str(ip.address):ip.config()})

    @gen_resp_deco
    def post(self):
        """ obviously the range here is only a calculated range,
        where hosts can get ips from """
        self.msg = "Create new IP"
        data = request.get_json(force=True)
        if any(key not in data for key in ['address', 'calcrange']):
            self.errors = "IP requires address, calculatedrange and host"
            return
        address = data.get('address')
        try:
            IP.is_ip_taken(address)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return

        # calcrange = get_by_id(CalculatedRange, data.get('calcrange'))
        ip = IP(address=address,
                host_id=data.get('host'),
                calcrange_id=data.get('calcrange'))

        # regular mode of work - no host_id given when creating ip instance
        # so its not deployable, next step would be creating the host ,attach it to
        # to this ip and then deploy host with ip to ldap
        deployable = True
        host = _get_or_none(Host, data.get('host'))
        if host and not host.deployed:
            deployable = False
        ip.deployed = data.get('deployed', True)
        if data.get('deployed'):
            if ip.deployed and not deployable:
                self.errors = "Cannot deploy IP in non-deployed host or range"
                return
        else:
            if not deployable:
                ip.deployed = False
        db.session.add(ip)
        db.session.commit()
        if ip.deployed:
            ip.ldap_add()

        self.result = ip.config()

    def delete(self):
        """ Delete all ip records from db """
        for ip in IP.query.all():
            db.session.delete(ip)
        db.session.commit()
        return jsonify("Cleared all ip records from DB")

class IPBaseAPI(DhcpawnMethodView):
    def get_ip_by_param(self, param):
        '''
        param can be:
        1. id and will contain only numbers
        2. address starting with a letter and could contain numbers and some special chars
        '''
        self.patterns = {k: patterns[k] for k in ('id', 'address')}
        ip = identify_param(IP ,param, self.patterns)
        if ip:
            return ip
        else:
            raise DhcpawnError('Bad param or no IP with param %s' % param)

    def disconnect_host_ip(self):
        ''' update the host connected to this ip, so that it will have no ip '''
        pass

class IPAPI(IPBaseAPI):

    @gen_resp_deco
    def get(self, param):
        """ get a specific IP entry """
        _logger.debug("IPAPI")
        self.msg = "get specific ip info by param %s" % param
        try:
            ip = self.get_ip_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
        else:
            self.result = ip.config()
        # return jsonify(ip.config())

    @gen_resp_deco
    def put(self, param):
        _logger.debug("IPAPI")
        try:
            ip = self.get_ip_by_param(param)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return
        data = request.get_json(force=True)
        if any(key not in ['host', 'deployed'] for key in data):
            self.errors = "IP PUT requests only accept host"
            return

        if 'deployed' in data:
            deployed = data.get('deployed')
            if deployed:
                if ip.host_id:
                    host = get_by_id(Host, ip.host_id)
                    if not host.deployed:
                        self.errors = "Cannot deploy IP as parameter of non-deployed host"
                        return

        if 'host' in data:
            try:
                host = get_by_field(Host, 'name', data.get('host'))
            except DhcpawnError as e:
                self.errors = e.__str__()
                return

            if ip.host_id == host.id:
                self.errors = "Host is already connected to this IP"
                return

            ip.host_id = host.id

        if 'deployed' in data:
            ip.deployed = data.get('deployed')
        db.session.add(ip)
        db.session.commit()
        ip.ldap_add()
        self.result = ip.config()

    @gen_resp_deco
    def delete(self, param):
        self.msg = "delete ip by param %s" % param
        _logger.debug("IPAPI")
        ip = self.get_ip_by_param(param)
        # 1. host.delete_ip (ldap and DB)
        # 2. ip.delete (DB)
        self.dtask = Dtask(self.drequest.id)
        self.res = task_host_ldap_modify.delay(ip.host.id,
                                               self.dtask.id,
                                               new_address_id='clear')
        self.msg = 'IP deletion async processing started.'

# DHCP CLASSES

class DhcpRangeListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        ranges = DhcpRange.query.all()
        self.msg = "Get all dhcpranges"
        self.result = dict(items=[range.config() for range in ranges])

    @gen_resp_deco
    def post(self):
        self.msg = "Create new dhcprange"
        data = request.get_json(force=True)
        if any(key not in data for key in ['min', 'max']):
            self.errors = "Dhcp Range requires a min, and max"
            return
        if all(key not in data for key in ['pool', 'pool_name']):
            self.errors = "Dhcp Range requires a pool_id (pool key in data) or a pool_name"
            return

        if 'pool' in data:
            pool_id = data.get('pool')
        else:
            pool = get_by_field(Pool, 'name', data.get('pool_name'))
            pool_id = pool.id

        ipmin = IPv4Address(data.get('min'))
        ipmax = IPv4Address(data.get('max'))
        deployed = data.get('deployed', False)

        for iprange in DhcpRange.query.all():
            if iprange.contains(ipmin) or iprange.contains(ipmax):
                self.errors = f"Range overlaps with existing ranges {iprange.id}"
                return

        dhcprange = DhcpRange(
            min=data.get('min'),
            max=data.get('max'),
            pool_id=pool_id,
            deployed=deployed
            )
        # update db with new range
        db.session.add(dhcprange)
        db.session.commit()
        dhcprange.ldap_add()
        self.result = dhcprange.config()

class DhcpRangeAPI(DhcpawnMethodView):

    def get(self, dhcp_range_id):
        pass

    def put(self, dhcp_range_id):
        pass

    def delete(self, dhcp_range_id):
        pass

# CALCULATED CLASSES

class CalculatedLRangeListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        self.msg = "Get all calculated ranges"
        ranges = CalculatedRange.query.all()
        self.result = dict(items=[range.config() for range in ranges])

    @gen_resp_deco
    def post(self):
        self.msg = "Create new calculated range"
        data = request.get_json(force=True)
        if any(key not in data for key in ['min', 'max']):
            self.errors = "Calculated Range requires a min, and max"
            return
        if all(key not in data for key in ['subnet', 'subnet_name']):
            self.errors = "Calculated Range requires a subnet_id or subnet_name"
            return
        ipmin = IPv4Address(data.get('min'))
        ipmax = IPv4Address(data.get('max'))

        if 'subnet' in data:
            subnet_id = data.get('subnet')
        else:
            subnet = get_by_field(Subnet, 'name', data.get('subnet_name'))
            subnet_id = subnet.id

        for iprange in CalculatedRange.query.all():
            if iprange.contains(ipmin) or iprange.contains(ipmax):
                self.errors = f"Range overlaps with existing ranges {iprange.id}"
                return
        calcrange = CalculatedRange(
            min=data.get('min'),
            max=data.get('max'),
            subnet_id=subnet_id
        )
        db.session.add(calcrange)
        db.session.commit()
        self.result = calcrange.config()

class CalculatedRangeAPI(DhcpawnMethodView):

    def get(self, calc_range_id):
        pass

    def put(self, calc_range_id):
        pass

    def delete(self, calc_range_id):
        pass

# POOL CLASSES

class PoolListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        self.msg = "Get all pools"
        pools = Pool.query.all()
        self.result = dict(items=[pool.config() for pool in pools])

    @gen_resp_deco
    def post(self):
        """ Create Pool but only in db
            only when we add a dhcpRange , we can deploy to ldap
        """
        self.msg = "Create new pool"
        data = request.get_json(force=True)
        if 'name' not in data:
            self.errors = "Pool requires a name"
            return
        if all(key not in data for key in ['subnet', 'subnet_name']):
            self.errors = "Pool requires either a subnet id or a subnet name"
            return

        if Pool.query.filter(Pool.name == data.get('name')).all():
            self.errors = "A pool by this name already exists"
            return

        if 'subnet' in data:
            subnet_id = data.get('subnet')
        else:
            subnet = get_by_field(Subnet, 'name', data.get('subnet_name'))
            subnet_id = subnet.id

        pool = Pool(name=data.get('name'),
                subnet_id=subnet_id,
                options=json.dumps(data.get('options', {})),
                deployed=False)

        subnet = get_by_id(Subnet, pool.subnet_id)

        db.session.add(pool)
        db.session.commit()
        if pool.deployed:
            pool.ldap_add()
        self.result = pool.config()

class PoolAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self, pool_id):
        self.msg = f"Get pool by pool id {pool_id}"
        pool = get_by_id(Pool, pool_id)
        self.result = pool.config()

    @gen_resp_deco
    def put(self, pool_id):
        """
        basically using this method to update dhcpRange
        and then deploy pool to ldap
        of course other changes may apply too
        """
        self.msg = "Update pool"
        pool = get_by_id(Pool, pool_id)
        data = request.get_json(force=True)
        if 'deployed' in data:
            deployed = data.get('deployed')
            if deployed:
                if pool.subnet_id:
                    subnet = get_by_id(Subnet, pool.subnet_id)
                    if not subnet.deployed:
                        self.errors = "Cannot deploy pool with non-deployed subnet"
                        return
        pool.ldap_delete()
        if 'name' in data:
            pool.name = data.get('name')
        if 'subnet' in data:
            pool.subnet_id = data.get('subnet')

        if 'options' in data:
            pool.options = json.dumps(data.get('options'))
        if 'deployed' in data:
            pool.deployed = data.get('deployed')
            if pool.range_id:
                ip_range = get_by_id(DhcpRange, pool.range_id)
                ip_range.deployed = pool.deployed
                db.session.add(ip_range)
        db.session.add(pool)
        db.session.commit()
        pool.ldap_add()
        self.result = pool.config()

    @gen_resp_deco
    def delete(self, pool_id):
        self.msg = "Delete pool by id {pool_id}"
        pool = get_by_id(Pool, pool_id)
        pool.ldap_delete()
        if pool.range:
            db.session.delete(pool.range)
        db.session.delete(pool)
        db.session.commit()
        self.result = [pool.config() for pool in Pool.query.all()]

# Duplicate Class
class DuplicateBaseAPI(DhcpawnMethodView):
    def get_duplicate_by_param(self, param):
        self.patterns = {k: patterns[k] for k in ('duptype','id')}
        dup = identify_param(Duplicate, param, self.patterns)
        if isinstance(dup, list):
            self.result = [d.config() for d in dup]
        elif isinstance(dup, Duplicate):
            self.result = dup.config()
        else:
            self.errors = f"Wrong parameter {param} or no dhcpawn request with this parameter"
            self.msg = f"Please make sure this duplicate type exists. to see all duplicates please use this url: {url_for('rest.dhcpawn_duplicate_list_api', _external=True)}"
            raise DhcpawnError(self.errors)

class DuplicateAPI(DuplicateBaseAPI):

    @gen_resp_deco
    def get(self, param):
        self.msg = f"Get info about ldap duplicates with parameter {param}"
        try:
            self.result = self.get_duplicate_by_param(param)
        except DhcpawnError:
            return


    @gen_resp_deco
    def post(self, param):
        ''' used to make a duplicate record valid again.
        param can only be an id nubmer '''
        try:
            dup = self.get_duplicate_by_param(param)
        except DhcpawnError:
            return
        dup.make_valid()
        self.msg = "Duplicate record is now valid"

    @gen_resp_deco
    def put(self, param):
        ''' param can only be an id nubmer
        used to invalidate a duplicate record'''
        try:
            dup = self.get_duplicate_by_param(param)
        except DhcpawnError:
            return

        dup.invalidate()
        self.msg = "Invalidated Duplicate record"


class DuplicateListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        self.result = [duplicate.config() if duplicate.valid
                        else None for duplicate in Duplicate.query.all()]
        self.msg = "get all duplicates"

###### Help functions

def identify_param(model, param, ptrns):
    for ptype in ptrns:
        for pat in ptrns[ptype]:
            if re.match(pat, param):
                return get_by_field(model, ptype, param)
    return None

class MultipleAction(DhcpawnMethodView):
    @gen_resp_deco
    @update_req
    def post(self):
        """
        can take more then one dhcpHost (i.e host or system) and register it in DB/ldap
        the record must have hostname, mac and group.
        the record can have subnet, ip  but if not ,then just create the entry without allocating the ip.
        {h1: {hostname: , mac: , group: ,subnet:, ip: }, h2: {}, ...}
        --> incase one of the inputs is wrong ,validation fails and the entire request will fail
        - no ip is allocated.
        """
        _logger.debug(f"multiple register")
        self.drequest.request_type = "Async Multiple Registration"
        self.data = request.get_json(force=True)
        self.drequest.update_drequest(params=self.data)
        deploy = "True"
        sync = False
        if 'deploy' in self.data:
            deploy = self.data.get('deploy')
            del self.data['deploy']
        if 'reply_url' in self.data:
            self.drequest.update_drequest(drequest_reply_url = self.data.get('reply_url'))
            del self.data['reply_url']
        if 'sync' in self.data and self.data.get('sync') == 'true':
            sync = True
            self.drequest.request_type = "Sync Multiple Registration"
            del self.data['sync']
        if deploy.lower()=="true":
            # _logger.debug("DEPLOY=%s" % deploy)
            # _logger.info(f"Data size: {len(self.data)}")
            # this is the day to day part of the code
            # validation is needed and all the rest of the flow
            dtasks_group = []
            tasks_group = []
            for hdata in self.data:
                dtasks_group.append(Dtask(self.drequest.id))
                tinput = {
                    'hkey': hdata,
                    'hdata': self.data[hdata],
                    'dtask_id':dtasks_group[-1].id
                    }
                if sync:
                    tasks_group.append(Host.single_host_register_track(**tinput))
                else:
                    tasks_group.append(task_single_input_registration.s(**tinput))



            if sync:
                self.drequest.refresh_status()
                self.drequest.postreply()
                self.msg = 'The Sync Way'
            else:
                tinput = {'dreq_id': self.drequest.id}
                # tasks_group.append(task_send_postreply.s(**tinput))
                register_chain = chain(*tasks_group)
                refresh_request_job = task_update_drequest.s(**tinput)
                post_reply_job = task_send_postreply.s(**tinput)
                full_chain = chain(register_chain, refresh_request_job, post_reply_job)
                res = full_chain.apply_async()
                self.msg = f"Registration to DB Finished. ldap async part is running. stay tuned.. {self.res}"

    @gen_resp_deco
    @update_req
    def delete(self):
        _logger.info("multiple delete")
        self.drequest.request_type = "Async Multiple Deletion"
        self.data = request.get_json(force=True)
        self.drequest.update_drequest(params=self.data)
        hard = False
        sync = False
        if 'deploy' in self.data:
            del self.data['deploy']
        if 'reply_url' in self.data:
            self.drequest.update_drequest(drequest_reply_url = self.data.get('reply_url'))
            del self.data['reply_url']
        # if 'hard' in self.data:
            # del self.data['hard']
            # hard = True
        if 'sync' in self.data and self.data.get('sync') == 'true':
            sync = True
            self.drequest.request_type = "Sync Multiple Deletion"
            del self.data['sync']

        dtasks_group = []
        tasks_group = []
        for hdata in self.data:
            dtasks_group.append(Dtask(self.drequest.id))
            tinput = {
                'hkey': hdata,
                'hdata': self.data[hdata],
                'dtask_id':dtasks_group[-1].id
            }
            if sync:
                tasks_group.append(Host.single_host_delete_track(**tinput))
            else:
                tasks_group.append(task_single_input_deletion.s(**tinput))

        if sync:
            self.drequest.refresh_status()
            self.drequest.postreply()
            self.msg = 'The Sync Way'
        else:

            tinput = {'dreq_id': self.drequest.id}
            delete_chain = chain(*tasks_group)
            refresh_request_job = task_update_drequest.s(**tinput)
            post_reply_job = task_send_postreply.s(**tinput)
            _logger.debug("Adding post reply task to chain")
            full_chain = chain(delete_chain, refresh_request_job, post_reply_job)
            res = full_chain.apply_async()
            self.msg = f"Deletion to DB Finished. ldap async part is running. stay tuned.. {self.res}"

#### HELP FUNCTIONS
# def hard_delete(data):
#     """ for cases we have dirty data, i.e hostnames in ldap but not in DB,
#     the regular validate before delete wont work"""
#     for h in data:

#         name = data[h]['hostname']
#         mac = data[h]['mac']
#         group = data[h]['group']
#         _hard_delete_by_name(name, group)
#         _hard_delete_by_mac(mac)

# def _hard_delete_by_name(name, group):
#     try:
#         host = Host.query.filter_by(name=name).first()
#         # _logger.debug("LDAP hard delete by name %s" % host.config())
#         if host == None:
#             raise ValueError
#     except ValueError:
#         host = Host(name=name,
#                     group = Group.validate_by_name(group),
#                     group_id = Group.validate_by_name(group).id,
#                     deployed=True)
#     finally:
#         try:
#             host.ldap_delete()
#             _logger.info("LDAP hard delete %s" % host.dn())
#             db.session.delete(host)
#             db.session.commit()
#         except DhcpawnError as e:
#             _logger.warning(f"Failed hard delete for {name} ({e.__str__()})")
#             db.session.rollback()


# def _hard_delete_by_mac(mac):
#     host = Host.query.filter_by(mac=mac).first()
#     try:
#         _logger.debug("DB hard delete by mac %s" % host.config())
#         host.ldap_delete()
#     except DhcpawnError:
#         _logger.error(f"Failed ldap delete during hard_delete_by_mac {mac}")
#     else:
#         db.session.delete(host)
#         db.session.commit()

def validate_data_before_registration(data):
    """
    a wrapper for the validation function. it will go over all hosts in request and
    return a dict of validated inputs and subnet distribution for optimization reasons..
    :param data: dictionary provided by the request
    :return:
        validated_host_dict - contains all Host instances created according to the data given to the request
        subnet_hist - subnet distribution
    """
    validated_host_dict = dict()
    remove_hosts_on_fail = []
    remove_ips_on_fail = []
    if isinstance(data, str):
        data = json.loads(data)
    for h in data.keys():
        hdata = data.get(h)
        try:

            # host, group, subnet, ip = single_input_validation(hdata)
            host, group, subnet, ip = Host.single_input_validate_before_registration(**hdata)
            new_host = False
            if not host:
                new_host = True
                host = Host(name=hdata.get('hostname'),
                            mac=hdata.get('mac'),
                            group_id=group.id
                            )
            else:
                _logger.info("Host %s already in DB. just updating it" % hdata['hostname'])
            remove_hosts_on_fail.append(host)
            if subnet:
                if ip == 'allocate':
                    ip = alloc_single_ip(subnet, 'allocate')
                elif ip:
                    ip = alloc_single_ip(subnet, ip)
                else:
                    raise DhcpawnError("what the fuck ? subnet exists (%s) but ip is none ?" % subnet.name)
                remove_ips_on_fail.append(ip)
                host.ip = ip

            elif not new_host:
                raise DhcpawnError("What the fuck ? Nothing to update, record already exists. %s" % hdata)

            # building a validated hosts dict of Host instances for later ip allocation
            # the dict should be divided into different subnets
            if subnet not in validated_host_dict:
                validated_host_dict[subnet] = dict()
            validated_host_dict[subnet][h] = host
        except DhcpawnError as e:
            if re.search("ip .* already taken", e.__str__()):
                ip_record = IP.query.filter_by(address=IPv4Address(hdata['ip'])).first()
                dup_description = re.search("ip .* already taken", e.__str__()).group(0)
                Duplicate(f"{dup_description} (new host:{hdata['hostname']} existing host: {ip_record.host.name})", "ip")
                _logger.error(f"DUPLICATION ERROR: {dup_description}")
            else:
                raise
    return validated_host_dict, remove_ips_on_fail

def validate_data_before_deletion(data):
    ''' date should include hostname mac and group to be deleted '''
    validated_host_dict = dict()
    for h in data.keys():
        hdata = data.get(h)
        try:
            host = Host.single_input_validate_before_deletion(**hdata)
        except DhcpawnError:
            raise
        else:
            validated_host_dict[h] = host

    return validated_host_dict

# def alloc_single_ip(su, addr=None):
#     """
#     go over subnet calculated ranges and find a free ip if addr=None
#     or check if the specific address is free to allocate
#     :param su: subnet in which the ip should be
#     :param addr: if a specific address in needed otherwise its find first free ip in subnet
#     :return: ip database inst
#     """
#     # for cr_id in subnet_get_calc_ranges(su):
#     try:
#         if addr == 'allocate':
#             ip = su.allocate_free_ip()
#         else:
#             return IP.allocate_specific_ip(addr)
#     except DhcpawnError as e:
#         _logger.error(e.__str__())
#         raise DhcpawnError("Failed allocating ip %s" % addr)
#     return ip

def clear_ips(ips):
    """
    function will delete all ips related to current dhcpawn transaction
    from db before aborting transaction.
    :param ips: list of ip database insts
    :return: [] if everything is cleared. [ips not cleared] if something went wrong and
    """
    db.session.expire_all()
    for ip in ips:
        try:
            db.session.delete(ip)
            db.session.commit()
        except SQLAlchemyError as e:
            _logger.error(f"Failed removing {ip.address} from DB ({e.__str__()})")

    _logger.debug("Finished removing ips from DB after fail")

def clear_hosts(hosts):
    """
    :param hosts: list of host db entries
    :return:
    """
    db.session.expire_all()
    for host in hosts:
        name = host.name
        try:
            try:
                host.ldap_delete()
            except DhcpawnError as e:
                _logger.warning("Failed while cleaning LDAP after failure %s (%s)" % (host.name, e.__str__()))

            db.session.delete(host)
            db.session.commit()
            _logger.info("Clear Hosts - Removed %s" % name)
        except SQLAlchemyError as e:
            _logger.error("Failed while cleaning %s after failure (%s)" % (name, e.__str__()))

        _logger.info("Cleaned all remainders of %s from LDAP/DB" % name)

    _logger.info("Finished removing hosts from DB after fail")


### Sync

class Sync(DhcpawnMethodView):

    @gen_resp_deco
    @update_req
    def get(self, group_name=None, sync=False):
        """
        get sync status per group or for all groups.
        :return: returns diff status
        """
        if not sync:
            self.drequest_type = "Get Sync Status"
        _logger.debug(self.drequest_type)

        try:
            isinstance(self.d, dict)
        except AttributeError:
            self.d = dict([('groups', {})])

        try:
            if group_name:
                gr = get_by_field(Group, 'name', group_name)
                self.d['groups'].update(self.get_per_group(gr))
            else:
                for gr in Group.query.all():
                    self.d['groups'].update(self.get_per_group(gr))
        except DhcpawnError as e:
            self.errors = e.__str__()
            self.msg = f"Failed getting sync status for group {group_name}"
            return

        self.result = self.d

    def get_per_group(self, group):

        try:
            d = group.get_sync_stat()
        except DhcpawnError as e:
            self.errors = e.__str__()
            self.msg = f"Failed getting sync status for group {group.name}"
            raise
        else:
            return d



    @gen_resp_deco
    @update_req
    def post(self, group_name=None):
        """
        sync db->ldap direction meaning we make sure ldap looks exactly as dhcpawn db.
        :return:
        """
        self.drequest_type = "Run Sync"
        _logger.debug(self.drequest_type)

        self.d = dict([('groups', {})])
        post_sync = dict([('groups', {})])
        try:
            if group_name:
                gr = get_by_field(Group, 'name', group_name)
                tmpd, host_stat_dict = gr.group_sync()
                self.d['groups'].update(tmpd)
                if host_stat_dict:
                    post_sync['groups'].update(host_stat_dict)
            else:
                for gr in Group.query.all():
                    tmpd, host_stat_dict = gr.group_sync()
                    self.d['groups'].update(tmpd)
                    if host_stat_dict:

                        post_sync['groups'].update(host_stat_dict)
        except DhcpawnError as e:
            self.errors = e.__str__()
            self.msg = f"Failed sync job"
            return

        if post_sync['groups']:
            self.msg = "Sync made some changes"
            self.result = {'pre sync': {k:v for k,v in self.d['groups'].items() if not v['group is synced']},
                           'post sync': {k:v for k,v in post_sync.items() if v} }
        else:
            self.msg = "Sync did not change anything"
            self.result = self.d


### Sentry
# @gossip.register('cob.after_configure_app')
# def after_configure_app(app):
#     app.config['SENTRY_DSN'] = 'http://1798f04a5bc749e7a99ba63eb8346e60:4560f83a51764b7b8f4fc400aa4b0b8e@sentry.infinidat.com/51'
#     Sentry(app)
