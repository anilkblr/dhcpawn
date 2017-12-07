import re
from ldap import ALREADY_EXISTS
from .models import Host, Group, Subnet, IP, Pool, DhcpRange, CalculatedRange, Req, Dtask
from .help_functions import err_json, _get_or_none, get_by_id, get_by_field, DhcpawnError, gen_resp, \
    update_req, gen_resp_deco, gen_drequest_in_db, subnet_get_calc_ranges

from flask import jsonify, request, has_request_context, url_for
from flask.views import MethodView
import json
from ipaddress import IPv4Address, IPv4Network
from cob import db
import logbook
from .tasks import task_host_ldap_delete, task_host_ldap_add, task_host_ldap_modify, task_get_group_sync_stat
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import BadRequest
from celery import group

_logger = logbook.Logger(__name__)

patterns = {
    'id': ['^\d+$'],
    'mac': ['^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$'],
    'name': ['^\D+[\da-zA-Z_\-]*$', '^\d[\d\.]+$'],
    'address': ['^\d[\d\.]+$']
    }
def value_by_context(returned):
    """
    check if request context exists to return jsonified
    """
    if has_request_context():
        return jsonify(returned)
    else:
        return returned


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
        reqs = Req.query.all()
        self.result = dict(items=[req.config() for req in reqs])
        self.msg = 'get all requests info'

class DRequestBaseAPI(DhcpawnMethodView):
    def get_drequest_by_param(self, param):
        self.patterns = {k: patterns[k] for k in ('id',)}
        req = identify_param(Req, param, self.patterns)
        if req:
            return req
        else:
            raise DhcpawnError('Bad param or no dhcpawn request with param %s' % param)

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
            self.errors = e.args[0]
            return

        self.result = dtask.config()
        self.msg = 'get specific dhcpawn dtask info'

### HOST CLASSES
class HostListAPI(DhcpawnMethodView):

    @gen_resp_deco
    def get(self):
        ''' used to get a list of all hosts from database '''
        hosts = Host.query.all()
        self.result = dict(items=[host.config() for host in hosts])
        self.msg = 'get all hosts'

    @gen_resp_deco
    @update_req
    def post(self):
        """ create new host entry in database and ldap"""
        self.data = request.get_json(force=True)
        try:
            host, group, subnet, ip = Host.single_input_validate_before_registration(self.data)
        except DhcpawnError as e:
            self.errors = e.__str__()
            self.msg = "Failed host registration"
            return

        if not host:
            host = Host(name=self.data.get('hostname'),
                        mac=self.data.get('mac'),
                        group=group)
        else:
            host.group = group

        if subnet:
            ip = alloc_single_ip(subnet, ip)
            host.ip = ip
        try:
            db.session.add(host)
            db.session.commit()
        except IntegrityError as e:
            self.errors = e.__str__()
            self.msg = "failed creating new host (while trying to commit to db). aborting.."
        else:
            self.dtask = Dtask(self.drequest.id)
            self.res = task_host_ldap_add.delay(host.id, self.dtask.id)
            self.msg = 'host created in db. waiting for ldap update'
            self.drequest_type = 'create single host'

    def delete(self):
        """ Delete all host records from db - only used in development mode """
        try:
            for h in Host.query.all():
                db.session.delete(h)

            db.session.commit()
            return jsonify("Cleared all host records from DB")

        except:
            return jsonify("Failed removing all Host records from DB")

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
            self.errors = e.args[0]
            return
        # changed = False
        # if not self.data.get('mac'): # mac / hostname correspondance
        #     self.errors = "no mac address provided"
        #     return

        # try:
        #     name_by_mac = get_by_field_or_404(Host, 'mac', self.data.get('mac')).name
        # except DhcpawnError as e:
        #     self.errors = e.args[0]
        #     return

        # if not name_by_mac == host.name:
        #     self.errors = "Provided mac %s doesn't match the hostname %s" % (self.data.get('mac'), host.name)
        #     return

        # if 'ip' in self.data and not host.ip.address == self.data.get('ip'):
        #     try:
        #         #new_address = is_ip_taken(self.data.get('ip'))
        #         new_address = IP().allocate_specific_ip(self.data.get('ip'))
        #         new_address_id = new_address.id
        #         changed = True
        #     except DhcpawnError as e:
        #         self.errors = e.args[0]
        #         return
        # else:
        #     new_address_id = None

        # if 'group' in self.data and not host.group.name == self.data.get('group'):
        #     changed = True
        #     try:
        #         new_group = get_by_field_or_404(Group, 'name', self.data.get('group'))
        #         new_group_id = new_group.id
        #     except DhcpawnError as e:
        #         self.errors = e.args[0]
        #         return
        # else:
        #     new_group_id = None

        # if 'deployed' in self.data and not host.deployed == self.data.get('deployed'):
        #     # changing deployment status:
        #     # current False -> True : meaning we want it to be deployed to LDAP
        #     # current True -> False : meaning we want to remove from LDAP ??? dont support for now.
        #     if host.deployed == False and self.data.get('deployed') == "True":
        #         changed = True
        #         host.deployed = True
        #     else:
        #         self.errors = "Trying to change deployment status from True to False - not supported for now"
        #         return
        # if host.deployed and not host.group.deployed:
        #     self.errors = "Cannot deploy host as subobject of non-deployed group"
        #     return

        # if not changed:
        #     self.errors = 'no real error - just nothing to change'
        #     return

        self.dtask = Dtask(self.drequest.id)
        self.res = task_host_ldap_modify.delay(host.id, self.dtask.id, new_group_id=new_group_id, new_address_id=new_address_id)
        self.msg = "Sent async ldap modify and db update on %s" % host.name
        self.drequest_type = "host update"
        # try:
        #     self.res = (task_host_ldap_delete(host.id, host.dn, self.drequest.id) |
        #                 task_host_ldap_add(host.id, self.drequest.id))
        # except DhcpawnError as e:
        #     self.errors = e.args[0]
        #     return

        # if new_address:
        #     host.ip.address = new_address
        # if new_group:
        #     host.group = new_group
        # db.session.add(host)
        # db.session.commit()


    def delete_host(self, host):
        """
        method will receive a host instance
        rather then id or name
        """
        self.dtask = Dtask(self.drequest.id)
        self.res = task_host_ldap_delete.delay(host.id, self.dtask.id)
        self.msg = "Async ldap delete and db delete sent for %s" % host.name
        self.drequest_type = "delete host"
        # try:
        #     self.res = task_host_full_delete.delay(host.id, self.drequest.id)
        # except DhcpawnError as e:
        #     self.errors = "Failed removing LDAP entry for host %s ( e.args[0] )" % host.name
        #     # return err_json("Failed removeing LDAP entry for host %s ( e.args[0] )" % host.name)
        # return jsonify({'status':'ongoing',
        #                 'task_id': res.task_id})


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
            self.errors = e.args[0]
            return
        self.result = host.config()
        # return gen_resp(result=host.config(), msg="get specific host")
        # return jsonify(host.config())

    @gen_resp_deco
    @update_req
    def put(self, param):
        self.drequest_type = 'modify host'
        try:
            host = self.get_host_by_param(param)
        except DhcpawnError as e:
            self.errors = e.args[0]
            self.msg = 'did not get to the modify part. failed on getting the host to modify'
            return

        try:
            self.data = request.get_json(force=True)
        except BadRequest as e:
            self.errors = e.description
            self.msg = 'check that you actually provided the request info'
            return
        self.update_host(host)

    @gen_resp_deco
    @update_req
    def delete(self,param):
        try:
            host = self.get_host_by_param(param)
        except DhcpawnError as e:
            self.errors = e.args[0]
            return
        self.delete_host(host)

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
            return err_json("Group requires name")
        if Group.query.filter(Group.name == data.get('name')).all():
            return err_json("A Group with this name already exists")
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
        # return jsonify(dict(items=[group.config() for group in Group.query.all()]))

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
        except:
            pass
        else:
            self.errors = "A subnet with this name %s already exists" % data.get('name')
            return
        # if Subnet.query.filter_by(name=data.get('name')).all():
            # return err_json("A subnet with this name %s already exists" % data.get('name'))
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
            return err_json(e.args[0])
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

        calcrange = get_by_id(CalculatedRange, data.get('calcrange'))
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
                return err_json("Cannot deploy IP in non-deployed host or range")
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
        try:
            for ip in IP.query.all():
                db.session.delete(ip)
            db.session.commit()
            return jsonify("Cleared all ip records from DB")

        except:
            return jsonify("Failed removing all ip records from DB")

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
            # return err_json(e.args[0])
        # return jsonify(ip.config())

    @gen_resp_deco
    def put(self, param):
        _logger.debug("IPAPI")
        try:
            ip = self.get_ip_by_param(param)
        except DhcpawnError as e:
            return err_json(e.__str__())
        data = request.get_json(force=True)
        if any(key not in ['host', 'deployed'] for key in data):
            return err_json("IP PUT requests only accept host")

        if 'deployed' in data:
            deployed = data.get('deployed')
            if deployed:
                if ip.host_id:
                    host = get_by_id(Host, ip.host_id)
                    if not host.deployed:
                        return err_json("Cannot deploy IP as parameter of non-deployed host")

        if 'host' in data:
            try:
                host = get_by_field(Host, 'name', data.get('host'))
            except DhcpawnError as e:
                return err_json(e.args[0])

            if ip.host_id == host.id:
                return err_json("Host is already connected to this IP")

            ip.host_id = host.id

        if 'deployed' in data:
            ip.deployed = data.get('deployed')
        db.session.add(ip)
        db.session.commit()
        ip.ldap_add()
        return jsonify(ip.config())

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
        # ip.ldap_delete()
        # db.session.delete(ip)
        # db.session.commit()
        # self.result = [{ip.address:ip.config()} for ip in IP.query.all()]

# DHCP CLASSES

class DhcpRangeListAPI(MethodView):

    def get(self):
        ranges = DhcpRange.query.all()
        return jsonify(dict(items=[range.config() for range in ranges]))

    def post(self):
        data = request.get_json(force=True)
        if any(key not in data for key in ['min', 'max']):
            return err_json("Dhcp Range requires a min, and max")
        if all(key not in data for key in ['pool', 'pool_name']):
            return err_json("Dhcp Range requires a pool_id or a pool_name")

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
                return err_json("Range overlaps with existing ranges %s" % (iprange.id))

        range_ips = []
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
        return jsonify(dhcprange.config())


class DhcpRangeAPI(MethodView):

    def get(self, dhcp_range_id):
        pass

    def put(self, dhcp_range_id):
        pass

    def delete(self, dhcp_range_id):
        pass

# CALCULATED CLASSES

class CalculatedLRangeListAPI(MethodView):

    def get(self):
        ranges = CalculatedRange.query.all()
        return jsonify(dict(items=[range.config() for range in ranges]))

    def post(self):
        data = request.get_json(force=True)
        if any(key not in data for key in ['min', 'max']):
            return err_json("Calculated Range requires a min, and max")
        if all(key not in data for key in ['subnet', 'subnet_name']):
            return err_json("Calculated Range requires a subnet_id or subnet_name")
        ipmin = IPv4Address(data.get('min'))
        ipmax = IPv4Address(data.get('max'))

        if 'subnet' in data:
            subnet_id = data.get('subnet')
        else:
            subnet = get_by_field(Subnet, 'name', data.get('subnet_name'))
            subnet_id = subnet.id

        for iprange in CalculatedRange.query.all():
            if iprange.contains(ipmin) or iprange.contains(ipmax):
                return err_json("Range overlaps with existing ranges %s" % (iprange.id))
        calcrange = CalculatedRange(
            min=data.get('min'),
            max=data.get('max'),
            subnet_id=subnet_id
        )
        db.session.add(calcrange)
        db.session.commit()
        return jsonify(calcrange.config())


class CalculatedRangeAPI(MethodView):

    def get(self, calc_range_id):
        pass

    def put(self, calc_range_id):
        pass

    def delete(self, calc_range_id):
        pass

# POOL CLASSES

class PoolListAPI(MethodView):

    def get(self):
        pools = Pool.query.all()
        return jsonify(dict(items=[pool.config() for pool in pools]))

    def post(self):
        """ Create Pool but only in db
            only when we add a dhcpRange , we can deploy to ldap
        """
        data = request.get_json(force=True)
        if 'name' not in data:
            return err_json("Pool requires a name")
        if all(key not in data for key in ['subnet', 'subnet_name']):
            return err_json("Pool requires either a subnet id or a subnet name")

        if Pool.query.filter(Pool.name == data.get('name')).all():
            return err_json("A pool by this name already exists")

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
        return jsonify(pool.config())


class PoolAPI(MethodView):

    def get(self, pool_id):
        pool = get_by_id(Pool, pool_id)
        return jsonify(pool.config())

    def put(self, pool_id):
        """
        basically using this method to update dhcpRange
        and then deploy pool to ldap
        of course other changes may apply too
        """
        pool = get_by_id(Pool, pool_id)
        data = request.get_json(force=True)
        if 'deployed' in data:
            deployed = data.get('deployed')
            if deployed:
                if pool.subnet_id:
                    subnet = get_by_id(Subnet, pool.subnet_id)
                    if not subnet.deployed:
                        return err_json("Cannot deploy pool with non-deployed subnet")
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
        return jsonify(pool.config())

    def delete(self, pool_id):
        pool = get_by_id(Pool, pool_id)
        pool.ldap_delete()
        if pool.range:
            db.session.delete(pool.range)
        db.session.delete(pool)
        db.session.commit()
        return jsonify([pool.config() for pool in Pool.query.all()])


###### Help functions

# def is_ip_taken(ip):
#     ''' returns the IPv4address(ip) is its available. otherwise ,will raise Dhcpawnerror
#     with an explanatory msg'''
#     try:
#         res = IP.query.filter_by(address=ip).first()
#     except Exception as e:
#         raise DhcpawnError('something went wrong while looking for %s in DB (%s)' % (ip, e.args[0]))
#     else:
#         if res:
#             raise DhcpawnError('ip %s already taken' % ip)
#         else:
#             return IPv4Address(ip)

def identify_param(model, param, patterns):
    for ptype in patterns:
        for pat in patterns[ptype]:
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
        _logger.debug("multiple register")
        self.drequest_type = "Multiple Registration"
        self.data = request.get_json(force=True)
        deploy = "True"
        if 'deploy' in self.data:
            deploy = self.data.get('deploy')
            del self.data['deploy']
        if 'reply_url' in self.data:
            self.drequest_reply_url = self.data.get('reply_url')
            del self.data['reply_url']
        if deploy.lower()=="true":
            _logger.debug("DEPLOY=%s" % deploy)
            _logger.info(f"Data size: {len(self.data)}")
            # this is the day to day part of the code
            # validation is needed and all the rest of the flow
            try:
                validated_host_dict, remove_ips_on_fail = validate_data_before_registration(self.data)
            except DhcpawnError as e:
                self.errors = e.__str__()
                return
            except Exception as e:
                self.errors = e.__str__()
                self.msg = "Encountered an unexpected exception"
                return
            # if we got here , all entries got their ips and we can commit to DB and
            # add to LDAP
            remove_hosts_on_fail = []
            tasks_group = []
            dtasks_group = []
            for su in validated_host_dict.keys():
                for hst in validated_host_dict[su].keys():
                    db.session.add(validated_host_dict[su][hst])
                    remove_hosts_on_fail.append(validated_host_dict[su][hst])
                    try:
                        _logger.debug("Commiting host %s to DB" % validated_host_dict[su][hst].name)
                        db.session.commit()
                    except Exception as e:
                        _logger.error(e.__str__())
                        db.session.rollback()
                        # clear_ips(remove_ips_on_fail)
                        # clear_hosts(remove_hosts_on_fail)
                        self.errors = e.__str__()
                        self.msg = "Aborted request"
                        # raise DhcpawnError(e.__str__())
                    except Exception as e:
                        _logger.error("Unexpected exception %s" % e.__str__())
                        self.errors = e.args[0]
                        return
                        # TODO: unexpected exception and i continue ????? WTF
                    try:
                        # validated_host_dict[su][hst].ldap_add()
                        dtasks_group.append(Dtask(self.drequest.id))
                        tasks_group.append(task_host_ldap_add.s(validated_host_dict[su][hst].id,
                                                                dtasks_group[-1].id))
                        # try:
                        #     validated_host_dict[su][hst].ldap_add()
                        # except Exception as e:
                        #     import pudb;pudb.set_trace()
                    except ALREADY_EXISTS as e:
                        self.errors = e.__str__()
                        self.msg = "Aborting Request: a host with these params already exists in LDAP (%s)" % validated_host_dict[su][hst].config()
                        # db.session.rollback()
                        clear_ips(remove_ips_on_fail)
                        clear_hosts(remove_hosts_on_fail)
                        return
                    except Exception as e:
                        self.errors = e.__str__()
                        clear_ips(remove_ips_on_fail)
                        clear_hosts(remove_hosts_on_fail)
                        return

                    if isinstance(self.result, dict):
                        self.result.update({hst:validated_host_dict[su][hst].config()})
                    else:
                        self.result = {hst:validated_host_dict[su][hst].config()}
                        _logger.debug("updating drequest result")

            # send all ldap actions to celery
            # tasks_group.append(task_check_drequest_status.s(self.drequest.id))
            job = group(tasks_group)
            try:
                self.res = job.apply_async()
                self.msg = "Registration to DB Finished. ldap async part is running. stay tuned.."
            except Exception as e:
                self.errors = e.__str__()
                self.msg = "Registration failed ,please check the errors part"
                clear_ips(remove_ips_on_fail)
                clear_hosts(remove_hosts_on_fail)
                # clear_hosts(validated_host_dict[su][hst])
                return

        else:
            _logger.info("Registring entries only in DB ,no LDAP update")
            # quick registration mode - simply writing all records to DB.
            # DB-ldap sync will happen later
            # validated_host_dict, _ = register_in_db_no_validation(data)
            try:
                validated_host_dict, _ = validate_data_before_registration(self.data)
            except DhcpawnError as e:
                _logger.error("Failed registration (%s)" % e.__str__())
                self.errors = e.__str__()
                self.msg = "Failed registration"
                return
            else:
                for su in validated_host_dict:
                    for hst in validated_host_dict[su]:
                        db.session.add(validated_host_dict[su][hst])
                        try:
                            db.session.commit()
                            # _logger.info("Finished quick db registration")
                        except Exception as e:
                            _logger.error("Quick mode - got an unexpected error, please check yml syntax and db duplications")
                            self.errors = "Failed quick db registration mode"


    @gen_resp_deco
    @update_req
    def delete(self):
        _logger.info("multiple delete")
        self.drequest_type = "Multiple Deletion"
        self.data = request.get_json(force=True)
        deploy = False
        hard = False
        if 'deploy' in self.data:
            deploy = self.data.get('deploy')
            del self.data['deploy']
        if 'reply_url' in self.data:
            self.drequest_reply_url = self.data.get('reply_url')
            del self.data['reply_url']
        if 'hard' in self.data:
            del self.data['hard']
            hard = True

        if hard:
            self.msg = "Performing hard delete by hostname"
            _logger.warning(self.msg)
            try:
                hard_delete(self.data)
            except DhcpawnError as e:
                raise DhcpawnError('Failed hard delete (%s)' % e.__str__())
            else:
                return

        try:
            validated_host_dict = validate_data_before_deletion(self.data)
        except DhcpawnError as e:
            self.errors = e.__str__()
            return
        except Exception as e:
            self.errors = e.__str__()
            self.msg = "Encountered an unexpected exception"
            return

        tasks_group = []
        dtasks_group = []

        for h in validated_host_dict:
            dtasks_group.append(Dtask(self.drequest.id))
            tasks_group.append(task_host_ldap_delete.s(validated_host_dict[h].id, dtasks_group[-1].id))
            if isinstance(self.result, dict):
                self.result.update({h:validated_host_dict[h].config()})
            else:
                self.result = {h:validated_host_dict[h].config()}

        job = group(tasks_group)
        try:
            self.res = job.apply_async()
            self.msg = 'Async deletion is running. stay tuned..'
        except Exception as e:
            self.errors = e.__str__()
            self.msg = "Deletion failed ,please check the errors part"



#### HELP FUNCTIONS
def hard_delete(data):
    """ for cases we have dirty data, i.e hostnames in ldap but not in DB,
    the regular validate before delete wont work"""
    for h in data:

        name = data[h]['hostname']
        mac = data[h]['mac']
        group = data[h]['group']
        _hard_delete_by_name(name, group)
        # _hard_delete_by_mac(mac)

def _hard_delete_by_name(name,  group):
    try:
        host = Host.query.filter_by(name=name).first()
        # _logger.debug("LDAP hard delete by name %s" % host.config())
        if host == None:
            raise ValueError
    except ValueError:
        host = Host(name=name,
                    group = Group.validate_by_name(group),
                    group_id = Group.validate_by_name(group).id,
                    deployed=True)
    finally:
        try:
            host.ldap_delete()
            _logger.info("LDAP hard delete %s" % host.dn())
            db.session.delete(host)
            db.session.commit()
        except Exception as e:
            _logger.warning("Failed hard delete for %s (%s)" % (name, e.__str__()))
            try:
                db.session.rollback()
            except:
                pass

def _hard_delete_by_mac(mac):
    try:
        host = Host.query.filter_by(mac=mac).first()
        _logger.debug("DB hard delete by mac %s" % host.config())
        host.ldap_delete()
        db.session.delete(host)
        db.session.commit()
    except:
        pass

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
        _logger.debug("validate %s: %s" % (h, hdata))
        try:

            # host, group, subnet, ip = single_input_validation(hdata)
            host, group, subnet, ip = Host.single_input_validate_before_registration(hdata)
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
                    ip = alloc_single_ip(subnet, ip)
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
        except DhcpawnError:
            # clear_ips(remove_ips_on_fail)
            # clear_hosts(remove_hosts_on_fail)
            raise
    return validated_host_dict, remove_ips_on_fail

def validate_data_before_deletion(data):
    ''' date should include hostname mac and group to be deleted '''
    validated_host_dict = dict()
    for h in data.keys():
        hdata = data.get(h)
        try:
            host = Host.single_input_validate_before_deletion(hdata)
        except DhcpawnError as e:
            raise
        else:
            validated_host_dict[h] = host

    return validated_host_dict

def alloc_single_ip(su, addr=None):
    """
    go over subnet calculated ranges and find a free ip if addr=None
    or check if the specific address is free to allocate
    :param su: subnet in which the ip should be
    :param addr: if a specific address in needed otherwise its find first free ip in subnet
    :return: ip database inst
    """
    for cr_id in subnet_get_calc_ranges(su):
        try:
            if addr == 'allocate':
                ip = su.allocate_free_ip()
            else:
                return IP.allocate_specific_ip(addr)
        except DhcpawnError as e:
            _logger.error(e.__str__())
            raise DhcpawnError("Failed allocating ip %s" % addr)
        return ip

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
            _logger.error("Failed removing %s from DB" % ip.address)
            pass
            # raise DhcpawnError(e.description)

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
            except Exception as e:
                _logger.warning("Failed while cleaning LDAP after failure %s (%s)" % (host.name, e.__str__()))
                pass
            db.session.delete(host)
            db.session.commit()
            _logger.info("Clear Hosts - Removed %s" % name)
        except SQLAlchemyError as e:
            _logger.error("Failed while cleaning %s after failure (%s)" % (name, e.__str__()))
            pass
            # raise DhcpawnError(e.__str__())
        _logger.info("Cleaned all remainders of %s from LDAP/DB" % name)

    _logger.info("Finished removing hosts from DB after fail")


### Sync

class Sync(DhcpawnMethodView):

    # def __init__(self):
    #     self.d = dict()

    @gen_resp_deco
    def get(self, group_name=None, sync=False):
        """
            function find diffs between ldap and db.
            1. can be run as a standalone request (if one wants to know what are the current diffs),
               and can only check all groups and not a specific group
            2. can be the first part of a sync request thus request data is given to the POST req and
               post function will transfer any relevant data to get function.

            for now we only have hosts sync (the assumption is that groups/subnets will not
            differ)

            :return: returns diff status
            """
        # self.drequest_type = "get sync status"
        self.d = dict([('hosts', {}),
                       ('groups', {}),
                       ('subnets', {})])

        if group_name:
            try:
                gr = Group.validate_by_name(group_name)
            except DhcpawnError as e:
                self.errors = e.__str__()
            except Exception as e:
                self.errors = e.__str__()
            else:
            # gr = get_by_field_or_404(Group, 'id', group_id)
                self.msg = "Evaluating group sync status for %s" % gr.name
                _logger.info(self.msg)

                # dtask = Dtask(self.drequest.id)
                # self.res = task_get_group_sync_stat.delay(gr.name, dtask.id)
                # self.msg = "get sync stat request for %s running async" % group_name
                try:
                    self.d['hosts'][gr.name] = gr.get_sync_stat()
                except DhcpawnError as e:
                    self.errors = e.__str__()
                    self.msg = "Failed getting sync status for group %s" % group_name
                    return
        else: # get sync stat for all groups
            # tasks_group = []
            self.msg = "Evaluate sync stat for all groups"
            for gr in Group.query.all():
                _logger.debug("Evaluating group sync status for %s" % gr.name)
            #     dtask = Dtask(self.drequest.id)
            #     tasks_group.append(task_get_group_sync_stat.s(gr.name, dtask.id))

            # job = group(tasks_group)
            # try:
            #     self.res = job.apply_async()
            #     self.msg = "Get sync status for all groups will run asynchronously"
            # except Exception as e:
            #     self.errors = e.__str__()
            #     self.msg = "Failed sending async job for all groups get sync stat"
                try:
                    self.d['hosts'][gr.name] = gr.get_sync_stat()
                except Exception as e:
                    self.errors = e.__str__()
                    self.msg = "Failed getting sync status for all groups (failing group is %s)" % gr.name
                    return

        self.result = self.d

    def post(self, group_id=None):
        """
        USED
        sync db->ldap direction meaning we make sure ldap looks exactly as db.
        :return:
        """

        if group_id:
            # need to fix next line - either find group name from group_id or change seld.get
            # method to use group_id
            self.get(group_name=group_id, sync=True) # self.d is created/updated
        else:
            self.get(sync=True)
        no_diff = True
        for g in self.d['hosts']:
            if not self.d['hosts'][g]['group is synced']:
                no_diff = False
                break
        if no_diff:
            return value_by_context(["No Diffs in {}".format(g) for g in self.d['hosts']])
        host_stat_dict = self.hosts_sync(self.d['hosts'])
        return value_by_context({'pre sync': {k:v for k,v in self.d['hosts'].items() if not v['group is synced']},
                                 'post sync': {k:v for k,v in host_stat_dict.items() if v} })

    def hosts_sync(self, host_diffs):
        """
        hosts_diff dict contains two dicts:
            content diffs
            amount diffs
        :param hosts_diff:
        :return:
        """
        stat_dict = {}
        for grp in host_diffs:
            stat_dict.setdefault(grp,{})
            if not host_diffs[grp]['group is synced']:
                gr = get_by_field(Group, 'name', grp)
                if host_diffs[grp].get('only in db'):
                    stat_dict[grp].setdefault('added to ldap', [])
                    for host2sync in host_diffs[grp]['only in db']:
                        _logger.debug("Creating missing host %s in LDAP (found only on DB)" % host2sync)
                        host = get_by_field(Host, 'name', host2sync)
                        host.ldap_add()
                        stat_dict[grp]['added to ldap'].append(host2sync)

                if host_diffs[grp].get('only in ldap'):
                    stat_dict[grp].setdefault('deleted from ldap', [])
                    for host2sync in host_diffs[grp]['only in ldap']:
                        _logger.debug("Deleting extra host %s from LDAP (found only on LDAP)" % host2sync)
                        extra_host_dn = "cn=%s,%s" % (host2sync, gr.dn())
                        ldap_extra_host_dn = gr.ldap_get(extra_host_dn)
                        if ldap_extra_host_dn:
                            gr.ldap_delete(ldap_extra_host_dn[0][0])
                            stat_dict[grp]['deleted from ldap'].append(host2sync)

                if host_diffs[grp].get('content'):
                    stat_dict[grp].setdefault('updated in ldap', [])
                    for hdict in host_diffs[grp]['content']['diff per host']:
                        for host2sync in hdict:
                            host = get_by_field(Host, 'name', host2sync)
                            host.ldap_modify()
                            stat_dict[grp]['updated in ldap'].append(host2sync)

        return stat_dict
