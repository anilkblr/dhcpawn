# cob: type=models
import json
from ipaddress import IPv4Address, IPv4Network
import requests
import logbook

from flask import current_app
from ldap import modlist, SCOPE_SUBTREE, NO_SUCH_OBJECT, LDAPError

from sqlalchemy_utils import IPAddressType
from sqlalchemy.exc import IntegrityError
from cob import db

# from .ldap_utils import server_dn
from .help_functions import _get_or_none, get_by_field, parse_ldap_entry, extract_skeleton
from .help_functions import DhcpawnError, ValidationError, IPAlreadyExists, BadSubnetName,\
    DoNothingRecordExists, DuplicateError, ConflictingParamsError, DoNothingRecordNotInDB,\
    InputValidationError

_logger = logbook.Logger(__name__)

def gen_modlist(obj_dict, options):
    """ create a modlist in order to change entry in LDAP"""
    if options:
        options = json.loads(options)
        boptions = {}
        for option in options:
            boptions[option] = []
            for o in options[option]:
                if isinstance(o, str):
                    boptions[option].append(o.encode('utf-8'))
                elif isinstance(o, list):
                    tmpl = []
                    for _o in o:
                        tmpl.append(_o.encode('utf-8'))
                    boptions[option].append(tmpl)
        obj_dict.update(boptions)
    return obj_dict

class LDAPModel(db.Model):
    __abstract__ = True

    def __eq__(self, name):
        if isinstance(name, str):
            if isinstance(self, Subnet):
                return json.loads(self.options).get('dhcpComments')[0] == name

            return self.name == name
        return False

    def dn(self):
        return ''

    def modlist(self):
        return dict()

    def ldap_retry(self, cmd_type=None, dn=None, parse=None):
        '''
        ldap retry code + exceptions handling
        cmd_type param: add, delete, get
        '''
        if cmd_type == 'add':
            ldapcmd = current_app.ldap_obj.add_s
            ldapcmd_args = modlist.addModlist(self.modlist())
        elif cmd_type == 'delete':
            ldapcmd = current_app.ldap_obj.delete_s
            ldapcmd_args = None
        elif cmd_type == 'get':
            ldapcmd = current_app.ldap_obj.search_s
            ldapcmd_args = SCOPE_SUBTREE
        else:
            raise DhcpawnError(f"Wrong command type given {cmd_type}")
        if not dn:
            dn = self.dn()
        if self.deployed:
            e = None
            try:
                if ldapcmd_args is None:
                    res = ldapcmd(dn)
                else:
                    res = ldapcmd(dn, ldapcmd_args)

                if cmd_type == 'get' and parse:
                    return parse_ldap_entry(res)
                return res

            except LDAPError as e:
                _logger.debug(e.__str__())
                raise
            else:
                return res

    def ldap_add(self):
        #raise DhcpawnError("prevent ldap_add from running")
        try:
            self.ldap_retry(cmd_type='add', dn=self.dn())
        except LDAPError:
            raise

    def ldap_delete(self):
        # raise RuntimeError("prevent ldap_delete from running")
        try:
            self.ldap_retry(cmd_type='delete', dn=self.dn())
        except LDAPError:
            raise

    def ldap_get(self, dn=None, parse=False):
        return self.ldap_retry(cmd_type='get', dn=dn, parse=parse)

    def ldap_modify(self, dn=None):
        raise RuntimeError("prevent ldap_modify from running")
        # if not dn:
        #     dn = self.dn()
        # _logger.debug("Modify LDAP entry: %s" % dn)
        # if self.deployed:
        #     try:
        #         # data taken from ldap
        #         objs = current_app.ldap_obj.search_s(dn, SCOPE_BASE)
        #         _logger.debug("Current data in DB: %s" % self.config())
        #         _logger.debug("Current DN in LDAP: %s" % str(objs[0][1]))
        #         if objs[0][1] != dict(self.modlist()):
        #             current_app.ldap_obj.modify_s(dn, modlist.modifyModlist(objs[0][1], dict(self.modlist())))
        #     except NO_SUCH_OBJECT:
        #         self.ldap_add()


    @classmethod
    def validate_by_name(cls, name):
        for inst in cls.query.all():
            if inst.name == name:
                return inst

        if isinstance(cls(), Subnet):
            try:
                return Subnet.get_name_by_dhcpcomment_name(name)
            except DhcpawnError:
                raise ValidationError("There is no subnet with name %s" % name)

        raise ValidationError("No matching db instance with this name %s" % name)


    def __repr__(self):
        if hasattr(self.__class__, 'name'):
            return f"<{self.__class__.__name__} : {self.name}>"
        else:
            return f"<{self.__class__.__name__}>"

#LDAP Models

class Host(LDAPModel):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    mac = db.Column(db.String(100), unique=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    ip = db.relationship('IP', backref='host', uselist=False)
    options = db.Column(db.Text)
    deployed = db.Column(db.Boolean, default=True)

    def dn(self):
        if self.group_id:
            return 'cn=%s,%s' % (self.name, self.group.dn())
        # return 'cn=%s,ou=Hosts,%s' % (self.name, server_dn())

    def modlist(self):
        options = json.loads(self.options) if self.options else {}
        if self.ip and self.ip.deployed:
            if not options.get('dhcpStatements'):
                options['dhcpStatements'] = []
            options['dhcpStatements'] += ['fixed-address %s' % str(self.ip.address)]
            options = json.dumps(options)
        return gen_modlist(dict(objectClass=[b'dhcpHost', b'top'], \
                                dhcpHWAddress=[b'ethernet %s' % \
                                               self.mac.encode('utf-8')], \
                                cn=[self.name.encode('utf-8')]), options)

    def config(self):
        return dict(id=self.id,
                    dn=self.dn(),
                    name=self.name,
                    mac=self.mac,
                    ip_id=self.ip.id if self.ip else None,
                    ip=self.ip.address.__str__() if self.ip else None,
                    subnet=self.subnet().__str__() if self.subnet() else None,
                    group=self.group_id,
                    group_name=self.group.name,
                    options=json.loads(self.options) if self.options else None,
                    deployed=self.deployed)

    def subnet(self):

        if isinstance(self.ip, IP) and isinstance(self.ip.calculatedrange, CalculatedRange):
            return self.ip.calculatedrange.subnet

    @staticmethod
    def get_by_hostname(hostname):
        host = Host.query.filter_by(name=hostname).first()
        if host:
            return host
        return None

    @staticmethod
    def get_by_mac(mac):
        host = Host.query.filter_by(mac=mac).first()
        if host:
            return host
        return None

    @staticmethod
    def look_for_existing_host(**kwargs):
        ''' cases to handle:
        1. kwargs consist all data (group, ip, subnet, hostname) and i found the same record in db
        2. kwargs consists all but ip (ip is empty becuase in infinilab there is no ip for some reason)
           in this case we should set the ip in infinilab to have the same ip in dhcpawn db
        3.
        '''
        host = Host.query.filter_by(name=kwargs.get('hostname')).first()
        if host and host.group.name == kwargs.get('group'):
            # if host.name == 'box-sivan-test-nas1-1':
            if host.ip and (host.ip.address.compressed == kwargs.get('ip') \
                            or kwargs.get('ip') is None and host.ip.address.compressed):
                return True

        return False
###########################################################
    @staticmethod
    def validate_host_before_deletion(**kwargs):
        # kwargs are expected to be identical to the actual record
        # in DB. otherwise we can't know we delete the right host.
        host = Host.query.filter_by(name=kwargs.get('hostname')).first()
        if not host:
            raise DoNothingRecordNotInDB(f"host by hostname {kwargs.get('hostname')} not in DB.")

        if not Host._check_identical(host, **kwargs):
            raise ConflictingParamsError(f"host {kwargs.get('hostname')} in request differs from record in DB")

        return host

    @staticmethod
    def validate_new_host_before_registration(**kwargs):
        _logger.debug(f"validating {kwargs}")
        if any(key not in kwargs for key in ['hostname', 'mac', 'group', 'subnet', 'ip']):
            raise ValidationError("Mandatory hostname, mac, group, subnet or ip missing in this record %s" % kwargs)
        try:
            mac = Host._unique_mac(kwargs.get('mac'))
            group = Group.validate_by_name(kwargs.get('group'))
            subnet, ip = Host._ip_subnet_validation(**kwargs)
        except (ValidationError, IPAlreadyExists, BadSubnetName) as e:
            raise ValidationError(e.__str__())
        else:
            if subnet or ip:
                if ip == '' or ip is None:
                    ip = 'allocate'
                host = Host(name=kwargs.get('hostname'),
                            mac=mac,
                            group_id=group.id,
                            ip=Subnet.alloc_single_ip(subnet, ip))

            else:
                host = Host(name=kwargs.get('hostname'),
                            mac=mac,
                            group=group)
            return host
    @staticmethod
    def validate_existing_host_before_registration(**kwargs):

        try:
            return Host._compare_existing_to_request(**kwargs)
        except ValidationError:
            raise

    @staticmethod
    def _unique_mac(mac):

        if Host.query.filter_by(mac=mac).first():
            raise ValidationError(f"Mac {mac} already in DB")

        return mac

    @staticmethod
    def _ip_subnet_validation(**kwargs):
        ''' there are 4 options for subnet,ip existance in request:
        00 - subnet/ip not in request - nothing to do ,no ip allocation
             (this is not supported, at least subnet shoudl be part )
        01 - only ip in request ,check its not taken and later
             find its subnet and update host with both after allocation
        10 - validate subnet by name and allocate ip in it
        11 - check if ip is taken and if ip is in subnet
        '''
        rsubnet = kwargs.get('subnet')
        rip = kwargs.get('ip')
        if (rip is None or rip == '') and (rsubnet is None or rsubnet == ''):
            return None, None

        if rsubnet:
            try:
                subnet = Subnet.validate_by_name(rsubnet)
            except ValidationError as e:
                raise BadSubnetName(e.__str__())

        if rip and IP.query.filter_by(address=rip).first():
            raise IPAlreadyExists(f"IP {rip} already in DB")

        if rip and rsubnet is None:
            subnet = IP.get_subnet(rip)

        if rip and rsubnet:
            if not IP.ip_in_subnet(rip, rsubnet):
                raise ValidationError(f"IP {rip} is not in subnet {subnet}")

        return subnet, rip

    @staticmethod
    def _compare_existing_to_request(**kwargs):
        new_mac = ''
        new_group = ''
        new_ip = ''

        host = Host.query.filter_by(name=kwargs.get('hostname')).first()
        if Host._check_identical(host, **kwargs):
            raise DoNothingRecordExists

        if not host.mac == kwargs.get('mac') and Host._unique_mac(kwargs.get('mac')):
            new_mac = kwargs.get('mac')
            # host.mac = kwargs.get('mac') # update db with the new mac


        if not host.group == kwargs.get('group'):
            _logger.debug(f"Updating group for host {host}: {host.group} --> {kwargs.get('group')}")
            new_group = Group.validate_by_name(kwargs.get('group'))
            # host.group = Group.validate_by_name(kwargs.get('group'))

        if not host.subnet() == kwargs.get('subnet') or (not host.ip == kwargs.get('ip')):
            try:
                _, _ = Host._ip_subnet_validation(**kwargs)
            except BadSubnetName as e:
                raise ValidationError(e.__str__())
            except IPAlreadyExists as e:
                if host.ip.address.compressed == kwargs.get('ip'):
                    pass
                else:
                    raise ValidationError(e.__str__())
            finally:
                if not host.subnet() == kwargs.get('subnet'):
                    if host.ip:
                        # subnet changed , delete current ip from db and allocate
                        # new one in the new subnet
                        db.session.delete(host.ip)
                    if kwargs.get('subnet') is None:
                        new_ip = None
                    else:
                        wanted_subnet = Subnet.validate_by_name(kwargs.get('subnet'))
                        new_ip = Subnet.alloc_single_ip(wanted_subnet, 'allocate')
                    # host.ip = Subnet.alloc_single_ip(wanted_subnet, 'allocate')
                # if ip == '':
                #     host.ip = Subnet.alloc_single_ip(subnet, 'allocate')
                # else:
                #     host.ip = Subnet.alloc_single_ip(subnet, ip)

        return new_mac, new_group, new_ip

    @staticmethod
    def _check_identical(host, **kwargs):
        if host.name == kwargs.get('hostname') and \
            host.mac == kwargs.get('mac') and \
            host.group == kwargs.get('group') and \
            (host.subnet() == kwargs.get('subnet') or \
             (host.subnet() is None and kwargs.get('subnet') == 'None')) and \
            host.ip == kwargs.get('ip'):
            return True

        return False

#############################################################

    @staticmethod
    def hostname_mac_coupling_check(**kwargs):
        ''' check that for hostname and mac ,either both are new
        or both exist in DB and are coupled.
        if None returned: just create new host with this mac.
        if host returned: use it to update entry in DB if needed
        else we raise exception'''
        hostname = kwargs.get('hostname')
        mac = kwargs.get('mac')
        host_by_hostname = Host.get_by_hostname(hostname)
        host_by_mac = Host.get_by_mac(mac)
        if host_by_hostname and host_by_mac:
            if host_by_hostname == host_by_mac:
                # both hostname and mac exist in DB and belong to the same entry.
                return host_by_hostname
            else:
                raise InputValidationError("hostname %s and mac %s \
                belong to two different entries in DB " % (hostname, mac))
        elif not host_by_hostname and not host_by_mac:
            # no record in DB with this hostname or mac
            return None

        if not kwargs.get('create_duplicate_record'):
            found_duplication_desc = ''
            duptype = None
            if host_by_hostname:
                found_duplication_desc = f"Existing host in DB with same hostname {hostname}."
                duptype = 'hostname'
            if host_by_mac:
                found_duplication_desc += f" Existing host in DB with mac {mac}. the hostname is {host_by_mac.name}"
                duptype = 'mac'

            Duplicate(f"Verifying {hostname} and {mac}. \
            Found {found_duplication_desc}", duptype)

        _logger.error("hostname/mac coupling check failed. \
        only one of them exist in DB (host_by_hostname: %s, host_by_mac: %s " % \
                      (host_by_hostname, host_by_mac))
        raise DuplicateError("Found duplication")

    @staticmethod
    def mac_group_validation(**kwargs):
        try:
            host = Host.hostname_mac_coupling_check(**kwargs)
        except ValidationError:
            raise
        try:
            group = Group.validate_by_name(kwargs.get('group'))
        except ValidationError:
            raise
        return host, group

    # @staticmethod
    # def ip_subnet_validation(**kwargs):
    #     req_subnet = kwargs.get('subnet')
    #     req_ip = kwargs.get('ip')
    #     h = Host.get_by_hostname(kwargs.get('hostname'))
    #     if host:
    #     # first check if we already have the host in DB with
    #     # the required ip
    #         if host.ip:
    #             if host.ip.address.commpressed == req_ip:
    #                 ip = host.ip

    #                 if req_subnet:
    #                     subnet = Subnet.validate_by_name(req_subnet)
    #             else:
    #                 subnet = IP.get_subnet(req_ip)
    #         return ip, subnet

    #     if req_subnet and req_ip: # todo verify that ip in subnet and not taken
    #         try:
    #             IP.is_ip_taken(req_ip)
    #         except ValidationError:
    #             raise
    #         else:
    #             try:
    #                 if IP.ip_in_subnet(req_ip, req_subnet):
    #                     ip = req_ip
    #                     subnet = Subnet.validate_by_name(req_subnet)
    #                 else:
    #                     raise ValidationError("IP %s does not belong to subnet %s" % (req_ip, req_subnet))
    #             except DhcpawnError:
    #                 raise
    #     elif req_subnet and not req_ip: # todo just verify subnet and ip will be allocated
    #         try:
    #             subnet = Subnet.validate_by_name(req_subnet)
    #         except ValidationError:
    #             raise
    #         else:
    #             ip = "allocate"
    #     elif not req_subnet and req_ip: # todo check if ip taken and if not ,calulate subnet and allocate
    #         try:
    #             IP.is_ip_taken(req_ip)
    #         except ValidationError:
    #             raise
    #         else:
    #             ip = req_ip
    #             subnet = IP.get_subnet(req_ip)
    #     else:
    #         subnet = None
    #         ip = None

    #     return ip, subnet

    # @staticmethod
    # def single_input_validate_before_registration(*args, **kwargs):
    #     ''' validate before registration, get single host creation inputs:
    #     hostname, mac, group, subnet, ip, and make sure its a valid request'''
    #     if any(key not in kwargs for key in ['hostname', 'mac', 'group']):
    #         raise ValidationError("Mandatory hostname, mac or group missing in this record %s" % kwargs)

    #     # trying to look for an existing host with same data
    #     # try:
    #     #     if Host.look_for_existing_host(**kwargs):
    #     #         raise DoNothingRecordExists
    #     # except DoNothingRecordExists:
    #     #     raise
    #     # except ValidationError:
    #     #     raise

    #     try:
    #         host, group = Host.mac_group_validation(*args,**kwargs)
    #     except ValidationError:
    #         raise
    #     else:
    #         try:
    #             ip, subnet = Host.ip_subnet_validation(*args, **kwargs)
    #         except DhcpawnError:
    #             raise
    #     return host, group, subnet, ip

    @staticmethod
    def get_by_ip(ipaddr):
        '''
        if ip is taken ,return the related host
        '''
        ip = IP.query.filter_by(address=IPv4Address(ipaddr)).first()
        if ip:
            return Host.query.get(ip.host)

    @staticmethod
    def create(**kwargs):
        ''' Host method to create new host '''
        if any(key not in kwargs for key in ['hostname', 'mac', 'group']):
            raise DhcpawnError('Host requires name, mac and group')

        if Host.query.filter(Host.mac == kwargs.get('mac')).all():
            existing_hosts = Host.query.filter(Host.mac == kwargs.get('mac')).all()
            Duplicate(f"A host with this MAC {(kwargs.get('mac'))} already exists \
            {[e.name for e in existing_hosts]} while trying to create host \
            {kwargs.get('hostname')}", 'mac')
            raise DhcpawnError('Duplicate MAC (%s) ' % kwargs.get('mac'))

        name=kwargs.get('hostname')
        mac=kwargs.get('mac')
        group=Group.validate_by_name(kwargs.get('group'))
        opts=json.dumps(kwargs.get('options',{}))
        deployed = kwargs.get('deployed', True)
        if deployed and not group.deployed:
            raise DhcpawnError('Cannot deploy host as subobject of non-deployed group')
        if kwargs.get('ip'):
            try:
                ip = IP.is_ip_taken(kwargs.get('ip'))
                ip_inst = IP(address=ip)

                db.session.add(ip_inst)
                db.session.commit()
            except DhcpawnError as e:
                errmsg = f"new host {name} has duplicate ip {kwargs.get('ip')} ({e.__str__()})  "
                Duplicate(errmsg, 'ip')
                raise DhcpawnError(errmsg)
        else:
            ip_inst = None

        h = Host(
            name=name,
            mac=mac,
            group=group,
            options=opts,
            deployed=deployed,
        )

        db.session.add(h)
        db.session.commit()
        if ip_inst:
            ip_inst.host = h
            cr = IP.get_calcrange(kwargs.get('ip'))
            dr = IP.get_dhcprange(kwargs.get('ip'))
            if cr:
                ip_inst.calcrange_id = cr.id
            elif dr:
                ip_inst.dhcprange_id = dr.id
            else:
                _logger.error(f"Failed deploying IP {kwargs.get('ip')} for host {name}")

            db.session.add(ip_inst)
            db.session.commit()

        return h.id

    # @staticmethod
    # def single_input_validate_before_deletion(*args, **kwargs):
    #     ''' simply make sure hostname really has the mac we got and
    #     belong to the provided group'''

    #     try:
    #         host, _ = Host.mac_group_validation(**kwargs)
    #     except DhcpawnError:
    #         raise

    #     if not host:
    #         raise DhcpawnError("No host with these params %s" % kwargs)

    #     try:
    #         host.validate_db_vs_ldap()
    #     except DhcpawnError as e:
    #         _logger.error(e.__str__())
    #         raise

    #     return host

    def validate_db_vs_ldap(self):
        """take DB entry and compare to LDAP
        compare mac and ip
        """
        ldap_entry = self.ldap_get(parse=True)
        ldap_mac = ldap_entry[self.name]['mac']
        ldap_ip = ldap_entry[self.name]['ip']
        if not ldap_mac == self.mac:
            raise DhcpawnError('%s- DB-LDAP validation failed - mac addresses are different (DB: %s , LDAP: %s)' % (self.name, self.mac, ldap_mac))
        if not ldap_ip == self.ip.address.compressed:
            raise DhcpawnError('%s- DB-LDAP validation failed - ip addresses are different (DB: %s , LDAP: %s)' % (self.name, self.ip.address, ldap_ip))


    def update(self, **kwargs):
        ''' Host modify method '''
        changed = False
        new_address_id = None
        new_group_id = None
        if not kwargs.get('mac'): # mac / hostname correspondance
            raise DhcpawnError("no mac address provided")

        try:
            name_by_mac = get_by_field(Host, 'mac', kwargs.get('mac')).name
        except DhcpawnError:
            raise

        if not name_by_mac == self.name:
            raise DhcpawnError("Provided mac %s doesn't match the hostname %s" % (kwargs.get('mac'), self.name))


        if 'ip' in kwargs:
            if not self.ip or self.ip and not self.ip.address == kwargs.get('ip'):
                try:
                    new_address = IP.allocate_specific_ip(kwargs.get('ip'))
                    new_address_id = new_address.id
                    changed = True
                except DhcpawnError:
                    raise

        if 'group' in kwargs and not self.group.name == kwargs.get('group'):
            changed = True
            try:
                new_group = get_by_field(Group, 'name', kwargs.get('group'))
                new_group_id = new_group.id
            except DhcpawnError:
                raise

        if 'deployed' in kwargs and not self.deployed == kwargs.get('deployed'):

            # changing deployment status:
            # current False -> True : meaning we want it to be deployed to LDAP
            # current True -> False : meaning we want to remove from LDAP ??? dont support for now.
            if self.deployed == False and kwargs.get('deployed') == "True":
                changed = True
                self.deployed = True
            else:
                raise DhcpawnError("Trying to change deployment status from True to False - not supported for now")
        if self.deployed and not self.group.deployed:
            raise DhcpawnError("Cannot deploy host as subobject of non-deployed group")

        if not changed:
            raise DhcpawnError('no real error - just nothing to change')

        return new_group_id, new_address_id

    def delete(self):
        if self.ip:
            db.session.delete(self.ip)
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def drequest_ldap_add(hid, dtask_id, current_tid):
        ''' after creating new host in db
        run async task to udpate LDAP
        hid = host id
        dreq_id = the related dhcpawn request id
        '''
        # current_tid = self.request.id # task_id of the task we are in

        host = Host.query.get(hid)
        dtask = Dtask.query.get(dtask_id)
        try:
            host.ldap_add()
        except LDAPError:
            dtask.update(
                status= 'failed',
                desc= 'ldap add host %s' % host.name,
                celery_task_id= current_tid
            )
            host.delete()
            raise
        else:
        # _logger.debug(f"Success {dtask_id} for host {host.name}")

            dtask.update(
                status= 'succeeded',
                desc= 'ldap add host %s' % host.name,
                celery_task_id= current_tid
            )
        finally:
            dreq = Req.query.get(dtask.dreq_id)
            dreq.refresh_status()

    @staticmethod
    def drequest_ldap_delete(hid, dtask_id, current_tid):
        ''' after creating new host in db
        run async task to udpate LDAP
        hid = host id
        dreq_id = the related dhcpawn request id
        '''
        # current_tid ע= self.request.id # task_id of the task we are in

        host = Host.query.get(hid)
        dtask = Dtask.query.get(dtask_id)
        try:
            _logger.info(f"deleting host {host.name} from ldap")
            host.ldap_delete()
        except LDAPError:
            dtask.update(
                status= 'failed',
                desc= 'ldap delete host %s' % host.name,
                celery_task_id= current_tid
            )
        else:
        # _logger.debug(f"Success {dtask_id} for host {host.name}")
            _logger.info('Host (%s) was also be deleted from DB', host.name)
            if host.ip:
                db.session.delete(host.ip)
            db.session.delete(host)
            db.session.commit()
            dtask.update(
                status= 'succeeded',
                desc= 'ldap+DB delete host %s' % host.name,
                celery_task_id= current_tid
            )
        finally:
            dreq = Req.query.get(dtask.dreq_id)
            dreq.refresh_status()

    # @staticmethod
    # def single_host_register_track_sync_working(*args, **kwargs):
    #     celery_task_id = kwargs.get('celery_task_id')
    #     dtask = Dtask.query.get(kwargs.get('dtask_id'))
    #     dtask.update(
    #             desc= f"Starting single register track for {kwargs['hdata'].get('hostname')}",
    #             celery_task_id= celery_task_id
    #         )
    #     new = True
    #     try:
    #         host = Host.query.filter_by(name=kwargs['hdata'].get('hostname')).first()
    #         if host:
    #             new_mac, new_group, new_ip = Host.validate_existing_host_before_registration(**kwargs['hdata'])
    #             try:
    #                 host.mac = new_mac if new_mac else host.mac
    #                 host.group = new_group if new_group else host.group
    #                 host.ip = new_ip if new_ip else host.ip
    #             except IntegrityError:
    #                 # db update failed - rollback
    #                 db.session.rollback()
    #             else:
    #                 db.session.add(host)
    #                 db.session.commit()
    #             new = False
    #         else:
    #             host = Host.validate_new_host_before_registration(**kwargs['hdata'])
    #     except ValidationError as e:
    #         _logger.error(f"Failed dtask {dtask.id}")
    #         dtask.update(
    #             status= 'failed',
    #             desc= f"single host validation failed ({e.__str__()})",
    #         )
    #         raise
    #     except DoNothingRecordExists:
    #         host = Host.query.filter_by(name=kwargs.get('hdata').get('hostname')).first()
    #         dtask.update(
    #             status= 'succeeded',
    #             desc= f"Host with these params already exists in DB - nothing to do in DB",
    #             result= json.dumps({kwargs.get('hkey'):host.config()})
    #         )
    #     else:
    #         dtask.update(
    #             desc= 'passed single host validation',
    #         )
    #         if new:
    #             dtask.update(desc=f"Created new host {host}")
    #             try:
    #                 db.session.add(host)
    #                 db.session.commit()
    #             except IntegrityError as e:
    #                 dtask.update(
    #                     status= 'failed',
    #                     desc= f"Failed DB commit for host {host}",
    #                     err_str= e.__str__(),
    #                 )
    #                 # todo: still need to remove record from ldap or
    #                 # something like that becuase commiting host to DB failed
    #                 db.session.delete(host.ip)
    #                 db.session.commit()
    #                 raise
    #             else:
    #                 dtask.update(
    #                     status= 'succeeded',
    #                     desc= f"Finished single host register track for {host}",
    #                     result= json.dumps({kwargs.get('hkey'):host.config()})
    #                 )
    #         else: # host already in DB
    #             dtask.update(status='succeeded',
    #                          desc=f"Host {host} already in DB. just updated DB",
    #                          result= json.dumps({kwargs.get('hkey'):host.config()})
    #                          )

    @staticmethod
    def single_host_register_track(*args, **kwargs):
        celery_task_id = kwargs.get('celery_task_id')
        dtask = Dtask.query.get(kwargs.get('dtask_id'))
        dtask.update(
                desc= 'Starting single register track',
                celery_task_id= celery_task_id
            )
        new = True
        try:
            host = Host.query.filter_by(name=kwargs['hdata'].get('hostname')).first()
            if host:
                new_mac, new_group, new_ip = Host.validate_existing_host_before_registration(**kwargs['hdata'])
                try:
                    host.ldap_delete()
                except LDAPError as e:
                    if isinstance(e, NO_SUCH_OBJECT):
                        _logger.error(f"Failed deleting LDAP record {e.__str__()}")
                    else:
                        dtask.update(
                            status= 'failed',
                            desc= f"ldap_delete failed. host not updated",
                        )
                        return
                try:
                    host.mac = new_mac if new_mac else host.mac
                    host.group = new_group if new_group else host.group
                    host.ip = new_ip if new_ip else host.ip
                except IntegrityError:
                    # db update failed - rollback and ldap_Add old record
                    db.session.rollback()
                    host.ldap_add()
                else:
                    # update ldap with new host record
                    try:
                        host.ldap_add()
                    except LDAPError as e:
                        _logger.error(f"Failed updating LDAP with new host details {e.__str__()}")
                        db.session.rollback()
                        host = Host.query.filter_by(name=kwargs['hdata'].get('hostname')).first()
                        host.ldap_add()
                    else:
                        db.session.add(host)
                        db.session.commit()
                new = False
            else:
                host = Host.validate_new_host_before_registration(**kwargs['hdata'])

            # host, group, subnet, ip = Host.single_input_validate_before_registration(**kwargs['hdata'])
        except ValidationError as e:
            _logger.error(f"Failed dtask {dtask.id}")
            dtask.update(
                status= 'failed',
                desc= f"single host validation failed ({e.__str__()})",
            )
            raise
        except DoNothingRecordExists:
            host = Host.query.filter_by(name=kwargs.get('hdata').get('hostname')).first()
            dtask.update(
                status= 'succeeded',
                desc= f"Host with these params already exists in DB - nothing to do in DB",
                result= json.dumps({kwargs.get('hkey'):host.config()})
            )
        else:
            dtask.update(
                desc= 'passed single host validation',
            )
            if new:
                dtask.update(desc=f"Created new host {host}")

                # LDAP ADD NEW HOSTS
                try:
                    host.ldap_add()
                except LDAPError as e:
                    dtask.update(
                        status= 'failed',
                        desc= f"Failed ldap add {host}",
                        err_str = e.__str__()
                    )
                    db.session.delete(host.ip)
                    db.session.commit()
                    raise
                else:
                    try:
                        db.session.add(host)
                        db.session.commit()
                    except IntegrityError as e:
                        dtask.update(
                            status= 'failed',
                            desc= f"Failed DB commit for host {host}",
                            err_str= e.__str__(),
                        )
                        # TODO: still need to remove record from ldap or
                        # something like that becuase commiting host to DB failed
                        db.session.delete(host.ip)
                        db.session.commit()
                        raise
                    else:
                        dtask.update(
                            status= 'succeeded',
                            desc= f"Finished single host register track for {host}",
                            result= json.dumps({kwargs.get('hkey'):host.config()})
                        )
            else: # host already in DB
                dtask.update(status='succeeded',
                             desc=f"Host {host} already in DB. just updated LDAP",
                             result= json.dumps({kwargs.get('hkey'):host.config()})
                             )
                # if subnet:
                #     host.ip =  Subnet.alloc_single_ip(subnet, ip)
                #     desc = f"Host {host} will have an ip {host.ip}"
                #     dtask.update(desc=desc)

        # finally:
            # dtask.req.refresh_status()

    # @staticmethod
    # def single_host_delete_track_sync_working(*args, **kwargs):
    #     celery_task_id = kwargs.get('celery_task_id')
    #     dtask = Dtask.query.get(kwargs.get('dtask_id'))
    #     dtask.update(
    #             desc= f"Starting single delete track for {kwargs['hdata'].get('hostname')}",
    #             celery_task_id= celery_task_id
    #         )
    #     try:
    #         host = Host.validate_host_before_deletion(**kwargs['hdata'])
    #     except ValidationError as e:
    #         _logger.error(f"Failed dtask {dtask.id}")
    #         dtask.update(
    #             status= 'failed',
    #             desc= f"single host validation failed ({e.__str__()})",
    #         )
    #         raise
    #     except ConflictingParamsError as e:
    #         _logger.error(f"Failed dtask {dtask.id}")
    #         dtask.update(
    #             status= 'failed',
    #             desc= f"Single host delete validation failed)",
    #             err_str = e.__str__()
    #         )
    #     except DoNothingRecordNotInDB:
    #         dtask.update(
    #             status= 'succeeded',
    #             desc= f"Host by name {kwargs['hdata'].get('hostname')} does not exist in DB - nothing to do",
    #             result= json.dumps({kwargs.get('hkey'):kwargs['hdata'].get('hostname')})
    #         )
    #     else:
    #         dtask.update(
    #             desc= 'passed single host validation',
    #         )

    #         try:
    #             host.ldap_delete()
    #         except LDAPError as e:
    #             dtask.update(
    #                 status= 'failed',
    #                 desc= f"Failed ldap delete {host}",
    #                 err_str = e.__str__()
    #             )
    #         else:
    #             success_result = json.dumps({kwargs.get('hkey'):host.config()})
    #             if host.ip:
    #                 db.session.delete(host.ip)
    #             try:
    #                 db.session.delete(host)
    #                 db.session.commit()
    #             except IntegrityError as e:
    #                 dtask.update(
    #                     status= 'failed',
    #                     desc= f"Failed DB deletion for host {host}",
    #                     err_str= e.__str__(),
    #                 )
    #                 raise
    #             else:
    #                 dtask.update(
    #                     status= 'succeeded',
    #                     desc= f"Finished single host delete track for {host}",
    #                     result= success_result
    #                 )


    @staticmethod
    def single_host_delete_track(*args, **kwargs):
        celery_task_id = kwargs.get('celery_task_id')
        dtask = Dtask.query.get(kwargs.get('dtask_id'))
        dtask.update(
                desc= 'Starting single delete track',
                celery_task_id= celery_task_id
            )
        try:
            # host = Host.single_input_validate_before_deletion(**kwargs['hdata'])
            host = Host.validate_host_before_deletion(**kwargs['hdata'])
        except ValidationError as e:
            _logger.error(f"Failed dtask {dtask.id}")
            dtask.update(
                status= 'failed',
                desc= f"single host validation failed ({e.__str__()})",
            )
            raise
        except ConflictingParamsError as e:
            _logger.error(f"Failed dtask {dtask.id}")
            dtask.update(
                status= 'failed',
                desc= f"Single host delete validation failed)",
                err_str = e.__str__()
            )
        except DoNothingRecordNotInDB:
            dtask.update(
                status= 'succeeded',
                desc= f"Host by name {kwargs['hdata'].get('hostname')} does not exist in DB - nothing to do",
                result= json.dumps({kwargs.get('hkey'):kwargs['hdata'].get('hostname')})
            )
        else:
            dtask.update(
                desc= 'passed single host validation',
            )

            try:
                host.ldap_delete()
            except LDAPError as e:
                dtask.update(
                    status= 'failed',
                    desc= f"Failed ldap delete {host}",
                    err_str = e.__str__()
                )
            else:
                success_result = json.dumps({kwargs.get('hkey'):host.config()})
                if host.ip:
                    db.session.delete(host.ip)
                try:
                    db.session.delete(host)
                    db.session.commit()
                except IntegrityError as e:
                    dtask.update(
                        status= 'failed',
                        desc= f"Failed DB deletion for host {host}",
                        err_str= e.__str__(),
                    )
                    raise
                else:
                    dtask.update(
                        status= 'succeeded',
                        desc= f"Finished single host delete track for {host}",
                        result= success_result
                    )
        # finally:
            # dtask.req.refresh_status()

class Group(LDAPModel):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    hosts = db.relationship('Host', backref='group', lazy='dynamic')
    options = db.Column(db.Text)
    deployed = db.Column(db.Boolean, default=True)

    # def dn(self):
    #     # return 'cn=%s,ou=Groups,%s' % (self.name, server_dn())
    #     return 'cn=%s,%s' % (self.name, server_dn())

    def modlist(self):
        return gen_modlist(dict(objectClass=[b'dhcpGroup', b'top'],
                                cn=[self.name.encode('utf-8')]), self.options)

    def config(self):
        return dict(id = self.id,
                    dn = self.dn(),
                    name = self.name,
                    hosts = [host.id for host in self.hosts.all()],
                    options = json.loads(self.options) if self.options else None,
                    deployed = self.deployed)


    def deploy(self):
        '''
        for this to work ,DB should be empty.
        otherwise we might have accidently activated this method
        ('cn=m-ibox612-ups3,cn=Infinilab-Systems,cn=DHCP Config,dc=dhcpawn,dc=net', {'objectClass': [b'dhcpHost', b'top'], 'dhcpHWAddress':
        [b'ethernet 00:20:85:ed:e2:e1'], 'cn': [b'm-ibox612-ups3'], 'dhcpStatements': [b'fixed-address 172.16.74.123']})
        '''
        _logger.info(f"deploying group {self.name}")
        ldap_records = self.ldap_get()[1:]
        _logger.info(f"Deploying {len(ldap_records)} hosts for {self.name}")
        for record in ldap_records:
            if not b'dhcpHost' in record[1].get('objectClass'):
                continue
            try:
                hostname = record[1]['cn'][0].decode('utf-8')
                mac = record[1]['dhcpHWAddress'][0].split()[1].decode('utf-8')
                if record[1].get('dhcpStatements'):
                    ip_addr = record[1]['dhcpStatements'][0].split()[1].decode('utf-8')
                else:
                    ip_addr = None
                group_name = record[0].split(",")[1].split("=")[1]
                try:
                    h_id = Host.create(hostname=hostname, mac=mac, ip=ip_addr, group=group_name, deployed=True)
                except DhcpawnError:
                    # _logger.error(f"Failed creating host {hostname} {(e.__str__())}")
                    raise
                else:
                    _logger.debug(f"Deployed host {hostname} with id {h_id}")
            except DhcpawnError as e:
                _logger.debug(f"Failed deploying record {hostname} {(e.__str__())}")
            except KeyError:
                raise

    def get_sync_stat(self):
        """
        :param gr: db group inst
        :return: group dict with amount, "only in ldap", "only in db" and content diffs
        """

        _logger.debug(f"Inside get_sync_status for group {self.name}")
        gr_diff = {self.name: {'group is synced':True, 'info':{}}}
        info = gr_diff[self.name]['info']
        try:
            ldap_records = self.ldap_get()[1:]
        except NO_SUCH_OBJECT:
            _logger.error(f"Group {self} in DB but not in LDAP ???")
            # gr_diff[self.name]['group is synced'] = False
            # return gr_diff
            raise
        db_records = self.hosts.all()

        # amount
        ldp = len(ldap_records)
        ldb = len(db_records)
        if not ldp == ldb:
            info.setdefault('amount', {})
            info['amount']['ldap'] = ldp
            info['amount']['db'] = ldb
            info['amount']['diff'] = abs(ldb-ldp)

        # only in ldap
        for ldap_host_dn in ldap_records:
            if ldap_host_dn[1].get('objectClass') and b'dhcpGroup' in ldap_host_dn[1].get('objectClass'):
                continue
            ldap_name = ldap_host_dn[1]['cn'][0].decode('utf-8')
            ldap_mac = ldap_host_dn[1]['dhcpHWAddress'][0].decode('utf-8').replace('ethernet','').strip()
            ldap_group = ldap_host_dn[0].split(',')[1].replace('cn=','')
            ldap_ip = ldap_host_dn[1]['dhcpStatements'][0].decode('utf-8').replace('fixed-address','').strip() if ldap_host_dn[1].get('dhcpStatements') else None
            tmphost = Host.query.filter_by(name=ldap_name).first()
            if not isinstance(tmphost, Host) or tmphost.dn() != ldap_host_dn[0]:
                info.setdefault('only in ldap', [])
                _logger.debug("Entry exists only in LDAP %s" % ldap_name)
                info['only in ldap'].append((ldap_name, ldap_mac, ldap_group, ldap_ip))

        # only in db
        for h in db_records:
            try:
                h.ldap_get()
            except NO_SUCH_OBJECT:
                _logger.debug(f"Entry exists only in DB {h.name}")
                info.setdefault('only in db', [])
                info['only in db'].append(h.name)

        # content
        gr_stat = self._get_host_content_diff()
        if gr_stat:
            info.setdefault('content',gr_stat)

        # Sum up all diff types if exist
        if info.get('amount') or info.get('only in db') or info.get('only in ldap') or info.get('content'):
            _logger.notice("diffs exist per group %s" %  self.name)

            gr_diff[self.name]['group is synced'] = False

        return gr_diff

    @staticmethod
    def get_sync_stat_for_all_groups():
        groups = {}
        returned = {'synced':{}, 'not synced':{}}
        for g in Group.query.all():
            try:
                groups.update(g.get_sync_stat())
            except NO_SUCH_OBJECT as e:
                _logger.info(f"Not calculating diffs per group {g}")
                groups.update({g.name: {'info': f"Looks like this group is not in LDAP but can be found in DB ({e.__str__()})",
                                        'group is synced': False}})
                continue

        for g in groups:
            if groups[g]['group is synced']:
                returned['synced'].update({g:groups[g]})
            else:
                returned['not synced'].update({g:groups[g]})

        return returned

    def group_sync(self, **kwargs):

        d = {self.name: {'group is synced':True, 'info':{}}}
        try:
            d = self.get_sync_stat()
        except LDAPError:
            d[self.name]['group is synced'] = False
        for g in d:
            if d[g]['group is synced']:
                return d, None
            else:
                host_stat_dict = self._hosts_sync(d, **kwargs)
                return (d, host_stat_dict)


    def _hosts_sync(self, host_diffs, **kwargs):
        _logger.info(host_diffs)
        _logger.info(kwargs)
        stat_dict = {}
        for grp in host_diffs:
            stat_dict.setdefault(grp,{})
            if not host_diffs[grp]['group is synced']:
                info = host_diffs[grp]['info']
                gr = get_by_field(Group, 'name', grp)
                if info.get('only in db'):
                    stat_dict[grp].setdefault('added to ldap', [])
                    for host2sync in info['only in db']:
                        _logger.debug("Creating missing host %s in LDAP (found only on DB)" % host2sync)
                        host = get_by_field(Host, 'name', host2sync)
                        host.ldap_add()
                        stat_dict[grp]['added to ldap'].append(host2sync)

                if info.get('only in ldap'):
                    # we have two ways to sync this case:
                    # 1. delete the record in ldap
                    # 2. add the record to DB
                    # the next two "if" statements will choose
                    stat_dict[grp].setdefault('deleted from ldap', [])
                    stat_dict[grp].setdefault('added to db', [])
                    for ldap_name, ldap_mac, ldap_group, ldap_ip in info['only in ldap']:
                        if kwargs.get('sync_delete_ldap_entries', False):
                            # option 1: delete the record from ldap
                            _logger.debug("Deleting extra host %s from LDAP (found only on LDAP)" % ldap_name)
                            extra_host_dn = "cn=%s,%s" % (ldap_name, gr.dn())
                            ldap_extra_host_dn = gr.ldap_get(extra_host_dn)
                            if ldap_extra_host_dn:
                                _logger.info(f"Going to delete {ldap_extra_host_dn[0][0]} from LDAP")
                                gr.ldap_delete(ldap_extra_host_dn[0][0])
                                stat_dict[grp]['deleted from ldap'].append(ldap_name)

                        elif kwargs.get('sync_copy_ldap_entries_to_db',True):
                            # option 2: add record to DB
                            _logger.debug(f"Adding new record to DB for host {ldap_name}")
                            to_validate = dict(
                                hostname=ldap_name,
                                mac=ldap_mac,
                                group=ldap_group,
                                ip=ldap_ip,
                                subnet=IP.get_subnet(ldap_ip).name if (ldap_ip and IP.get_subnet(ldap_ip)) else None
                            )
                            try:
                                host2add = Host.validate_new_host_before_registration(**to_validate)
                            except (DhcpawnError, ValidationError) as e:
                                _logger.error(f"Failed syncing {ldap_name} by adding DB record. {e.__str__()}")
                            else:
                                db.session.add(host2add)
                                db.session.commit()

                if info.get('content'):
                    stat_dict[grp].setdefault('updated in ldap', [])
                    for hdict in info['content']['diff per host']:
                        for host2sync in hdict:
                            host = get_by_field(Host, 'name', host2sync)
                            host.ldap_delete()
                            host.ldap_add()
                            stat_dict[grp]['updated in ldap'].append(host2sync)

        return stat_dict

    def _get_host_content_diff(self):
        """
        the highest entity with regard to sync importance, changes more then
        the rest. need to verify that for a host in DB we see the same mac, ip, and group in ldap
        :return:
        """
        _logger.debug("Group get content diff in progress - %s" % self.name)
        hosts_diff_list = []

        for hst in Host.query.filter_by(group=self):
            db_entry = hst.config()
            try:
                ldap_entry = hst.ldap_get(parse=True)
            except NO_SUCH_OBJECT:
                ldap_entry = None

            if not ldap_entry:
                _logger.debug("Host - %s - in DB but not in LDAP" % db_entry['name'])
                continue
            hst_stat, elab_diff_lst = self._compare_hst(db_entry, ldap_entry)
            if not hst_stat:
                hosts_diff_list.append({hst.name: {'elaborated diff pairs': elab_diff_lst}})

        if not hosts_diff_list:
            _logger.debug("No content diffs exists per group %s" % self.name)
            return {}
        else:
            _logger.notice("Content diffs found for %s" % self.name)
            return {'diff per host': hosts_diff_list}

    def _compare_hst(self, db_entry, ldap_entry):
        """
        compare LDAP vs. DB entry (ip if exists, mac, name, group name)
        :param db_entry: host config dict
        :param ldap_entry: specific host ldap record
        :return:
                 True,   []               -> if no diff
                 False, [list with diffs] -> if records differ
        """
        dbl = []
        ldapl = []
        # get db values
        db_name = db_entry['name']
        db_ip = db_entry['ip']
        db_mac = db_entry['mac']
        db_gr = db_entry['group_name']
        # get ldap values
        for k in ldap_entry:
            ldap_name = k
            ldap_ip = ldap_entry[k]['ip']
            ldap_mac = ldap_entry[k]['mac']
            ldap_gr = ldap_entry[k]['dn'].split(',')[1].replace("cn=","")

        dbl.extend((db_name, db_ip, db_mac, db_gr))
        ldapl.extend((ldap_name, ldap_ip, ldap_mac, ldap_gr))

        if dbl == ldapl:
            return True, []
        else:
            _logger.debug("Diff in %s" % dbl[0])
            df = []
            for i, d in enumerate(dbl):
                if not d == ldapl[i]:
                    df.append({'db': str(d), 'ldap': str(ldapl[i])})
            _logger.debug("Elaborated diff pairs: %s" % df)
            return False, df

    @staticmethod
    def sync_all_groups():
        # run sync on all groups
        stat = dict()
        post_sync = dict([('groups', {})])

        for gr in Group.query.all():
            try:
                tmpd, host_stat_dict = gr.group_sync()
                stat.update(tmpd)
                if host_stat_dict:
                    post_sync['groups'].update(host_stat_dict)
            except DhcpawnError:
                pass

        if post_sync['groups']:
            return {'pre sync': {k:v for k,v in stat.items() if not v['group is synced']},
                    'post sync': {k:v for k,v in post_sync.items() if v} }
        else:
            return stat

class Subnet(LDAPModel):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    netmask = db.Column(db.Integer)
    options = db.Column(db.Text)
    pools = db.relationship('Pool', backref='subnet', lazy='dynamic')
    calcranges = db.relationship('CalculatedRange', backref='subnet', lazy='dynamic', uselist=True)
    deployed = db.Column(db.Boolean, default=True)

    # def dn(self):

    #     # return 'cn=%s,ou=Subnets,%s' % (self.name, server_dn())
    #     return 'cn=%s,%s' % (self.name, server_dn())

    def __repr__(self):
        return f"{json.loads(self.options).get('dhcpComments')[0]}"

    def modlist(self):
        mod_dict = dict(objectClass=[b'dhcpSubnet', b'top'],
                cn=[self.name.encode('utf-8')],
                dhcpNetMask=[str(self.netmask).encode('utf-8')])

        # if self.ranges and self.ranges.deployed:
        #     mod_dict.update(dict(dhcpRange=[str('%s %s' % (self.ranges.min, self.ranges.max)).encode()]))
        return gen_modlist(mod_dict, self.options)

    def contains(self, ip):
        network = IPv4Network('%s/%d' % (self.name, self.netmask))
        return ip in network

    def config(self):
        return dict(id=self.id,
                    dn=self.dn(),
                    name=self.name,
                    netmask=self.netmask,
                    options=json.loads(self.options) if self.options else None,
                    # range = self.ranges,
                    pools=[pool.id for pool in self.pools.all()],
                    deployed=self.deployed)

    @staticmethod
    def get_name_by_dhcpcomment_name(dhcpcomment_name):
        ''' try finding out if we got a subnet name
        that corresponds to the dhcpComments name and not the
        ip name type.
        i.e: Data1 is a dhcpComment name but the actual subnet name is 172.16.32.0 '''
        for s in Subnet.query.all():
            if json.loads(s.options)['dhcpComments'][0] == dhcpcomment_name:
                return s
        raise DhcpawnError


    @staticmethod
    def get_crid_list(subnet):
        ''' subnet is db instance
        returnes a list of calculated ranges id '''
        return [cr.id for cr in subnet.calcranges.all()]


    @staticmethod
    def alloc_single_ip(su, addr=None):
        """
        go over subnet calculated ranges and find a free ip if addr=None
        or check if the specific address is free to allocate
        :param su: subnet in which the ip should be
        :param addr: if a specific address in needed otherwise its find first free ip in subnet
        :return: ip database inst
        """
        # for cr_id in subnet_get_calc_ranges(su):
        try:
            if addr == 'allocate':
                ip = su.allocate_free_ip()
            else:
                return IP.allocate_specific_ip(addr)
        except DhcpawnError as e:
            _logger.error(e.__str__())
            raise DhcpawnError("Failed allocating ip %s" % addr)
        return ip

    def allocate_free_ip(self):
        for cr in self.calcranges.all():
            try:
                if cr.get_free_ips():
                    ip = cr.allocate_free_ips()
                    return ip[0]
            except DhcpawnError:
                raise

    @staticmethod
    def get_free_ips(sub_addr):
        su = Subnet.validate_by_name(sub_addr)
        for cr in su.calcranges.all():
            free_ips = cr.get_free_ips()
            if free_ips:
                return free_ips
        return None

class Pool(LDAPModel):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    subnet_id = db.Column(db.Integer, db.ForeignKey('subnet.id'))
    # dhcprange_id = db.Column(db.Integer, db.ForeignKey('dhcprange.id'))
    dhcprange = db.relationship('DhcpRange', backref='pool', uselist=False)
    options = db.Column(db.Text)
    deployed = db.Column(db.Boolean, default=True)

    def dn(self):
        return 'cn=%s,%s' % (self.name, self.subnet.dn())

    def modlist(self):
        # range is required
        _logger.debug("Return POOL modlist")
        mod_dict = dict(objectClass=[b'dhcpPool', b'top'],
                        cn=[self.name.encode('utf-8')],
                        dhcpRange=[str('%s %s' % (self.dhcprange.min, self.dhcprange.max)).encode('utf-8')])
        pool_modlist = gen_modlist(mod_dict, self.options)
        _logger.debug("Pool modlist: %s" % pool_modlist)
        return pool_modlist

    def config(self):
        _logger.debug("Return POOL config")
        return dict(id=self.id,
                    name=self.name,
                    subnet=self.subnet.id,
                    dhcprange=self.dhcprange.id if self.dhcprange else None,
                    options=self.options,
                    deployed=self.deployed)


# DB Models

class IP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(IPAddressType, unique=True)
    calcrange_id = db.Column(db.Integer, db.ForeignKey('calculatedrange.id'))
    dhcprange_id = db.Column(db.Integer, db.ForeignKey('dhcprange.id'))
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'))
    deployed = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<IP : {self.address.compressed}>"

    def __eq__(self, addr):
        if isinstance(addr, str):
            return self.address.compressed == addr
        return False

    def ldap_add(self):
        host = _get_or_none(Host, self.host_id)
        if host and self.deployed:
            host.ldap_modify()

    def ldap_delete(self):
        if self.host and self.deployed:
            host = self.host
            host.ip = None
            db.session.add(host)
            db.session.commit()
            host.ldap_modify()

    def config(self):
        return dict(id=self.id,
                    address=self.address.compressed,
                    calcrange=self.calcrange_id,
                    dhcprange=self.dhcprange_id,
                    host=self.host_id)

    @staticmethod
    def is_ip_taken(addr):
        ''' returns the IPv4address(addr) is its available. otherwise ,will raise Dhcpawnerror
        with an explanatory msg'''
        res = IP.query.filter_by(address=addr).first()
        if res:
            raise ValidationError(f"ip {addr} already taken by {res.host.name}")
        else:
            return IPv4Address(addr)

    @staticmethod
    def allocate_specific_ip(addr):
        """
        check if specific address is free and allocate in DB
        :param addr: ip address ( string )
        :return: ip database inst
        """
        if not addr:
            raise DhcpawnError("provided ip is empty")
        try:
            IP.is_ip_taken(addr)
        except DhcpawnError:
            raise
        else:
            cr = IP.get_calcrange(addr)
            if cr:
                ip = IP(address=IPv4Address(addr),
                    calcrange_id=cr.id)
                db.session.add(ip)
                db.session.commit()
                return ip

            else:
                raise DhcpawnError('No calculated range for %s' % addr)

    @staticmethod
    def get_calcrange(addr):
        ''' returns the calcrange instance or None'''
        for cr in CalculatedRange.query.all():
            if cr.contains(IPv4Address(addr)):
                return cr

        return None

    @staticmethod
    def get_dhcprange(addr):
        ''' returns the dhcprange instance or None'''
        for dr in DhcpRange.query.all():
            if dr.contains(IPv4Address(addr)):
                return dr

        return None

    @staticmethod
    def get_subnet(addr):
        ''' subnet instance is returned '''
        cr = IP.get_calcrange(addr)
        if cr:
            return cr.subnet
        else:
            return None

    @staticmethod
    def ip_in_subnet(addr, subnet_name):
        ''' get addr and subnet_name and check if ip address
        is in one of the subnet's calculated ranges '''
        if IP.get_subnet(addr).name == Subnet.validate_by_name(subnet_name).name:
            return True
        return False

class DhcpRange(db.Model):
    '''
    model that holds the range of dhcp addresses , that is related to a pool
    '''

    __tablename__ = 'dhcprange'

    id = db.Column(db.Integer, primary_key=True)
    min = db.Column(IPAddressType)
    max = db.Column(IPAddressType)
    pool_id = db.Column(db.Integer, db.ForeignKey('pool.id'))
    deployed = db.Column(db.Boolean, default=True)

    def ldap_delete(self):
        if self.deployed:
            pool = _get_or_none(Pool, self.pool_id)
            pool.dhcprange = None
            db.session.add(pool)
            db.session.commit()
            pool.ldap_modify()

    def ldap_add(self):
        if self.deployed:

            # once we have a dhcprange and a related pool ,we can deploy the pool
            # to ldap + changing the deployed status to True in DB.
            pool = _get_or_none(Pool, self.pool_id)
            pool.deployed = True
            db.session.add(pool)
            db.session.commit()
            pool.ldap_modify()

    def contains(self, ip):
        return ip >= self.min and ip <= self.max


    def config(self):

        # pool = _get_or_none(Pool, self.pool_id)
        return dict(id=self.id,
                    type='DhcpRange',
                    min=self.min.compressed,
                    max=self.max.compressed,
                    pool=self.pool_id,
                    deployed=self.deployed)


class CalculatedRange(db.Model):
    '''
    model related only to a subnet, data will only reside in the database and not in ldap (
    thus it doesn't have an ldap_add method).
    will hold the static ip ranges from which infinilab allocate ips to hosts/services..
    '''

    __tablename__ = 'calculatedrange'

    id = db.Column(db.Integer, primary_key=True)
    min = db.Column(IPAddressType)
    max = db.Column(IPAddressType)
    subnet_id = db.Column(db.Integer, db.ForeignKey('subnet.id'))
    ips = db.relationship('IP', backref='calculatedrange', lazy='dynamic')

    def get_free_ips(self):
        ''' just get a free ip address in this calculated range '''
        free = []
        count = 0
        top = self.max + 1
        ips = [ip.address for ip in self.ips.all()]
        while top > self.min:
            top -= 1
            if top not in ips:
                free.append(top.__str__())
                count += 1
            if count > 5:
                break

        return free

    def allocate_free_ips(self, num=1):

        # return the first IP address in the range, from the top, without conflict
        # if num is greater than 1, returns a list of ips
        # _logger.debug("Allocate_free_ips - need %s ips" % num)
        free = []
        top = self.max + 1
        ips = [ip.address for ip in self.ips.all()]
        while top > self.min:
            top -= 1
            if top not in ips:

                # found a free ip, allocating it
                # _logger.debug("Allocating ip %s from calculated range %s in subnet %s" % (top, self.id, self.subnet_id))
                fip = IP(address=top, calcrange_id=self.id)
                try:
                    db.session.add(fip)
                except IntegrityError as e:
                    db.session.rollback()
                    raise DhcpawnError(e.__str__())
                else:
                    free.append(fip)

            if len(free) == num:
                db.session.commit()
                return free

        # if we got here, we are probably short of free ips
        # _logger.debug("Didnt get all the needed ips in current calculated range %s" % self.id)
        return free

    def contains(self, ip):
        return ip >= self.min and ip <= self.max

    def config(self):

        # subnet = _get_or_none(Subnet, self.subnet_id)
        return dict(id=self.id,
                    type='CalculatedRange',
                    min=self.min.compressed,
                    max=self.max.compressed,
                    subnet=self.subnet_id,
                    )


##### REQUEST MODEL

class Req(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20)) # possible values: Fully Completed/Partially Completed/Failure/OnGoing
    err_str = db.Column(db.Text, default='')
    request_type = db.Column(db.String(100))
    params = db.Column(db.Text)
    dtasks = db.relationship('Dtask', backref='req', lazy='dynamic', uselist=True)
    drequest_result = db.Column(db.Text, default='')
    reply_url = db.Column(db.Text, default='') # if set, send an HTTP POST request with the drequest config
    replied = db.Column(db.Boolean, default=False) # if True, the reply_url was used so dont sent another reply

    def __init__(self):
        self.status = "OnGoing"
        self.params = json.dumps({})
        self.celery_tasks_list = json.dumps([])

    def __repr__(self):
        return f"<{self.id} : {self.request_type}>"

    def config(self):
        dtasks_category_dict = {'failed': [],
                                'running': [],
                                'succeeded': [],
        }
        for dt in self.dtasks.all():
            # succeeded, failed, running
            if dt.status == 'succeeded':
                dtasks_category_dict['succeeded'].append(dt.config())
            elif dt.status == 'failed':
                dtasks_category_dict['failed'].append(dt.config())
            elif dt.status == 'running':
                dtasks_category_dict['running'].append(dt.config())
            else:
                _logger.error(f"Found a dtask with unknown state {dt.status}")

        return  dict(id=self.id,
            drequest_status=self.status,
            drequest_type=self.request_type,
            drequest_result=json.loads(self.drequest_result) if self.drequest_result else None,
            params=json.loads(self.params),
            dtasks_amount = len(self.dtasks.all()),
            dtasks=dtasks_category_dict,
            err_str = self.err_str,
            reply_url = self.reply_url,
            replied=self.replied,
            )

    def refresh_status(self):
        ''' used for cases where request has celery tasks '''
        _logger.debug("refreshing dreq %s status (%s tasks)" % (self.id, len(self.dtasks.all())))
        # failed = False
        drequest_result = {}
        running = False
        num_running = 0
        num_failed = 0
        num_passed = 0
        for dtask in self.dtasks.all():
            if dtask.status == 'failed':
                # self.status = 'Failed'
                # failed = True
                num_failed += 1
                # self.commit()
                # self.postreply()
            elif dtask.status == 'running':
                running = True
                num_running += 1
            elif dtask.status == 'succeeded':
                # drequest_result.update(json.loads(dtask.result))
                # if self.drequest_result:

                #     self.drequest_result = json.dumps(json.loads(self.drequest_result).update(json.loads(dtask.result)))
                # else:
                #     self.drequest_result = json.dumps(dtask.result)
                drequest_result.update(json.loads(dtask.result))
                num_passed += 1
            else:
                _logger.info(f"wrong dtask status {dtask.status}")
                self.status = 'Bug ???'
                self.commit()
                return "Buggggg"

        if drequest_result:
            self.update_drequest(drequest_result=drequest_result)
        # _logger.debug(f"PASSED: {num_passed} ; RUNNING: {num_running} ; FAILED: {num_failed}")
        # if failed:
        #     self.status = 'Failed'
        #     self.commit()
        if running:
            return
            # return "Request still has running tasks"

        # if self.status != 'Failed':
        #     self.status = 'Done'
        #     _logger.info("Tasks Done!!!!")
        #     self.commit()
        if num_passed and num_failed:
            self.status = 'Partially Completed'
        elif num_passed and not num_failed:
            self.status = 'Fully Completed'
        else:
            self.status = 'Failure'
        self.commit()
        _logger.debug("Finish request refresh_status")
        # self.clean_on_failure()
        # self.postreply()

    def clean_on_failure(self):
        '''for cases where the drequest failed ,at least one of the hosts didn't
        register properly, this method will clear all other hosts data from DB/LDAP'''

        if not self.status == 'Failed':
            return
        hosts = json.loads(self.params)
        _logger.info("HOSTS TO DELETE %s" % len(hosts))
        for h in hosts.keys():
            _logger.info(f"will try to delete {hosts[h]} from LDAP")

            h_inst = Host.query.filter_by(name=hosts[h]['hostname']).first()
            _logger.info(f"deleting {h_inst.id} from LDAP")
            h_inst.ldap_delete()

            if h_inst.ip:
                db.session.delete(h_inst.ip)
            db.session.delete(h_inst)
            db.session.commit()

    def postreply(self):
        '''method to post drequest config to the reply_url
        when drequest finished (either failed or succeeded)'''
        if self.status == "OnGoing":
            raise DhcpawnError(f"dRequest {self.id} still running")

        if not self.replied and self.reply_url:
            # url = '%s%s/' % (self.reply_url, self.id)
            _logger.info("Post reply to url %s" % self.reply_url)
            requests.post(self.reply_url, data=self.config(), verify=False)
            self.replied = True
            self.commit()
            # self.refresh_status()

    def update_drequest(self, drequest_type=None, drequest_reply_url=None, drequest_result=None,
                        params=None, tasks_list=None, tasks_count=None, err_str=None, status=None):

        if params:
            self.params = json.dumps(params)
        if tasks_list:
            self.celery_tasks_list = json.dumps(tasks_list)
        if drequest_type:
            self.drequest_type = drequest_type
        if drequest_reply_url:
            self.reply_url = drequest_reply_url
        if drequest_result:
            self.drequest_result = json.dumps(drequest_result)
        if tasks_count:
            self.celery_tasks_count = tasks_count
        if status:
            self.status = status
        if err_str:
            self.err_str = err_str

        self.commit()

    def commit(self):

        db.session.add(self)
        db.session.commit()
        _logger.debug("dreq %s was updated in DB" % self.id)


class Dtask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    celery_task_id = db.Column(db.String(50))
    status = db.Column(db.String(10)) # possible values: succeeded, failed, running
    desc = db.Column(db.Text, default='') # task description
    err_str = db.Column(db.Text, default='')
    dreq_id = db.Column(db.Integer, db.ForeignKey('req.id'))
    result = db.Column(db.Text, default='')

    def __init__(self, dreq_id):
        self.status = "running"
        self.dreq_id = dreq_id
        self.commit()

    def __repr__(self):
        return f"<DTASK: {self.id} part of DREQUEST: {self.dreq_id}>"

    def commit(self):
        db.session.add(self)
        db.session.commit()

    def update(self, **kwargs):
        _logger.debug(f"Updating dtask {self}")
        if 'celery_task_id' in kwargs:
            self.celery_task_id = kwargs.get('celery_task_id')
        if 'desc' in kwargs:
            self.desc = kwargs.get('desc')
        if 'status' in kwargs:
            self.status = kwargs.get('status')
            if kwargs.get('status') == 'failed':
                _logger.error(f"Task failed: {kwargs.get('desc')} - {kwargs.get('err_str')}")
        if 'err_str' in kwargs:
            self.err_str = kwargs.get('err_str')
        if 'result' in kwargs:
            self.result = kwargs.get('result')

        self.commit()

    def config(self):
        return dict(id=self.id,
                    dreq_id=self.dreq_id,
                    status=self.status,
                    description=self.desc,
                    err_str=self.err_str,
                    celery_task_id=self.celery_task_id,
                    result=json.loads(self.result) if self.result else None)

class Duplicate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    desc = db.Column(db.Text, default='')
    valid = db.Column(db.Boolean, default=True)
    duptype = db.Column(db.String(10), default='')

    def __init__(self, description, duptype=None):
        '''
        duptype can be one of the strings mac, hostname or ip
        '''
        self.desc = description
        if duptype and duptype not in ['mac', 'hostname', 'ip']:
            raise DhcpawnError("Failed creating a duplication record. type should be one of mac,hostname,ip")
        self.duptype = duptype
        self._update()

    def config(self):
        return dict(id=self.id,
                    description=self.desc,
                    valid=self.valid,
                    duplication_type=self.duptype)

    def invalidate(self):
        self.valid = False
        self._update()

    def make_valid(self):
        self.valid = True
        self._update()

    def _update(self):
        db.session.add(self)
        db.session.commit()

# Deploy help functions
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

def deploy_skeleton():
    skeleton = extract_skeleton()
    deploy_groups(skeleton)
    deploy_subnets(skeleton)
    deploy_pools(skeleton)
    deploy_calcranges(skeleton)
    deploy_dhcpranges(skeleton)

def deploy_hosts():

    for gr in Group.query.all():
        gr.deploy()
