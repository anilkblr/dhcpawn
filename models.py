# cob: type=models
from cob import db
from cob.celery.app import celery_app
import logbook
from flask import current_app, has_request_context
from cob.project import get_project
from ldap import modlist, SCOPE_BASE, NO_SUCH_OBJECT, SCOPE_SUBTREE
from ipaddress import IPv4Address, IPv4Network
from sqlalchemy_utils import IPAddressType
import json
import requests
import ldap
from .ldap_utils import server_dn
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.exc import IntegrityError
from .help_functions import _get_or_none, get_by_field, DhcpawnError, get_by_id, parse_ldap_entry

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
                    tmpl= []
                    for _o in o:
                        tmpl.append(_o.encode('utf-8'))
                    boptions[option].append(tmpl)
        obj_dict.update(boptions)
    return obj_dict

class LDAPModel(db.Model):
    __abstract__ = True

    def dn(self):
        return ''

    def modlist(self):
        return dict()

    def ldap_add(self):
        if self.deployed:

            # from cob.app import build_app
            # app = build_app(use_cached=True)
            tries = 0
            while True:
                _logger.debug(f"Add LDAP entry {self.dn()} (tries={tries})")
                tries += 1
                try:
                    current_app.ldap_obj.add_s(self.dn(), modlist.addModlist(self.modlist()))
                except ldap.TIMEOUT as e:
                    pass
                except ldap.SERVER_DOWN as e:
                    pass
                except Exception as e:
                    _logger.error(f'ldap add unexpected exception {e.__str__()} - trying again')
                    if tries > 10:
                        _logger.error(f"Failed ldap_add on {self.dn()} even after retries")
                        raise
                finally:
                    _logger.debug(f"ldap add {self.dn()} succeeded")
                    break

    def ldap_get(self, dn=None, parse=False):
        if not dn:
            dn = self.dn()

        try:
            res = current_app.ldap_obj.search_s(dn, SCOPE_SUBTREE)
            if parse:
                return parse_ldap_entry(res)
            else:
                return res

        except NO_SUCH_OBJECT:
            _logger.debug("Missing DN is: %s" % dn)
            return None
        except Exception as e:
            _logger.warning("unexcepted exception %s" % e.__str__())
            return {}
        _logger.info("Found")

    def ldap_modify(self, dn=None):
        if not dn:
            dn = self.dn()
        _logger.debug("Modify LDAP entry: %s" % dn)
        if self.deployed:
            try:

                # data taken from ldap
                objs = current_app.ldap_obj.search_s(dn, SCOPE_BASE)
                _logger.debug("Current data in DB: %s" % self.config())
                _logger.debug("Current DN in LDAP: %s" % str(objs[0][1]))
                if objs[0][1] != dict(self.modlist()):
                    import pudb;pudb.set_trace()
                    current_app.ldap_obj.modify_s(dn, modlist.modifyModlist(objs[0][1], dict(self.modlist())))
            except NO_SUCH_OBJECT:
                self.ldap_add()

    def ldap_delete(self, dn=None):
        if not dn:
            dn = self.dn()

        if self.deployed:
            tries = 0
            while True:
                _logger.debug(f"Delete LDAP entry {self.dn()} (tries={tries})")
                tries += 1
                try:
                    current_app.ldap_obj.delete_s(dn)
                except Exception as e:
                    _logger.error(f'ldap delete unexpected exception {e.__str__()} - trying again')
                    if tries > 10:
                        _logger.error(f"Failed ldap_delete on {self.dn()} even after retries")
                        raise
                finally:
                    _logger.debug(f"ldap delete {self.dn()} succeeded")
                    break

    @classmethod
    def validate_by_name(cls, name):
        for inst in cls.query.all():
            if inst.name == name:
                return inst

        if isinstance(cls(), Subnet):
            try:
                return Subnet.get_name_by_dhcpcomment_name(name)
            except DhcpawnError:
                raise DhcpawnError("There is no subnet with name %s" % name)

        raise DhcpawnError("No matching db instance with this name %s" % name)


    def __repr__(self):
        if hasattr(self.__class__, 'name'):
            return '<%s:%s>' % (self.__class__.__name__, self.name)
        else:
            return '<%s>' % self.__class__.__name__

#LDAP Models

class Host(LDAPModel):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    mac = db.Column(db.String(100), unique=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    ip = db.relationship('IP', backref='host', uselist=False)
    # ip_id = db.Column(db.Integer, db.ForeignKey('ip.id'))
    options = db.Column(db.Text)
    deployed = db.Column(db.Boolean, default=True)

    def dn(self):
        if self.group_id:
            return 'cn=%s,%s' % (self.name, self.group.dn())
        return 'cn=%s,ou=Hosts,%s' % (self.name, server_dn())

    def modlist(self):
        options = json.loads(self.options) if self.options else {}
        if self.ip and self.ip.deployed:
            if not options.get('dhcpStatements'):
                options['dhcpStatements'] = []
            options['dhcpStatements'] += ['fixed-address %s' % str(self.ip.address)]
            options = json.dumps(options)
        return gen_modlist(dict(objectClass=[b'dhcpHost', b'top'],
                dhcpHWAddress=[b'ethernet %s' % self.mac.encode('utf-8')],
                cn=[self.name.encode('utf-8')]), options)

    def config(self):
        return dict(id=self.id,
                    dn=self.dn(),
                    name=self.name,
                    mac=self.mac,
                    ip_id=self.ip.id if self.ip else None,
                    ip=self.ip.address.__str__() if self.ip else None,
                    group=self.group_id,
                    group_name=self.group.name,
                    options=json.loads(self.options) if self.options else None,
                    deployed=self.deployed)

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
    def hostname_mac_coupling_check(hostname, mac):
        ''' check that for hostname and mac ,either both are new
        or both exist in DB and are coupled.
        if None returned: just create new host with this mac.
        if host returned: use it to update entry in DB if needed
        else we raise exception'''
        host_by_hostname = Host.get_by_hostname(hostname)
        host_by_mac = Host.get_by_mac(mac)
        if host_by_hostname and host_by_mac:
            if host_by_hostname == host_by_mac:
                # both hostname and mac exist in DB and belong to the same entry.
                return host_by_hostname
            else:
                raise DhcpawnError("hostname %s and mac %s belong to two different entries in DB " % (hostname, mac) )
        elif not host_by_hostname and not host_by_mac:
            # no record in DB with this hostname or mac
            return None
        raise DhcpawnError("hostname/mac coupling check failed. only one of them exist in DB (host_by_hostname: %s, host_by_mac: %s " % (host_by_hostname, host_by_mac))

    @staticmethod
    def host_mac_group_validation(**kwargs):
        try:
            host = Host.hostname_mac_coupling_check(kwargs.get('hostname'), kwargs.get('mac'))
        except DhcpawnError as e:
            _logger.debug(e.__str__())
            raise
        try:
            group = Group.validate_by_name(kwargs.get('group'))
        except DhcpawnError as e:
            _logger.debug(e.__str__())
            raise
        return host, group

    @staticmethod
    def ip_subnet_validation(**kwargs):
        req_subnet = kwargs.get('subnet')
        req_ip = kwargs.get('ip')
        if req_subnet and req_ip: # TODO verify that ip in subnet and not taken
            try:
                IP.is_ip_taken(req_ip)
            except DhcpawnError:
                raise
            else:
                try:
                    if IP.ip_in_subnet(req_ip, req_subnet):
                        ip = req_ip
                        subnet = Subnet.validate_by_name(req_subnet)
                    else:
                        raise DhcpawnError("IP %s does not belong to subnet %s" % (req_ip, req_subnet))
                except DhcpawnError:
                    raise
        elif req_subnet and not req_ip: # TODO just verify subnet and ip will be allocate
            try:
                subnet = Subnet.validate_by_name(req_subnet)
            except DhcpawnError:
                raise
            else:
                ip = "allocate"
        elif not req_subnet and req_ip: # TODO check if ip taken and if not ,calulate subnet and allocate
            try:
                IP.is_ip_taken(req_ip)
            except DhcpawnError:
                raise
            else:
                ip = req_ip
                subnet = IP.get_subnet(req_ip)
        else:
            subnet = None
            ip = None

        return ip, subnet

    @staticmethod
    def single_input_validate_before_registration(kwargs):
        ''' validate before registration, get single host creation inputs:
        hostname, mac, group, subnet, ip, and make sure is a valid request'''
        if any(key not in kwargs for key in ['hostname', 'mac', 'group']):
            raise DhcpawnError("Mandatory hostname, mac or group missing in this record %s" % kwargs)
        try:
            host, group = Host.host_mac_group_validation(**kwargs)
        except DhcpawnError:
            _logger.warning("Killed ???")
            raise
        else:
            _logger.debug("%s %s" % (host, group))
            try:
                ip, subnet = Host.ip_subnet_validation(**kwargs)
            except DhcpawnError:
                raise
        return host, group, subnet, ip

    def create(self, **kwargs):
        ''' Host method to create new host '''
        if any(key not in kwargs for key in ['hostname', 'mac', 'group']):
            raise DhcpawnError('Host requires name, mac and group')

        if Host.query.filter(Host.mac == kwargs.get('mac')).all():
            raise DhcpawnError('A host with this MAC (%s) already exists' % kwargs.get('mac'))

        self.name=kwargs.get('name')
        self.mac=kwargs.get('mac')
        self.group_id=kwargs.get('group')
        self.options=json.dumps(kwargs.get('options',{}))
        deployable = True
        try:
            group = get_by_id(Group, self.group_id)
        except DhcpawnError as e:
                raise

        if 'deployed' in kwargs and kwargs.get('deployed') == "True":
            if not group.deployed:
                raise DhcpawnError('Cannot deploy host as subobject of non-deployed group')
        elif 'deployed' in kwargs and kwargs.get('deployed') == "False":
            raise DhcpawnError("setting deployed to False is not supported ")

    @staticmethod
    def single_input_validate_before_deletion(kwargs):
        ''' simply make sure hostname really has the mac we got and
        belong to the provided group'''

        try:
            host, _ = Host.host_mac_group_validation(**kwargs)
        except DhcpawnError:
            raise

        if not host:
            raise DhcpawnError("No host with these params %s" % kwargs)

        try:
            host.validate_db_vs_ldap()
        except DhcpawnError as e:
            _logger.error(e.__str__())
            raise

        return host

    def validate_db_vs_ldap(self):
        """take DB entry and compare to LDAP
        compare mac and ip
        """
        ldap_entry = self.ldap_get(parse=True)
        ldap_mac = ldap_entry[self.name]['mac']
        ldap_ip = ldap_entry[self.name]['ip']
        if not ldap_mac == self.mac:
            raise DhcpawnError('%s- DB-LDAP validation failed - mac addresses are different (DB: %s , LDAP: %s)' % (self.name, self.mac, ldap_mac))
        if not ldap_ip == self.ip:
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


class Group(LDAPModel):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    hosts = db.relationship('Host', backref='group', lazy='dynamic')
    options = db.Column(db.Text)
    deployed = db.Column(db.Boolean, default=True)

    def dn(self):
        # return 'cn=%s,ou=Groups,%s' % (self.name, server_dn())
        return 'cn=%s,%s' % (self.name, server_dn())

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


    def get_sync_stat(self):
        """
        :param gr: db group inst
        :return: group dict with amount, "only in ldap", "only in db" and content diffs
        """

        gr_diff = {'group is synced':True}
        ldap_records = self.ldap_get()[1:]
        db_records = self.hosts.all()

        # amount
        ldp = len(ldap_records)
        ldb = len(db_records)
        if not ldp == ldb:
            gr_diff.setdefault('amount', {})
            gr_diff['amount']['ldap'] = ldp
            gr_diff['amount']['db'] = ldb
            gr_diff['amount']['diff'] = abs(ldb-ldp)

        # only in ldap
        for ldap_host_dn in ldap_records:
            ldap_name = ldap_host_dn[1]['cn'][0].decode('utf-8')
            if not Host.query.filter_by(name=ldap_name).first():
                gr_diff.setdefault('only in ldap', [])
                _logger.debug("Entry exists only in LDAP %s" % ldap_name)
                gr_diff['only in ldap'].append(ldap_name)

        # only in db
        for h in db_records:
            if not h.ldap_get():
                _logger.debug("Entry exists only in DB %s" % h.name)
                gr_diff.setdefault('only in db', [])
                gr_diff['only in db'].append(h.name)

        # content
        gr_stat = self.get_host_content_diff()
        if gr_stat:
            gr_diff.setdefault('content',gr_stat)

        if gr_diff.get('amount') or gr_diff.get('only in db') or gr_diff.get('only in ldap') or gr_diff.get('content'):
            _logger.notice("Amount diffs exists per group %s" %  self.name)
            gr_diff['group is synced'] = False

        return gr_diff

    def get_host_content_diff(self):
        """
        the highest entity with regard to sync importance, changes more then
        the rest. need to verify that for a host in DB we see the same mac, ip, and group in ldap
        :return:
        """
        _logger.debug("Group get content diff in progress - %s" % self.name)
        hosts_diff_list = []

        for hst in Host.query.filter_by(group=self):

            db_entry = hst.config()
            ldap_entry = hst.ldap_get()

            if not ldap_entry:
                _logger.debug("Host - %s - in DB but not in LDAP" % db_entry['name'])
                continue
            hst_stat, elab_diff_lst = self.compare_hst(db_entry, ldap_entry)
            if not hst_stat:
                hosts_diff_list.append({hst.name: {'elaborated diff pairs': elab_diff_lst}})

        if not hosts_diff_list:
            _logger.info("No content diffs exists per group %s" % self.name)
            return {}
        else:
            _logger.notice("Content diffs found for %s" % self.name)
            return {'diff per host': hosts_diff_list}

    def compare_hst(self, db_entry, ldap_entry):
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
        # name
        dbl.append(db_entry['name'].encode('utf-8'))
        ldapl.append(ldap_entry[0][1]['cn'][0])
        # ip
        db_ip = IP.query.filter_by(id=db_entry['id']).first()
        if db_ip:
            dbl.append(db_ip.address.compressed.encode('utf-8'))
        else:
            dbl.append(None)
        if 'dhcpStatements' in ldap_entry[0][1]:
            ldapl.append(ldap_entry[0][1]['dhcpStatements'][0].split()[1])
        else:
            ldapl.append(None)
        # mac
        dbl.append(db_entry['mac'].encode('utf-8'))
        ldapl.append(ldap_entry[0][1]['dhcpHWAddress'][0].split()[1])
        # group
        db_gr = Group.query.filter_by(id=db_entry['group']).first()
        if db_gr:
            dbl.append(db_gr.name)
        ldapl.append(ldap_entry[0][0].split(',')[1][3:])
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



class Subnet(LDAPModel):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    netmask = db.Column(db.Integer)
    options = db.Column(db.Text)
    pools = db.relationship('Pool', backref='subnet', lazy='dynamic')
    calcranges = db.relationship('CalculatedRange', backref='subnet', lazy='dynamic', uselist=True)
    deployed = db.Column(db.Boolean, default=True)

    def dn(self):

        # return 'cn=%s,ou=Subnets,%s' % (self.name, server_dn())
        return 'cn=%s,%s' % (self.name, server_dn())

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
            # import pudb;pudb.set_trace()
            if json.loads(s.options)['dhcpComments'][0] == dhcpcomment_name:
                return s
        raise DhcpawnError


    @staticmethod
    def get_crid_list(subnet):
        ''' subnet is db instance
        returnes a list of calculated ranges id '''
        return [cr.id for cr in subnet.calcranges.all()]


    def allocate_free_ip(self):
        for cr in self.calcranges.all():
            try:
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
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'))
    # host = db.relationship("Host", backref='ip', uselist=False)
    deployed = db.Column(db.Boolean, default=True)

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
                    host=self.host_id)

    @staticmethod
    def is_ip_taken(addr):
        ''' returns the IPv4address(addr) is its available. otherwise ,will raise Dhcpawnerror
        with an explanatory msg'''

        try:
            res = IP.query.filter_by(address=addr).first()
        except Exception as e:
            raise DhcpawnError('something went wrong while looking for %s in DB (%s)' % (addr, e.__str__()))
        else:
            if res:
                raise DhcpawnError('ip %s already taken' % addr)
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
            # get_by_field_or_404(IP, 'address', IPv4Address(addr))
        except DhcpawnError as e:
            raise
        else:
            # if "does not exist" in e.__str__():
            cr = IP.get_calcrange(addr)
            if cr:
                ip = IP(address=IPv4Address(addr),
                    calcrange_id=cr.id)
                db.session.add(ip)
                try:
                    db.session.commit()
                except Exception as e:
                   raise DhcpawnError(e.__str__())
                else:
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
    def get_subnet(addr):
        ''' subnet instance is returned '''
        cr = IP.get_calcrange(addr)
        if cr:
            return cr.subnet
        else:
            return None

    @staticmethod
    def ip_in_subnet(addr, subnet):
        ''' get addr and subnet and check if ip address
        is in one of the subnet's calculated ranges '''
        if IP.get_subnet(addr) == Subnet.validate_by_name(subnet):
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
                    # ips=[ip.id for ip in self.ips],
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
        # import pudb;pudb.set_trace()
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
                except Exception as e:
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
    status = db.Column(db.String(10)) # possible values : Done/Failed/OnGoing
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

    def config(self):
        return  dict(id=self.id,
            status=self.status,
            request_type=self.request_type,
            drequest_result=json.loads(self.drequest_result) if self.drequest_result else None,
            params=json.loads(self.params),
            dtasks=[dtask.config() for dtask in self.dtasks.all()],
            err_str = self.err_str,
            reply_url = self.reply_url,
            replied=self.replied,
            )

    def refresh_status(self):
        ''' used for cases where request has celery tasks '''
        _logger.debug("refreshing dreq %s status (%s tasks)" % (self.id, len(self.dtasks.all())))
        failed = False
        running = False
        num_running = 0
        num_failed = 0
        num_passed = 0
        for dtask in self.dtasks.all():
            _logger.debug("task %s status %s" % (dtask.id, dtask.status))
            if self.status != 'Failed' and dtask.status == 'failed':
                # self.status = 'Failed'
                failed = True
                num_failed += 1
                # self.commit()
                # self.postreply()
            elif dtask.status == 'running':
                running = True
                num_running += 1
            else:
                num_passed += 1


        _logger.debug('PASSED: %s ; RUNNING: %s ; FAILED: %s' % (num_passed, num_running, num_failed))
        if failed:
            self.status = 'Failed'
            self.commit()
        if running:
            return "Request still has running tasks"

        if self.status != 'Failed':
            self.status = 'Done'
            self.commit()

        self.clean_on_failure()
        self.postreply()

        # if not failed and not running:
        #     # if we got here all tasks succeeded
        #     self.status = 'Done'
        #     self.commit()
        #     self.postreply()
        # elif :
    def clean_on_failure(self):
        '''for cases where the drequest failed ,at least one of the hosts didn't
        register properly, this method will clear all other hosts data from DB/LDAP'''

        if not self.status == 'Failed':
            return
        hosts = json.loads(self.params)
        _logger.info("HOSTS TO DELETE %s" % len(hosts))
        for h in hosts.keys():
            _logger.info("will try to delete %s" % h)
            continue
            h_inst = Host.query.get(hosts[h]['id'])
            try:
                h_inst.ldap_delete()
            except Exception as e:
                _logger.warning("failed cleaning %s data from LDAP after failure (%s) " % (h_inst.name, e.__str__()))
                pass

            try:
                db.session.delete(IP.query.get(hosts[h].ip_id))
                db.session.delete(Host.query.get(hosts[h].id))
                db.session.commit()
            except:
                _logger.warning("failed cleaning %s data from DB after failure (%s) " % (hosts[h].name, e.__str__()))
                pass



    def postreply(self):
        '''method to post drequest config to the reply_url
        when drequest finished (either failed or succeeded)'''
        if not self.replied and self.reply_url:
            url = '%s%s/' % (self.reply_url, self.id)
            _logger.info("Post reply to url %s" % url)
            res = requests.post(url, data=self.config())
            self.replied = True
            self.commit()

    def update_drequest(self, drequest_type=None, drequest_reply_url=None, drequest_result=None,
                        params=None, tasks_list=None, tasks_count=None):

        if params:
            self.params = json.dumps(params)
        if tasks_list:
            self.celery_tasks_list = json.dumps(tasks_list)
        if drequest_type:
            self.request_type = drequest_type
        if drequest_reply_url:
            self.reply_url = drequest_reply_url
        if drequest_result:
            self.drequest_result = drequest_result
        if tasks_count:
            self.celery_tasks_count = tasks_count

        self.commit()

    def commit(self):
        db.session.add(self)
        db.session.commit()
        _logger.debug("dreq %s was updated in DB" % self.id)

class Dtask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    celery_task_id = db.Column(db.String(50))
    status = db.Column(db.String(10)) # possible values: succeeded, failed, running
    desc = db.Column(db.String(50)) # short task description
    err_str = db.Column(db.Text, default='')
    dreq_id = db.Column(db.Integer, db.ForeignKey('req.id'))

    def __init__(self, dreq_id):
        self.status = "running"
        self.dreq_id = dreq_id
        self.commit()

    def commit(self):

        db.session.add(self)
        db.session.commit()

    def update(self, **kwargs):
        if 'celery_task_id' in kwargs:
            self.celery_task_id = kwargs.get('celery_task_id')
        if 'desc' in kwargs:
            self.desc = kwargs.get('desc')
        if 'status' in kwargs:
            self.status = kwargs.get('status')
        if 'err_str' in kwargs:
            self.err_str = kwargs.get('err_str')
        self.commit()

    def config(self):
        return dict(id=self.id,
                    dreq_id=self.dreq_id,
                    status=self.status,
                    description=self.desc,
                    err_str=self.err_str,
                    celery_task_id=self.celery_task_id)
