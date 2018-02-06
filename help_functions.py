import json
import re
import logbook
from ldap import SCOPE_SUBTREE
from ipaddress import IPv4Address, IPv4Network
from functools import wraps

from flask import jsonify, current_app
from sqlalchemy.exc import IntegrityError
from celery.result import AsyncResult
from cob import db
from cob.project import get_project

_logger = logbook.Logger(__name__)
##### Helping functions ########


class DhcpawnError(Exception):
    pass

def get_by_id(model, id):

    toreturn =  model.query.get(id)
    if not toreturn:
        raise DhcpawnError("%s with id %s does not exist in db" % (model.__name__, str(id)))
    return toreturn


def get_by_field(model, field, value):
    """

    :param model: IP, CalcRange, DhcpRange, Subnet,...
    :param field: "name", "address" - its one of the column names for the provided model
    :param value: value by which we filter
    :return: DhcpawnError , None or the inst we found
    """

    fieldDict = {
        'name':    model.query.filter_by(name=value) if field=='name' else None,
        'address': model.query.filter_by(address=value) if field=='address' else None,
        'id':      model.query.filter_by(id=value) if field=='id' else None,
        'mac':     model.query.filter_by(mac=value) if field=='mac' else None,
        'duptype': model.query.filter_by(duptype=value) if field=='duptype' else None,
        }
    try:
        rv = fieldDict[field].all() if field == 'duptype' else fieldDict[field].first()
    except KeyError:
        raise DhcpawnError("Field value unsupported - please update this function (get_by_field) before continuing.")
    except IntegrityError:
        raise DhcpawnError("%s %s does not exist" % (model.__name__, value))

    if rv == None:
        raise DhcpawnError("%s with %s=%s does not exist" % (model.__name__, field, value))

    return rv

def _get_or_none(model, id):
    if id:
        return model.query.get(id)
    return None

def subnet_get_calc_ranges(subnet):
    """ given a subnet ,this function will return a list of
    calculated ranges belonging to it """
    return [crange.id for crange in subnet.calcranges.all()]



def gen_resp(drequest=None, result=None, errors=None, msg=None):
    ''' return generic response '''

    if drequest:
        current_req =  drequest.query.filter_by(id=drequest.id).first()

    if drequest and current_req:
        status = current_req.status
        if not result:
            result = current_req.config()
    elif errors:
        status = 'Failed'
    else:
        status = 'Done'

    returned = {
        'result': result,
        'errors': errors,
        'request_id': drequest.id if drequest else None,
        'user_msg': msg,
        'status': status
        }
    return jsonify(returned)

def gen_resp_deco(func):
    ''' decorator for generating and returning the generic
    response of dhcapwn '''
    @wraps(func)
    def decorator(*args, **kwargs):
        if args:
            obj = args[0]
            func(*args, **kwargs)
            if obj and obj.errors:
                return gen_resp(errors=obj.errors, msg=obj.msg)
        else:
            returned = func(*args, **kwargs)
            if any(key not in returned for key in ['result', 'errors']):
                return gen_resp(errors=f"Wrong function return value {func}")
            return gen_resp(result=returned['result'], errors=returned['errors'])
        return gen_resp(drequest=obj.drequest,
                        result=obj.result,
                        msg=obj.msg)
    return decorator


def update_req(func):
    ''' a decorator that will update dhcpawn request
        at the end of a relevant method. POST/DELETE/PUT
    '''

    def decorator(*args, **kwargs):
        obj = args[0]
        db.session.add(obj.drequest)
        db.session.commit()
        returned = func(*args, **kwargs)
        if obj.errors:
            return
        # if isinstance(returned, dict) and returned.get('status', None) == 'error':
            # return gen_resp(errors=returned['description'])

        if hasattr(obj, 'drequest'):
            _logger.debug("Updating dRequest Object")
            obj.drequest.update_drequest(drequest_type=obj.drequest_type,
                                         drequest_reply_url=obj.drequest_reply_url,
                                         drequest_result=json.dumps(obj.result),
                                         tasks_list=get_full_chain_tasks_list(obj.res),
                                         params=obj.data)

    return decorator

def get_full_chain_tasks_list(top_async_result):

    full_list = []
    if not top_async_result:
        return []
    if top_async_result.parent:
        async_res = top_async_result
        full_list = [top_async_result.id]
        while async_res.parent:
            full_list.append(async_res.parent.id)
            async_res = async_res.parent
    elif top_async_result.children:
        for async_child in top_async_result.children:
            full_list.append(async_child.id)
    elif isinstance(top_async_result, AsyncResult):
        # its just a simple task ,no group ,no chain
        return [top_async_result.id]
    else:
        return []
    return full_list

def gen_drequest_in_db(func):
    ''' decorator to actually add a new instance of
    drequest to DB so that in POST/PUT/DELETE
    its done and not in GET'''

    def decorator(*args, **kwargs):
        obj = args[0]
        db.session.add(obj.drequest)
        db.session.commit()
        returned = func(*args, **kwargs)
        return returned
    return decorator

def parse_ldap_entry(entry):
    """ when running ldap, if everything was ok,
    we get a list with data. this func will parse it
    into a dict.
    """
    tmpd = dict()
    info = entry[0]
    dn = info[0]
    objectClass = info[1]['objectClass']
    cn = info[1]['cn'][0].decode('utf-8')
    dhcpStatements = info[1]['dhcpStatements'][0].decode('utf-8').split()[1] if 'dhcpStatements' in info[1] else None
    dhcpHWAddress = info[1]['dhcpHWAddress'][0].decode('utf-8').split()[1] if 'dhcpHWAddress' in info[1] else None
    tmpd[cn] = {'dn': dn,
                'ip': dhcpStatements,
                'mac': dhcpHWAddress,
                'objClass': objectClass
    }
    return tmpd

def extract_skeleton():
    '''
    use this function to extract LDAP skeleton for first dhcpawn deployment
    '''
    config = get_project().config
    skeleton = {'groups':[],
                'subnets':{},
                'dhcpranges':{},
                'pools':{},
                'calcranges':{},
                }
    basedn = config['PRODUCTION_LDAP_DN']
    ldap_obj = current_app.ldap_obj
    rawdata = current_app.ldap_obj.search_s(basedn, SCOPE_SUBTREE, '(objectClass=*)')

    s = dict()
    p = dict()
    for e in rawdata:
        if 'dhcpGroup' in [el.decode('utf-8') for el in e[1]['objectClass']]:
            skeleton['groups'].append(e[1]['cn'][0].decode('utf-8'))

        elif 'dhcpSubnet' in [el.decode('utf-8') for el in e[1]['objectClass']]:
            name = e[1]['cn'][0].decode('utf-8')
            routers = ''
            ddns_domainname = ''
            netmask = e[1]['dhcpNetMask'][0].decode('utf-8')

            if e[1].get('dhcpOption'):
                for item in e[1]['dhcpOption']:
                    if item.decode('utf-8').startswith('routers'):
                        routers = ','.join(item.decode('utf-8').replace(",","").split(" ")[1:]) # taking only the default gateway ip , excluding the "routers" word.
            if e[1].get('dhcpStatements'):
                for item in e[1]['dhcpStatements']:
                    search_ddns_statement = re.search('ddns-domainname (.+)', item.decode('utf-8'))
                    if search_ddns_statement is not None:
                        ddns_domainname = search_ddns_statement.group(1).replace("\"","")
            options = {
                'dhcpComments': [e[1]['dhcpComments'][0].decode('utf-8')],
                'dhcpStatements': ['ddns-domainname %s' % ddns_domainname],
                'dhcpOption': ['routers %s' % routers]
            }
            skeleton['subnets'].update({name: {'netmask':netmask, 'options':options}})
            # subnets += yaml.dump([{'url': url, 'data': {'name':name, 'netmask':netmask, 'options':options, 'deployed':deploy}}])
            s[name] = {'netmask':netmask}

        elif 'dhcpPool' in [el.decode('utf-8') for el in e[1]['objectClass']]:
            name = e[1]['cn'][0].decode('utf-8')
            subnet_name = e[0].replace(",","").split("cn=")[2]
            skeleton['pools'].update({name: {'subnet_name':subnet_name}})

            min_dhcprange = e[1]['dhcpRange'][0].split()[0].decode('utf-8')
            max_dhcprange = e[1]['dhcpRange'][0].split()[1].decode('utf-8')
            skeleton['dhcpranges'].update({name: {'max':max_dhcprange, 'min':min_dhcprange}})

            p[subnet_name] = {'mindhcp':min_dhcprange, 'maxdhcp':max_dhcprange}

    # Calculate and create calcranges yml
    for sub in s:
        if not p.get(sub):
            continue
        sname = sub
        smask = s[sub]['netmask']
        mind = p[sub]['mindhcp']
        maxd = p[sub]['maxdhcp']
        lastip = list(IPv4Network("%s/%s" % (sname,smask)).hosts())[-1]
        ranges = [[IPv4Address(sname)+1,IPv4Address(mind)-1], [IPv4Address(maxd)+1, lastip]]
        skeleton['calcranges'].setdefault(sname, [])
        # lower range
        if ranges[0][1] > ranges[0][0]:
            skeleton['calcranges'][sname].append({'min':str(ranges[0][0]),'max':str(ranges[0][1])})
            # skeleton['calcranges'].update({sname: {'min':str(ranges[0][0]),'max':str(ranges[0][1])}})
            # calcranges += yaml.dump([{'url':'/rest/calcranges/', 'data': {'subnet_name':sname, 'min':str(ranges[0][0]),'max':str(ranges[0][1]), 'deployed':deploy}}])
        # upper range
        if ranges[1][1] > ranges[1][0]:
            skeleton['calcranges'][sname].append({'min':str(ranges[1][0]),'max':str(ranges[1][1])})
            # skeleton['calcranges'].update({sname: {'min':str(ranges[1][0]),'max':str(ranges[1][1])}})
            # calcranges += yaml.dump([{'url':'/rest/calcranges/', 'data': {'subnet_name':sname, 'min':str(ranges[1][0]),'max':str(ranges[1][1]), 'deployed':deploy}}])

    return skeleton
