import collections
import os
import os.path
import utils
import fabric.api

def get_or_create_key_pair(conn, name, get_pem_filename):
    utils.log('info', 'Ensuring key pair exists', show_header=True)
    key_pair = conn.get_key_pair(name)
    if key_pair is None:
        utils.log('info', 'Not found: creating')
        key_pair = create_key_pair(conn, name, get_pem_filename)
    return key_pair

def create_key_pair(conn, name, get_pem_filename):
    key_pair = conn.create_key_pair(name)
    write_private_key_to_pem_file(key_pair, get_pem_filename)
    return key_pair

def write_private_key_to_pem_file(key_pair, get_pem_filename):
    filename = get_pem_filename(key_pair.name)
    if os.path.isfile(filename):
        raise RuntimeError('%s already exists' % filename)
    with open(filename, 'w') as f:
        utils.log('info', 'writing private key to %s' % filename)
        f.write(key_pair.material)
    os.chmod(filename, 0600)
    fabric.api.local('ssh-add %s' % (filename,))

def get_security_group(c, group_name):
    groups = [g for g in c.get_all_security_groups() if g.name == group_name]
    return groups[0] if groups else None

##############################################################################
# Based off of steder/aws_sg_recipe.py: https://gist.github.com/steder/1498451
##############################################################################

SecurityGroupRule = collections.namedtuple("SecurityGroupRule", ["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])

def ensure_security_groups(conn, security_groups, vpc_id):
    groups = []
    for group_name, rules in security_groups:
        group = get_or_create_security_group(conn, group_name, vpc_id=vpc_id)
        update_security_group(conn, group, rules)
        groups.append(group)
    return groups

def get_or_create_security_group(c, group_name, description="", vpc_id=None):
    """
    """
    groups = [g for g in c.get_all_security_groups() if g.name == group_name]
    group = groups[0] if groups else None
    if not group:
        print "-----> Creating group '%s'..."%(group_name,)
        group = c.create_security_group(group_name, "A group for %s"%(group_name,), vpc_id)
    return group


def modify_sg(c, group, rule, authorize=False, revoke=False):
    src_group = None
    if rule.src_group_name:
        src_group = c.get_all_security_groups([rule.src_group_name,])[0]

    if authorize and not revoke:
        print "       Authorizing missing rule %s..."%(rule,)
        group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=rule.cidr_ip,
                        src_group=src_group)
    elif not authorize and revoke:
        print "       Revoking unexpected rule %s..."%(rule,)
        group.revoke(ip_protocol=rule.ip_protocol,
                     from_port=rule.from_port,
                     to_port=rule.to_port,
                     cidr_ip=rule.cidr_ip,
                     src_group=src_group)


def authorize(c, group, rule):
    """Authorize `rule` on `group`."""
    return modify_sg(c, group, rule, authorize=True)


def revoke(c, group, rule):
    """Revoke `rule` on `group`."""
    return modify_sg(c, group, rule, revoke=True)


def update_security_group(c, group, expected_rules):
    """
    """
    print '-----> Updating group "%s"...'%(group.name,)
    #import pprint
    #print "Expected Rules:"
    #pprint.pprint(expected_rules)

    current_rules = []
    for rule in group.rules:
        if not rule.grants[0].cidr_ip:
            current_rule = SecurityGroupRule(rule.ip_protocol,
                              rule.from_port,
                              rule.to_port,
                              "0.0.0.0/0",
                              rule.grants[0].name)
        else:
            current_rule = SecurityGroupRule(rule.ip_protocol,
                              rule.from_port,
                              rule.to_port,
                              rule.grants[0].cidr_ip,
                              None)

        if current_rule not in expected_rules:
            revoke(c, group, current_rule)
        else:
            current_rules.append(current_rule)

    #print "Current Rules:"
    #pprint.pprint(current_rules)

    for rule in expected_rules:
        if rule not in current_rules:
            authorize(c, group, rule)

##############################################################################

