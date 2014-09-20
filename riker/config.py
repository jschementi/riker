import boto
import getpass
import json
import uuid
import os
from os import path

import boto_helpers

directory = path.expanduser('~/.riker')

def default_config():
    return {
        "instance_user": "ubuntu",
        "deploy_user": "dokku",
        "deploy_remote_name": "riker-deploy",
        "os_image_id": "ami-864d84ee",
        "instance_type": "t2.micro",
        "instance_key_pair_name": "riker",
        "base_instance_name": "riker-base-instance-v1",
        "security_groups": {
            "riker-instance": [
                ["tcp", "22", "22", "0.0.0.0/0", None],
                ["tcp", "80", "80", "0.0.0.0/0", None]
            ],
            "riker-load-balancer": [
                ["tcp", "80", "80", "0.0.0.0/0", None],
                ["tcp", "443", "443", "0.0.0.0/0", None]
            ]
        },
        "vpc_id": None,
        "subnet_id": None,
        "availability_zone": None,
        "system_name": None,
    }

def load_config(show_output=False):
    config_filename = path.join(directory, 'config')
    aws_dirty = False
    if not boto.config.has_option('Credentials', 'aws_access_key_id'):
        aws_access_key_id = getpass.getpass('AWS Access Key ID: ')
        boto.config.save_user_option('Credentials', 'aws_access_key_id', aws_access_key_id)
        aws_dirty = True
    if not boto.config.has_option('Credentials', 'aws_secret_access_key'):
        aws_secret_access_key = getpass.getpass('AWS Secret Access Key: ')
        boto.config.save_user_option('Credentials', 'aws_secret_access_key', aws_secret_access_key)
        aws_dirty = True
    if aws_dirty:
        print "-----> AWS configuration written to {}".format(boto.pyami.config.UserConfigPath)
    else:
        if show_output: print "-----> AWS configuration unchanged, see `{}`".format(boto.pyami.config.UserConfigPath)
    vpc = boto.connect_vpc()
    try:
        with open(config_filename, 'r') as config_file:
            config = json.loads(config_file.read())
    except IOError:
        config = default_config()
    dirty = False
    vpc_id = config.get('vpc_id')
    if not vpc_id:
        vpc_id = raw_input("AWS VPC ID (choose: {}): ".format(', '.join([v.id for v in vpc.get_all_vpcs()])))
        config['vpc_id'] = vpc_id
        dirty = True
    subnet_id = config.get('subnet_id')
    if not subnet_id:
        def format_subnet(s):
            return '{}({})'.format(s.id, s.availability_zone)
        possible_subnets = vpc.get_all_subnets(filters=[('vpcId', vpc_id)])
        subnet_id = raw_input("AWS VPC Subnet ID (choose: {}): ".format(', '.join(map(format_subnet, possible_subnets))))
        config['subnet_id'] = subnet_id
        dirty = True
    subnet = vpc.get_all_subnets(subnet_ids=[subnet_id])[0]
    if config['availability_zone'] != subnet.availability_zone:
        config['availability_zone'] = subnet.availability_zone
        dirty = True
    system_name = config.get('system_name')
    if not system_name:
        config['system_name'] = raw_input("Name of your \"system\" (press return for a uuid): ") or uuid.uuid1().hex
        dirty = True
    if dirty:
        config_filename = path.join(directory, 'config')
        if not path.exists(directory):
            os.makedirs(directory)
        with open(config_filename, 'w') as config_file:
            config_file.write(json.dumps(config, indent=2, separators=(',', ': ')))
            print "-----> Riker configuration written to {}".format(config_filename)
    else:
        if show_output: print "-----> Riker configuration unchanged, see `{}`".format(config_filename)
    def create_sgrs(memo, kvp):
        name = kvp[0]
        rules = kvp[1]
        sgrs = [boto_helpers.SecurityGroupRule(*rule) for rule in rules]
        memo[name] = sgrs
        return memo
    config['security_groups'] = reduce(create_sgrs, config['security_groups'].iteritems(), {})
    return config
