import sys
from os import walk, getcwd
from os.path import join, isdir, expanduser, relpath, normpath, basename
import os.path
from operator import itemgetter
import datetime
import time
import re
import json
import uuid

import boto
import boto.ec2
from boto.route53.record import ResourceRecordSets
from boto.ec2.elb import HealthCheck
from boto.ec2.autoscale import LaunchConfiguration
from boto.ec2.autoscale import AutoScalingGroup
from boto.ec2.elb.attributes import ConnectionDrainingAttribute
from fabric.api import task, run, local, env, sudo, lcd, execute, put
from fabric.contrib.files import exists, append, sed
from fabric.operations import reboot
import giturlparse
from tld import get_tld
import pybars

import git_helpers as git
import boto_helpers
import config as riker_config
from utils import poll_for_condition, log, first
from retry import synchronize

import fabric
fabric.state.output.everything = True

# http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_website_region_endpoints
s3_website_regions = {
    'us-east-1': ('s3-website-us-east-1.amazonaws.com.', 'Z3AQBSTGFYJSTF'),
    'us-west-2': ('s3-website-us-west-2.amazonaws.com.', 'Z3BJ6K6RIION7M'),
    'us-west-1': ('s3-website-us-west-1.amazonaws.com.', 'Z2F56UZL2M1ACD'),
    'eu-west-1': ('s3-website-eu-west-1.amazonaws.com.', 'Z1BKCTXD74EZPE'),
    'ap-southeast-1': ('s3-website-ap-southeast-1.amazonaws.com.', 'Z3O0J2DXBE1FTB'),
    'ap-southeast-2': ('s3-website-ap-southeast-2.amazonaws.com.', 'Z1WCIGYICN2BYD'),
    'ap-northeast-1': ('s3-website-ap-northeast-1.amazonaws.com.', 'Z2M4EHUR26P7ZW'),
    'sa-east-1': ('s3-website-sa-east-1.amazonaws.com.', 'Z7KQH4QJS55SO'),
    'us-gov-west-1': ('s3-website-us-gov-west-1.amazonaws.com.', 'Z31GFT0UA1I2HV')
}

aws = None
initialized = False
config = riker_config.default_config()

def get_public_dns(instances):
    return [inst.public_dns_name for inst in instances]

def ensure_running(instances, timeout=600, poll_delay=10):
    if len(instances) == 0:
        return
    log('info', 'Waiting for instances {} to be running'.format(instances), show_header=True)
    def get_status():
        try:
            return aws.conn.get_all_instance_status([inst.id for inst in instances])
        except boto.exception.EC2ResponseError:
            log('info', 'No status yet')
    def is_status_ok(statuses):
        #for s in statuses:
        #    log('info', 'state={}, system_status={}'.format(s.state_name, s.system_status.status))
        return len(statuses) > 0 and \
            all([s.state_name == 'running' and s.system_status.status == 'ok' for s in statuses])
    poll_for_condition(get_status, is_status_ok, timeout, poll_delay)
    [instance.update() for instance in instances]

def ensure_complete(image_ids, timeout=1200, poll_delay=10):
    if len(image_ids) == 0:
        return
    log('info', 'Waiting for image {} to be available'.format(image_ids), show_header=True)
    def get_image(image_id):
        def _get_image():
            try:
                return aws.conn.get_image(image_id)
            except boto.exception.EC2ResponseError:
                log('info', 'No state yet')
        return _get_image
    def is_image_available(image):
        #log('info', 'state={}'.format(image.state if image is not None else 'noimage',))
        return image is not None and image.state == 'available'
    for image_id in image_ids:
        poll_for_condition(get_image(image_id), is_image_available, timeout, poll_delay)

class AWS(object):

    @classmethod
    def from_config(cls, config):
        return cls(key_pair_name=config['instance_key_pair_name'],
                   vpc_id=config['vpc_id'],
                   availability_zone=config['availability_zone'],
                   subnet_id=config['subnet_id'],
                   security_groups=config['security_groups'],
                   base_image=config['os_image_id'],
                   instance_type=config['instance_type'])

    def __init__(self, key_pair_name, security_groups, base_image, instance_type, vpc_id, availability_zone, subnet_id):
        self.key_pair_name = key_pair_name
        self.security_groups = security_groups
        self.base_image = base_image
        self.instance_type = instance_type
        self.vpc_id = vpc_id
        self.availability_zone = availability_zone
        self.subnet_id = subnet_id

    def connect(self):
        log('info', 'Connecting to AWS', show_header=True)
        self.conn = boto.connect_ec2()

    def setup(self):
        log('info', 'Setting up AWS', show_header=True)
        boto_helpers.get_or_create_key_pair(self.conn, self.key_pair_name, get_pem_filename)
        boto_helpers.ensure_security_groups(self.conn,
                                            self.security_groups.items(),
                                            self.vpc_id)

    def run_instance(self, group_ids, ami=None):
        if ami is None:
            ami = self.base_image
        log('info', 'running instance')
        return self.conn.run_instances(ami,
                                       instance_type=self.instance_type,
                                       security_group_ids=group_ids,
                                       key_name=self.key_pair_name,
                                       subnet_id=self.subnet_id)

    def create_tags(self, ids, tags):
        log('info', 'tagging resource {}: {}'.format(ids, tags))
        self.conn.create_tags(ids, tags)

    def create_image(self, instance_ids, name):
        log('info', 'creating image from {}'.format(instance_ids))
        image_ids = [self.conn.create_image(instance_id=instance_id,
                                            name=name)
                     for instance_id in instance_ids]
        log('info', 'images: {}'.format(image_ids))
        return image_ids

    def get_security_group(self, name):
        return boto_helpers.get_security_group(self.conn, name)

    def get_security_group_id(self, name):
        return self.get_security_group(name).id


class Repo(object):

    def __init__(self, name, path, remote_url=None, remote_branch=None, local_branch=None):
        self.remote_url = remote_url
        self.remote_branch = remote_branch
        self.local_branch = local_branch
        self.name = name
        self._path = path
        self.app_config = config.get('apps', {}).get(name, {})

        self.set_prop_from_app_config('remote_url')
        self.set_prop_from_app_config('remote_branch')
        self.set_prop_from_app_config('local_branch')

    def set_prop_from_app_config(self, prop):
        if getattr(self, prop) is None:
            setattr(self, prop, self.app_config.get(prop))

    @property
    def path(self):
        return self._path or expanduser(join(riker_config.directory, 'apps', self.name))

    @synchronize('repo_fetch.lock')
    def fetch(self):
        if self._path: return
        log('info', 'Fetching app {} from {} to {}'.format(self.name, self.remote_url, self.path), show_header=True)
        git_remote_host = giturlparse.parse(self.remote_url).host
        ssh.remove_from_known_hosts(git_remote_host)
        ssh.add_to_known_hosts(git_remote_host)
        if not isdir(self.path):
            local('mkdir -p {}'.format(self.path))
            git.clone_repo(self.remote_url, self.path, self.local_branch)
        else:
            git.ensure_is_repo(self.path)
            with lcd(self.path):
                local_branch = self.local_branch if self.local_branch is not None else 'master'
                local('git reset --hard HEAD')
                local('git pull origin {}'.format(local_branch))
                local('git fetch')
                local('git checkout {}'.format(local_branch))

    def head_commit_id(self):
        with lcd(self.path):
            return git.get_head_commit_sha1()

    def get_deploy_remote_url(self, host):
        return '{}@{}:{}'.format(config['deploy_user'], host, self.name)

class NoAppFoundError(Exception):
    pass

class App(object):

    def __init__(self, env_name, app_name):
        if git.is_repo(getcwd()):
            app_path = getcwd()
        else:
            app_path = None

        if app_name is None:
            if app_path is not None:
                app_name = basename(app_path)
            else:
                raise Exception("Riker App: either provide an app name, or " +
                                "current directory must be a git repo")
        self.repo = Repo(app_name, app_path)

        if env_name is None:
            env_name = 'dev'
        self.env_name = env_name

    @property
    def name(self):
        return '{}/{}'.format(self.env_name, self.repo.name)

    @property
    def config(self):
        return self.repo.app_config

class CachedObject(object):

    def create(self, *args, **kwargs):
        raise NotImplementedError()

    def get(self, *args, **kwargs):
        raise NotImplementedError()

    def get_or_create(self, *args, **kwargs):
        obj = self.get(*args, **kwargs)
        if obj is None or (hasattr(obj, '__len__') and len(obj) == 0):
            obj = self.create(*args, **kwargs)
        return obj

class AppImage(CachedObject):

    def __init__(self, app, instances):
        self.app = app
        self.instances = instances

    def tags(self):
        return {
            'app': self.app.name,
            'version': self.app.repo.head_commit_id(),
            'timestamp': datetime.datetime.now().isoformat(),
            'deploy-id': self.get_deploy_id()
        }

    def image_name(self):
        tags = self.tags()
        return "{}/{}/{}".format(tags['app'], tags['deploy-id'], tags['version'])

    def get_deploy_id(self):
        images = [aws.conn.get_image(instance.image_id) for instance in self.instances]
        deploy_id_values = [image.tags.get('deploy-id') for image in images]
        deploy_ids = [int(deploy_id) for deploy_id in deploy_id_values if deploy_id is not None]
        latest_deploy_id = max(deploy_ids) if len(deploy_ids) > 0 else 0
        return latest_deploy_id + 1

    def create(self):
        log('info', 'Creating app image {} (deploy-id: {})'.format(self.app.name, self.get_deploy_id()), show_header=True)
        image_ids = aws.create_image([inst.id for inst in self.instances], self.image_name())
        aws.create_tags(image_ids, self.tags())
        ensure_complete(image_ids)
        return image_ids

    def get(self):
        return None

class LatestAppImage(CachedObject):
    def __init__(self, app):
        self.app = app
    def get(self):
        print '-----> Looking for latest app image: {}'.format(self.app.name)
        images = aws.conn.get_all_images(owners=['self'], filters={'tag:app': self.app.name,
                                                                   'tag-key': 'deploy-id',
                                                                   'tag-key': 'version'})
        images_ordered_by_deploy_id = sorted(images,
                                             key=lambda image: itemgetter('deploy-id')(image.tags), reverse=True)
        for image in images_ordered_by_deploy_id:
            print '-----> Found {} (deploy-id: {}) (image: {})'.format(self.app.name, image.tags['deploy-id'], image.id)
            return image
        print '-----> First deploy of {}!'.format(self.app.name)
        return None
    def create(self):
        return None

class AppInstance(CachedObject):

    def __init__(self, app, image, group_ids):
        self.app = app
        self.image = image
        self.group_ids = group_ids

    def create(self):
        print '-----> App instance for {} not found, running from image {}'.format(self.app.name, self.image.id)
        reservation = aws.run_instance(self.group_ids, self.image.id)
        instance_ids = [inst.id for inst in reservation.instances]
        aws.create_tags(instance_ids, {
            'app_instance': 'true',
            'deployed': 'false',
            'app': self.app.name,
            'timestamp': datetime.datetime.now().isoformat()
        })
        return reservation.instances

    def get(self):
        print '-----> Looking for app instance to deploy to: {} (image: {})'.format(self.app.name, self.image.id)
        return aws.conn.get_only_instances(filters={'tag:app': self.app.name,
                                                    'tag:app_instance': 'true',
                                                    'tag:deployed': 'true',
                                                    'image-id': self.image.id,
                                                    'instance-state-name': 'running'})

    def deploy_instances(self, instances):
        print '-----> Deploying app {} to instances {}'.format(self.app.name, instances)
        ensure_running(instances)
        hosts = get_public_dns(instances)
        execute(self.deploy(), hosts=hosts)

    def update_instances_config(self, instances):
        print '-----> Updating config of {} to instances {}'.format(self.app.name, instances)
        ensure_running(instances)
        hosts = get_public_dns(instances)
        execute(update_config, self.app.repo.name, self.app.env_name, hosts=hosts)

    def deploy(self):
        @task
        def _deploy():
            app_name = self.app.name
            repo_name = self.app.repo.name
            env_name = self.app.env_name
            repo_path = self.app.repo.path
            remote_branch = self.app.repo.remote_branch
            local_branch = self.app.repo.local_branch
            remote_name = config['deploy_remote_name']
            log('info', 'Deploying app: {}'.format(app_name), show_header=True)
            git.ensure_is_repo(repo_path)
            with lcd(repo_path):
                git.ensure_remote(remote_name, self.app.repo.get_deploy_remote_url(env.host))
                ssh.add_to_known_hosts(env.host)
                put('~/.ssh/id_rsa.pub', '~', mirror_local_mode=True)
                run('sudo sshcommand acl-remove {} ubuntu'.format(config['deploy_user']), warn_only=True)
                run('cat ~/id_rsa.pub | sudo sshcommand acl-add {} ubuntu'.format(config['deploy_user']))
                run('rm ~/id_rsa.pub')
                git.push_repo(remote_name, branch_name=remote_branch, local_branch_name=local_branch, auto_confirm=True)
            # make dokku (nginx) serve this app for any server name
            # this is OK since we're only deploying one app per server
            run('dokku domains:set {} "{}"'.format(repo_name, '~^(www\.)?(?<domain>.+)$'))
            update_config(repo_name, env_name)
            ssh.remove_from_known_hosts(env.host)
            instance_id = get_instance_id_from_server()
            aws.create_tags([instance_id], {
                'deployed': 'true',
                'version': self.app.repo.head_commit_id(),
                'timestamp': datetime.datetime.now().isoformat()
            })
        return _deploy

def configure_nginx_xforwarded_passthru(name):
    sed("/home/dokku/{}/nginx.conf".format(name), 'X-Forwarded-Proto \$scheme', 'X-Forwarded-Proto \$real_scheme', use_sudo=True)
    sed("/home/dokku/{}/nginx.conf".format(name), 'X-Forwarded-For \$remote_addr', 'X-Forwarded-For \$real_remote_addr', use_sudo=True)
    sed("/home/dokku/{}/nginx.conf".format(name), 'X-Forwarded-Port \$server_port', 'X-Forwarded-Port \$real_server_port', use_sudo=True)

class BaseImage(CachedObject):

    def __init__(self, name, base_instance):
        self.name = name
        self.base_instance = base_instance

    def get_or_create_base_instance(self):
        instances = self.base_instance.get_or_create()
        if len(instances) != 1:
            raise Exception("1 base instance must be running")
        self.base_instance.provision_instances(instances)
        return instances

    def create(self):
        print '-----> Creating base image {}'.format(self.name)
        instances = self.get_or_create_base_instance()
        instance_ids = [inst.id for inst in instances]
        image_ids = aws.create_image(instance_ids, self.name)
        aws.create_tags(image_ids, {
            'base_image': 'true',
            'timestamp': datetime.datetime.now().isoformat()
        })
        ensure_complete(image_ids)
        terminate_instances(instance_ids)
        for image_id in image_ids:
            return aws.conn.get_image(image_id)
        return None

    def get(self):
        print '-----> Getting base image {}'.format(self.name)
        images = aws.conn.get_all_images(owners=['self'], filters={'name': self.name, 'tag:base_image': 'true'})
        image_ids = [image.id for image in images]
        ensure_complete(image_ids)
        for image_id in image_ids:
            print '-----> Found {}'.format(image_id)
            return aws.conn.get_image(image_id)
        print '-----> Not found'
        return None

def get_instance_id_from_server():
    return run('curl http://169.254.169.254/latest/meta-data/instance-id')

class BaseInstance(CachedObject):

    def __init__(self, name, image, group_ids):
        self.image = image
        self.group_ids = group_ids
        self.name = name

    def create(self):
        print '-----> Base instance {} not found, running from image {}'.format(self.name, self.image.id)
        reservation = aws.run_instance(self.group_ids, self.image.id)
        instances = reservation.instances
        instance_ids = [inst.id for inst in instances]
        aws.create_tags(instance_ids, {
            'Name': self.name,
            'base_instance': 'true',
            'provisioned': 'false'
        })
        return instances

    def get(self):
        print '-----> Getting base instance {} (image {})'.format(self.name, self.image.id)
        return aws.conn.get_only_instances(filters={'tag:Name': self.name,
                                                    'tag:base_instance': 'true',
                                                    'image-id': self.image.id,
                                                    'instance-state-name': 'running'})

    def provision_instances(self, instances):
        ensure_running(instances)
        hosts = get_public_dns(instances)
        execute(self.provision(), hosts=hosts)

    def provision(self):
        @task
        def _provision():
            self.add_swap_space()
            self.install_mosh()
            self.install_docker()
            self.install_dokku()
            self.configure_nginx()
            aws.create_tags([get_instance_id_from_server()], {
                'provisioned': 'true'
            })
        return _provision

    # @synchronize('add_swap_space.lock', is_remote=True)
    def add_swap_space(self):
        # t2.micro instances only have 512MB RAM, so compensate with swap space.
        log('info', 'Creating swap', show_header=True)
        if exists('/extraswap', use_sudo=True):
            log('info', 'Swap already exists')
            return
        sudo('dd if=/dev/zero of=/extraswap bs=1M count=512')
        sudo('chown root:root /extraswap')
        sudo('chmod 600 /extraswap')
        sudo('mkswap /extraswap')
        sudo('swapon /extraswap')
        append('/etc/fstab', '/extraswap swap swap defaults 0 0', use_sudo=True)
        sudo('swapon -a')

    # @synchronize('install_docker.lock', is_remote=True)
    def install_docker(self):
        """
        http://docs.docker.com/installation/ubuntulinux/#ubuntu-trusty-1404-lts-64-bit
        """
        log('info', 'Installing docker', show_header=True)
        run('curl -s https://get.docker.io/ubuntu/ > ~/docker_install.sh')
        sudo('sh ~/docker_install.sh; rm -f ~/docker_install.sh')

    # @synchronize('install_dokku.lock', is_remote=True)
    def install_dokku(self):
        """
        https://github.com/progrium/dokku
        """
        log('info', 'Installing dokku', show_header=True)
        run('curl -sL https://raw.github.com/progrium/dokku/v0.3.15/bootstrap.sh > ~/dokku-install.sh')
        sudo('DOKKU_TAG=v0.3.15 bash ~/dokku-install.sh; rm -f ~/dokku-install.sh')
        reboot(wait=5*60)
        sudo('git clone https://github.com/statianzo/dokku-supervisord.git /var/lib/dokku/plugins/dokku-supervisord')
        sudo('git clone https://github.com/neam/dokku-custom-domains.git /var/lib/dokku/plugins/custom-domains')
        sudo('git clone https://github.com/musicglue/dokku-user-env-compile.git /var/lib/dokku/plugins/user-env-compile')
        sudo('dokku plugins-install')

    # @synchronize('install_mosh.lock', is_remote=True)
    def install_mosh(self):
        log('info', 'Installing mosh', show_header=True)
        sudo('add-apt-repository -y ppa:keithw/mosh')
        sudo('apt-get update -y')
        sudo('apt-get install -y python-software-properties')
        sudo('apt-get install -y mosh')

    # @synchronize('configure_nginx.lock', is_remote=True)
    def configure_nginx(self):
        log('info', 'Configuring nginx', show_header=True)
        # nginx default domain name cache size is 64 bytes per domain. This may be
        # too small for EC2 public domain names, so increase to 256 bytes.
        sed('/etc/nginx/nginx.conf', 'server_names_hash_bucket_size 64;', 'server_names_hash_bucket_size 256;', use_sudo=True)

class ssh(object):

    @staticmethod
    @synchronize('add_to_known_hosts.lock')
    def add_to_known_hosts(host):
        ip = local('dig +short {}'.format(host), capture=True).strip()
        local('ssh-keyscan -H {} >> ~/.ssh/known_hosts'.format(host))
        local('ssh-keyscan -H {} >> ~/.ssh/known_hosts'.format(ip))
        local('ssh-keyscan -H {},{} >> ~/.ssh/known_hosts'.format(host, ip))

    @staticmethod
    @synchronize('remove_from_known_hosts.lock')
    def remove_from_known_hosts(host):
        ip = local('dig +short {}'.format(host), capture=True).strip()
        # http://serverfault.com/questions/132970/can-i-automatically-add-a-new-host-to-known-hosts
        local('ssh-keygen -R {}'.format(host))
        local('ssh-keygen -R {}'.format(ip))
        local('ssh-keygen -R {},{}'.format(host, ip))

def get_pem_filename(name):
    return expanduser(join(riker_config.directory, '{}.pem'.format(name)))

def get_config_path(env_name):
    return expanduser(join(riker_config.directory, 'envs', env_name))

def terminate_instances(instance_ids):
    log('info', 'Terminating instances: {}'.format(instance_ids), show_header=True)
    return aws.conn.terminate_instances(instance_ids)

def get_config(app, env):
    config_path = get_config_path(env)
    cfg_path = join(config_path, '{}.env'.format(app))
    log('info', "looking for config at cfg_path: {}".format(cfg_path))
    try:
        with open(cfg_path) as f:
            cfg = f.read().replace("\n", ' ').strip()
        return cfg
    except IOError:
        return None

def test_docker_installation():
    sudo('docker run -i -t ubuntu /bin/bash -c "uname -a"')

@task
def update_config(app, env, clear='yes'):
    log('info', 'Updating config for {}'.format(app), show_header=True)
    cfg = get_config(app, env)
    if cfg is None:
        log('info', "No configuration found for {}".format(app))
        return
    if clear == 'yes':
        sudo('truncate -s0 /home/{}/{}/ENV'.format(config['deploy_user'], app), user=config['deploy_user'])
    sudo('dokku config:set {} {}'.format(app, cfg), user=config['deploy_user'])

    # make nginx pass-through x-forwarded-* headers
    nginx_transparent_forward = """map $http_x_forwarded_proto $real_scheme {
  default $http_x_forwarded_proto;
  ''      $scheme;
}
map $http_x_forwarded_for $real_remote_addr {
  default $http_x_forwarded_for;
  ''      $remote_addr;
}
map $http_x_forwarded_port $real_server_port {
  default $http_x_forwarded_port;
  ''      $server_port;
}
"""
    sudo('rm -f /etc/nginx/conf.d/x-forwarded-passthru.conf')
    append('/etc/nginx/conf.d/x-forwarded-passthru.conf', nginx_transparent_forward, use_sudo=True)
    configure_nginx_xforwarded_passthru(app)
    sudo('/etc/init.d/nginx restart')

def logs(app, tail='no'):
    run('dokku logs {}{}'.format(app, ' -t' if tail == 'yes' else ''))

def ps():
    sudo('docker ps')

def deploy_to_single_instance(app_name, env_name):
    global aws

    aws = AWS.from_config(config)

    aws.connect()

    aws.setup()

    env.key_filename = get_pem_filename(aws.key_pair_name)

    os_image = aws.conn.get_image(aws.base_image)

    group_ids=[aws.get_security_group_id('riker-instance')]

    app = App(env_name, app_name)

    app.repo.fetch()

    base_image = BaseImage(name=config['base_instance_name'],
                           base_instance=BaseInstance(name=config['base_instance_name'],
                                                      image=os_image,
                                                      group_ids=group_ids)
                         ).get_or_create()

    app_inst = AppInstance(app=app, image=base_image, group_ids=group_ids)
    app_instances = app_inst.get_or_create()
    app_inst.deploy_instances(app_instances)

    print '=====> DONE!'

def create_app_ami(app_name, env_name):
    global aws

    aws = AWS.from_config(config)

    aws.connect()

    aws.setup()

    env.key_filename = get_pem_filename(aws.key_pair_name)

    os_image = aws.conn.get_image(aws.base_image)

    group_ids=[aws.get_security_group_id('riker-instance')]

    app = App(env_name, app_name)

    base_image = BaseImage(name=config['base_instance_name'],
                           base_instance=BaseInstance(name=config['base_instance_name'],
                                                      image=os_image,
                                                      group_ids=group_ids)
                          ).get_or_create()

    existing_app_image = LatestAppImage(app).get()

    app_inst = AppInstance(app=app,
                           image=existing_app_image or base_image,
                           group_ids=group_ids
                          )
    app_instances = app_inst.get_or_create()


    app.repo.fetch()

    app_inst.deploy_instances(app_instances)

    app_img = AppImage(app=app,
                       instances=app_instances
                      )
    app_images = app_img.get_or_create()

    terminate_instances([inst.id for inst in app_instances])

    print '-----> DONE: {} images ready'.format(app_images)

def deploy_config_update(app_name, env_name):
    global aws
    aws = AWS.from_config(config)
    aws.connect()
    aws.setup()
    env.key_filename = get_pem_filename(aws.key_pair_name)
    os_image = aws.conn.get_image(aws.base_image)
    group_ids=[aws.get_security_group_id('riker-instance')]
    app = App(env_name, app_name)
    base_image = BaseImage(name=config['base_instance_name'], base_instance=BaseInstance(name=config['base_instance_name'], image=os_image, group_ids=group_ids)).get_or_create()
    existing_app_image = LatestAppImage(app).get()
    if not existing_app_image:
        raise Exception("Need previous deployment to update config!")
    app_inst = AppInstance(app=app, image=existing_app_image or base_image, group_ids=group_ids)
    app_instances = app_inst.get_or_create()
    app_inst.update_instances_config(app_instances)
    app_img = AppImage(app=app, instances=app_instances)
    app_images = app_img.get_or_create()
    terminate_instances([inst.id for inst in app_instances])
    print '-----> DONE: {} images ready'.format(app_images)

def deploy_latest_app_ami(app_name, env_name):

    global aws
    aws = AWS.from_config(config)

    aws.connect()

    lb_group_ids=[aws.get_security_group_id('riker-load-balancer')]
    inst_group_ids=[aws.get_security_group_id('riker-instance')]

    app = App(env_name, app_name)

    health_check_target = app.config.get('health_check', 'TCP:80')

    name = re.sub('[^A-Za-z0-9\-]', '-', app.name)

    app_image = LatestAppImage(app).get()

    print '-----> Connecting to ELB'
    elb_conn = boto.connect_elb()

    log('info', 'Load balancer', show_header=True)
    load_balancer_name = name
    try:
        elb_result = elb_conn.get_all_load_balancers(load_balancer_names=[load_balancer_name])
        lb = elb_result[0]
        log('info', 'Found {}'.format(load_balancer_name))
    except boto.exception.BotoServerError:
        log('info', 'Not found, creating load balancer')
        listeners = [(80, 80, 'HTTP', 'HTTP')]
        lb = elb_conn.create_load_balancer(name=load_balancer_name,
                                           zones=None,
                                           complex_listeners=listeners,
                                           security_groups=lb_group_ids,
                                           subnets=[aws.subnet_id])
    hc = HealthCheck(target=health_check_target)
    lb.configure_health_check(hc)
    cda = ConnectionDrainingAttribute()
    cda.enabled = True
    cda.timeout = 300
    elb_conn.modify_lb_attribute(load_balancer_name=load_balancer_name,
                                  attribute='connectionDraining',
                                  value=cda)

    print '-----> Connecting to AutoScale'
    as_conn = boto.connect_autoscale()

    log('info', 'Launch configuration', show_header=True)
    launch_config_name = "{}-{}".format(name, app_image.tags['deploy-id'])
    lc_result = as_conn.get_all_launch_configurations(names=[launch_config_name])
    if len(lc_result) == 0:
        log('info', 'Not found, creating LaunchConfiguration')
        lc = LaunchConfiguration(name=launch_config_name,
                                 image_id=app_image.id,
                                 key_name=aws.key_pair_name,
                                 security_groups=inst_group_ids,
                                 instance_type=aws.instance_type)
        as_conn.create_launch_configuration(lc)
    else:
        log('info', 'Found {}'.format(launch_config_name))
        lc = lc_result[0]

    existing_group = None
    deploy_id = int(app_image.tags['deploy-id'] or 0)
    log('info', 'Getting previous auto-scaling group', show_header=True)
    for did in xrange(deploy_id-1, 0, -1):
        existing_group_name = "{}-{}".format(name, did)
        log('info', '{} ?'.format(existing_group_name))
        ag_result = as_conn.get_all_groups(names=[existing_group_name])
        if len(ag_result) > 0:
            existing_group = ag_result[0]
            log('info', 'Found {}'.format(existing_group.name))
            break
        else:
            log('info', 'No')

    if existing_group is not None:
        existing_healthy_instances = [inst for inst in existing_group.instances if inst.lifecycle_state == 'InService' and inst.health_status == 'Healthy']
        existing_healthy_instance_count = len(existing_healthy_instances)
        desired_capacity = existing_group.desired_capacity
        min_size = existing_group.min_size
        max_size = existing_group.max_size
        if existing_healthy_instance_count == 0 and desired_capacity == 0:
            print '-----> WARNING: existing auto-scaling group {} has no healthy instances and a desired capacity of 0. New auto-scaling group will launch 1 instance.'.format(existing_group)
            desired_capacity = 1
            min_size = 1
            max_size = max_size if max_size > 0 else 1
    else:
        existing_healthy_instance_count = 0
        desired_capacity = 1
        min_size = 1
        max_size = 1

    log('info', '{} existing instance(s) found'.format(existing_healthy_instance_count), show_header=True)

    log('info', 'Existing auto-scale properties: desired_capacity={}, min_size={}, max_size={}'.format(desired_capacity, min_size, max_size))

    log('info', 'Auto-scaling group', show_header=True)
    group_name = "{}-{}".format(name, app_image.tags['deploy-id'])
    ag_result = as_conn.get_all_groups(names=[group_name])
    if len(ag_result) == 0:
        log('info', 'Not found, creating autoscale group')
        ag = AutoScalingGroup(name=group_name,
                              load_balancers=[load_balancer_name], launch_config=lc,
                              desired_capacity=desired_capacity, min_size=min_size, max_size=max_size,
                              health_check_type='ELB', health_check_period='300',
                              vpc_zone_identifier=aws.subnet_id)
        as_conn.create_auto_scaling_group(ag)
    else:
        log('info', 'Found {}'.format(group_name))
        ag = ag_result[0]
        ag.desired_capacity = desired_capacity
        ag.max_size = max_size
        ag.min_size = min_size
        ag.launch_config_name = launch_config_name
        ag.update()

    log('info', 'Waiting for new instances to become healthy', show_header=True)
    all_healthy = False
    for i in xrange(60):
        if i > 0:
            print '       ---'
            time.sleep(10)
        elb_result = elb_conn.get_all_load_balancers(load_balancer_names=[load_balancer_name])
        lb = elb_result[0]
        lb_insts = lb.get_instance_health()
        print '       Load-balancer instances: {}'.format(lb_insts)
        # NOTE: re-get auto-scaling group to get updated instance info.
        ag = as_conn.get_all_groups(names=[group_name])[0]
        ag_insts = [inst for inst in ag.instances]
        log('info', 'Auto-scaling group Instances: {}'.format(ag_insts))
        if len(ag_insts) < desired_capacity:
            not_yet_launched_count = desired_capacity - len(ag_insts)
            log('info', '{} new instance(s) not yet launched'.format(not_yet_launched_count))
            continue
        ag_inst_ids = set(inst.instance_id for inst in ag_insts)
        lb_inst_ids = set(inst.instance_id for inst in lb_insts)
        asg_insts_not_in_lb = ag_inst_ids.difference(lb_inst_ids)
        if len(asg_insts_not_in_lb) > 0:
            log('info', '{} new instance(s) not yet in load balancer'.format(len(asg_insts_not_in_lb)))
            continue
        new_lb_insts = [inst for inst in lb_insts if inst.instance_id in ag_inst_ids]
        healthy_new_lb_insts = [inst for inst in new_lb_insts if inst.state == 'InService']
        all_healthy = len(healthy_new_lb_insts) == len(ag_insts)
        log('info', '{} new instance(s) are healthy'.format(len(healthy_new_lb_insts)))
        diff = existing_healthy_instance_count - len(healthy_new_lb_insts)
        if existing_group is not None and diff >= 0:
            change = False
            if existing_group.desired_capacity != diff:
                existing_group.desired_capacity = diff
                change = True
            if existing_group.max_size != diff:
                existing_group.max_size = diff
                change = True
            if diff < existing_group.min_size:
                existing_group.min_size = diff
                change = True
            if change:
                existing_group.update()
                log('info', 'Change previous auto-scale group {} properties: desired_capacity={}, min_size={}, max_size={}'.format(existing_group, existing_group.desired_capacity, existing_group.min_size, existing_group.max_size))
        if all_healthy:
            log('info', 'All new instances healthy!', show_header=True)
            healthy_lb_inst_ids = [inst.instance_id for inst in lb_insts if inst.state == 'InService']
            previous_healthy_inst_ids = [inst.instance_id for inst in existing_healthy_instances] if existing_group else []
            not_yet_out_of_service = set(previous_healthy_inst_ids).intersection(healthy_lb_inst_ids)
            if len(not_yet_out_of_service) > 0:
                log('info', 'Waiting to remove previous instances ({}) from load balancer'.format(not_yet_out_of_service))
            else:
                log('info', 'All previous instances ({}) have been removed from load balancer'.format(previous_healthy_inst_ids), show_header=True)
        if all_healthy and len(not_yet_out_of_service) == 0:
            break
    else:
        raise Exception("Timeout")

    elb_result = elb_conn.get_all_load_balancers(load_balancer_names=[load_balancer_name])
    lb = elb_result[0]
    lb_insts = [inst for inst in lb.get_instance_health() if inst.state == 'InService']
    print '-----> Deployed {} instance(s) of {} to {}'.format(lb_insts, app.name, lb.dns_name)

    print '-----> DONE!'

def deploy_static(app_name, env_name, domain, force):
    app = App(env_name, app_name)
    bucket_name = domain or '{}-{}'.format(config.get('system_name', uuid.uuid1().hex), app.repo.name)

    app.repo.fetch()

    version = app.repo.head_commit_id()

    s3 = boto.connect_s3()
    b = s3.lookup(bucket_name)

    if b is not None:
        version_key = b.get_key('__VERSION__')
        if version_key is not None:
            current_version = version_key.get_metadata('git-version')
            if version == current_version:
                if force:
                    print '-----> Version {} already deployed, but re-deploying anyway'.format(version)
                else:
                    print '-----> Version {} already deployed!'.format(version)
                    return

    with lcd(app.repo.path):
        build_cmd = app.config.get('build_script')
        if build_cmd:
            print '-----> Building'
            local(build_cmd)

    if b is None:
        print '-----> Creating bucket {}'.format(bucket_name)
        b = s3.create_bucket(bucket_name)

    # TODO: this policy allows all users read access to all objects.
    # Need to find a way to limit access to __VERSION__ to only authenticated
    # users.
    public_access_policy = json.dumps({"Version":"2012-10-17",
                                       "Statement":[{"Sid":"PublicReadForGetBucketObjects",
                                                     "Effect":"Allow",
                                                     "Principal": "*",
                                                     "Action":["s3:GetObject"],
                                                     "Resource":["arn:aws:s3:::{}/*".format(bucket_name)]}]})
    b.set_policy(public_access_policy)
    #b.configure_versioning(versioning=False)
    b.configure_website(suffix="index.html", error_key="error.html")

    def map_key_to_obj(m, obj):
        if obj.key != '__VERSION__':
            m[obj.key] = obj
        return m
    existing_keys = reduce(map_key_to_obj, b.get_all_keys(), {})

    root = normpath(join(app.repo.path, app.config.get('root_dir', '')))

    app_redirects = app.config.get('redirects', {})
    for key_name in app_redirects.keys():
        existing_keys.pop(key_name, None)

    print '-----> Uploading {} to {} bucket'.format(root, bucket_name)
    new_keys = []
    updated_keys = []
    for dirname, dirnames, filenames in walk(root):
        reldirname = relpath(dirname, root)
        reldirname = '' if reldirname == '.' else reldirname
        if os.path.commonprefix(['.git', reldirname]) == '.git':
            continue
        for filename in filenames:
            full_filename = join(reldirname, filename)
            if full_filename == '.s3':
                continue
            new_or_update = '        '
            if existing_keys.has_key(full_filename):
                new_or_update = '[UPDATE]'
                updated_keys.append(full_filename)
                key = existing_keys.pop(full_filename)
            else:
                new_or_update = '[NEW]   '
                new_keys.append(full_filename)
                key = b.new_key(full_filename)
            print '       {} Uploading {}'.format(new_or_update, full_filename)
            key.set_contents_from_filename(join(dirname, filename))
    if len(existing_keys) > 0:
        print '-----> WARNING: the following files are still present but no'
        print '       longer part of the website:'
        for k,v in existing_keys.iteritems():
            print '       {}'.format(k)

    print '-----> Tagging bucket with git version {}'.format(version)
    version_key = b.get_key('__VERSION__')
    if version_key:
        version_key.delete()
    version_key = b.new_key('__VERSION__')
    version_key.set_metadata('git-version', version)
    version_key.set_contents_from_string('')

    print '-----> Setting up redirects'
    app_redirects = app.config.get('redirects', {})
    if len(app_redirects) == 0:
        print '       No redirects.'
    else:
        def get_or_new_key(bucket, name):
            key = bucket.get_key(name)
            if key is not None:
                key.delete()
            return bucket.new_key(name)
        elb = boto.connect_elb()
        pybars_compiler = pybars.Compiler()
        for key_name, redirect_source in app_redirects.iteritems():
            redirect_template = pybars_compiler.compile(redirect_source)
            app_redirects[key_name] = redirect_template
        data = {
            'webui_dns': elb.get_all_load_balancers(load_balancer_names=['{}-web-ui'.format(env_name)])[0].dns_name
        }
        for key_name, redirect_template in app_redirects.iteritems():
            k = get_or_new_key(b, key_name)
            redirect = unicode(redirect_template(data))
            print '       Redirect {} to {}'.format(key_name, redirect)
            k.set_redirect(redirect)

    print '=====> Deployed to {}!'.format(b.get_website_endpoint())

    if domain is not None:

        # TODO: support redirection from www.<domain>
        # b_www = 'www.{}'.format(bucket_name)

        ec2 = boto.connect_ec2()
        region_name = first([z.region.name for z in ec2.get_all_zones() if z.name == config['availability_zone']])
        s3_website_region = s3_website_regions[region_name]

        route53 = boto.connect_route53()
        zone_name = "{}.".format(get_tld("http://{}".format(domain)))
        zone = route53.get_zone(zone_name)
        if zone is None:
            raise Exception("Cannot find zone {}".format(zone_name))
        full_domain = "{}.".format(domain)
        a_record = zone.get_a(full_domain)
        if not a_record:
            print '-----> Creating ALIAS for {} to S3'.format(full_domain)
            changes = ResourceRecordSets(route53, zone.id)
            change_a = changes.add_change('CREATE', full_domain, 'A')
            change_a.set_alias(alias_hosted_zone_id=s3_website_region[1], alias_dns_name=s3_website_region[0])
            #change_cname = records.add_change('CREATE', 'www.' + full_domain, 'CNAME')
            #change_cname.add_value(b_www.get_website_endpoint())
            changes.commit()
        else:
            print '-----> ALIAS for {} to S3 already exists'.format(full_domain)
            print '       {}'.format(a_record)
            if a_record.alias_dns_name != s3_website_region[0]:
                print '       WARNING: Alias DNS name is {}, but should be {}'.format(a_record.alias_dns_name, s3_website_region[0])
            if a_record.alias_hosted_zone_id != s3_website_region[1]:
                print '       WARNING: Alias hosted zone ID is {}, but should be {}'.format(a_record.alias_hosted_zone_id, s3_website_region[1])
            if a_record.name != full_domain:
                print '       WARNING: Domain is {}, but should be {}'.format(a_record.name, full_domain)
            if a_record.type != 'A':
                print '       WARNING: Record type is {}, but should be {}'.format(a_record.type, 'A')

    print '=====> DONE!'

def get_ssh_command(inst_id):
    ec2 = boto.connect_ec2()
    instance = ec2.get_only_instances(instance_ids=[inst_id])[0]
    pem_filename = get_pem_filename(config['instance_key_pair_name'])
    return 'ssh -i {} {}@{}'.format(pem_filename, config['instance_user'], instance.public_dns_name)

def get_dokku_command(inst_id, cmd):
    ec2 = boto.connect_ec2()
    instance = ec2.get_only_instances(instance_ids=[inst_id])[0]
    return 'ssh {}@{} {}'.format(config['deploy_user'], instance.public_dns_name, cmd)

def do_ssh(inst_id):
    if inst_id == None:
        inst_id = get_info(None, None)[0]['instance_id']
    local(get_ssh_command(inst_id))

def dokku(inst_id, cmd):
    local(get_dokku_command(inst_id, cmd))

def get_info(app_name, env_name):
    ec2 = boto.connect_ec2()
    elb = boto.connect_elb()
    lb = None
    app = App(env_name, app_name)
    try:
        lbresult = elb.get_all_load_balancers(load_balancer_names=['{}-{}'.format(env_name, app_name)])
        lb = lbresult[0] if len(lbresult) > 0 else None
    except boto.exception.BotoServerError:
        pass
    if lb is None:
        instances = ec2.get_only_instances(filters={'tag:app': '{}/{}'.format(app.env_name, app.repo.name),
                                                    'tag:deployed': 'true',
                                                    'instance-state-name': 'running'})
        datas = [{'instance_id': instance.id,
                 'public_dns_name': instance.public_dns_name,
                 'ssh_command': get_ssh_command(instance.id)} for instance in instances]
        for data in datas:
            print '-----> Instance {}'.format(data['instance_id'])
            print '       DNS:   {}'.format(data['public_dns_name'])
            print '       SSH:   {}'.format(data['ssh_command'])
        if len(datas) == 0:
            print 'No deployment found'
            sys.exit(1)
        else:
            return datas
    print '-----> Load Balancer'
    print '       Name: {}'.format(lb.name)
    print '       DNS:  {}'.format(lb.dns_name)
    i = 0
    for inst in lb.get_instance_health():
        i += 1
        print '-----> Instance #{}'.format(i)
        inst_id = inst.instance_id
        print '       ID:    {}'.format(inst_id)
        print '       State: {}'.format(inst.state)
        instance = ec2.get_only_instances(instance_ids=[inst_id])[0]
        print '       DNS:   {}'.format(instance.public_dns_name)
        print '       SSH:   {}'.format(get_ssh_command(inst_id))
    if i == 0:
        print '-----> Instances'
        print '       None'

def get_url(app_name, env_name):
    protocol = 'http://' # TODO detect if load balancer supports HTTPS
    app = App(env_name, app_name)
    bucket_name = '{}-{}'.format(config.get('system_name', uuid.uuid1().hex), app.repo.name)

    ec2 = boto.connect_ec2()
    elb = boto.connect_elb()
    s3 = boto.connect_s3()

    b = s3.lookup(bucket_name)
    if b is not None:
        return protocol + b.get_website_endpoint()

    lb = None
    try:
        lbresult = elb.get_all_load_balancers(load_balancer_names=['{}-{}'.format(app.env_name, app.repo.name)])
        lb = lbresult[0] if len(lbresult) > 0 else None
    except boto.exception.BotoServerError:
        pass
    if lb is None:
        instances = ec2.get_only_instances(filters={'tag:app': app.name,
                                                    'tag:deployed': 'true',
                                                    'instance-state-name': 'running'})
        if len(instances) != 1:
            return None
        else:
            return protocol + instances[0].public_dns_name
    return protocol + lb.dns_name

def is_static(arguments):
    return arguments['--static'] or os.path.exists(join(getcwd(), '.s3'))

def open_url(app_name, env_name):
    import webbrowser
    url = get_url(app_name, env_name)
    if not url:
        print "=====> Error: No running application found."
        return False
    print '-----> Opening {}'.format(url)
    webbrowser.open_new(url)

def initialize_configuration(show_output=False):
    global config
    global initialized
    if not initialized:
        config = riker_config.load_config(show_output)
        env.user = config['instance_user']
        env.use_ssh_config = True
        initialized = True
