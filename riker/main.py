"""Heroku-like deployments with AWS

Usage:
  riker deploy [--app <app-name>] [--env <env-name>] [--scale] [--static --domain <domain-name>] [--force]
  riker create-new-ami [--app <app-name>] [--env <env-name>]
  riker deploy-ami [--app <app-name>] [--env <env-name>]
  riker update-config [--app <app-name>] [--env <env-name>]
  riker info [--app <app-name>] [--env <env-name>]
  riker ssh [--instance-id <instance-id>]
  riker dokku --instance-id <instance-id> <cmd>...
  riker open [--app <app-name>] [--env <env-name>]
  riker url [--app <app-name>] [--env <env-name>]
  riker config
  riker (-h | --help)
  riker --version

Options:
  -a <app>, --app <app>           Name of app.
  -e <env>, --env <env>           Environment for app.
  -s, --static                    Deploy to S3.
  -d <domain>, --domain <domain>  Domain for app.
  --instance-id <instance-id>     EC2 Instance ID.
  --scale                         Enable scalable deployments.
  -f, --force                     Force deployment.
  -h --help                       Show this screen.
  --version                       Show version.
"""

import os

from fabric.network import disconnect_all

from docopt import docopt

import api

from version import VERSION

def main():
    arguments = docopt(__doc__, version='riker {}'.format(VERSION))
    try:
        if arguments.get('create-new-ami') == True:
            create_new_ami(arguments)
        elif arguments.get('deploy-ami') == True:
            deploy_ami(arguments)
        elif arguments.get('deploy') == True:
            deploy(arguments)
        elif arguments.get('update-config') == True:
            update_config(arguments)
        elif arguments.get('info') == True:
            get_info(arguments)
        elif arguments.get('ssh') == True:
            ssh(arguments)
        elif arguments.get('dokku') == True:
            dokku(arguments)
        elif arguments.get('open') == True:
            open_url(arguments)
        elif arguments.get('url') == True:
            get_url(arguments)
        elif arguments.get('config') == True:
            config(arguments)
    finally:
        disconnect_all()

def deploy(arguments):
    if arguments.get('--scale') == True:
        create_new_ami(arguments)
        deploy_ami(arguments)
    elif api.is_static(arguments):
        deploy_static(arguments)
    else:
        deploy_to_single_instance(arguments)

def create_new_ami(arguments):
    api.initialize_configuration()
    api.create_app_ami(arguments['--app'], arguments['--env'])

def deploy_ami(arguments):
    api.initialize_configuration()
    api.deploy_latest_app_ami(arguments['--app'], arguments['--env'])

def update_config(arguments):
    api.initialize_configuration()
    api.deploy_config_update(arguments['--app'], arguments['--env'])
    deploy_ami(arguments)

def deploy_static(arguments):
    api.initialize_configuration()
    domain = arguments.get('--domain')
    force = arguments.get('--force')
    api.deploy_static(arguments['--app'], arguments['--env'], domain, force)

def deploy_to_single_instance(arguments):
    api.initialize_configuration()
    api.deploy_to_single_instance(arguments['--app'], arguments['--env'])

def get_info(arguments):
    api.initialize_configuration()
    api.get_info(arguments['--app'], arguments['--env'])

def ssh(arguments):
    api.initialize_configuration()
    api.do_ssh(arguments['--instance-id'])

def dokku(arguments):
    api.initialize_configuration()
    cmd = ' '.join(arguments.get('<cmd>', ''))
    api.dokku(arguments['--instance-id'], cmd)

def open_url(arguments):
    api.initialize_configuration()
    api.open_url(arguments['--app'], arguments['--env'])

def get_url(arguments):
    api.initialize_configuration()
    url = api.get_url(arguments['--app'], arguments['--env'])
    if url: print url

def config(arguments):
    api.initialize_configuration(show_output=True)

if __name__ == '__main__':
    main()
