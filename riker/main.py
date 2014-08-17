"""Heroku-like deployments with AWS

Usage:
  riker deploy --app <app-name> --env <env-name> [--single] [--static --domain <domain-name>] [--force]
  riker create-new-ami --app <app-name> --env <env-name>
  riker deploy-ami --app <app-name> --env <env-name>
  riker update-config --app <app-name> --env <env-name>
  riker get-info --app <app-name> --env <env-name>
  riker ssh --instance-id <instance-id>
  riker dokku --instance-id <instance-id> <cmd>...
  riker (-h | --help)
  riker --version

Options:
  -a <app>, --app <app>           Name of app.
  -e <env>, --env <env>           Environment for app.
  -s, --static                    App is static.
  -d <domain>, --domain <domain>  Domain for app.
  --instance-id <instance-id>     EC2 Instance ID.
  --single                        Deploy to a single instance.
  -f, --force                     Force deployment.
  -h --help                       Show this screen.
  --version                       Show version.

"""

from fabric.network import disconnect_all

from docopt import docopt

import api

def main(arguments):
    try:
        if arguments.get('create-new-ami') == True:
            create_new_ami(arguments)
        if arguments.get('deploy-ami') == True:
            deploy_ami(arguments)
        if arguments.get('deploy') == True:
            if arguments.get('--static') == True:
                deploy_static(arguments)
            elif arguments.get('--single') == True:
                deploy_to_single_instance(arguments)
            else:
                deploy(arguments)
        if arguments.get('update-config') == True:
            update_config(arguments)
        if arguments.get('get-info') == True:
            get_info(arguments)
        if arguments.get('ssh') == True:
            ssh(arguments)
        if arguments.get('dokku') == True:
            dokku(arguments)
    finally:
        disconnect_all()

def deploy(arguments):
    create_new_ami(arguments)
    deploy_ami(arguments)

def create_new_ami(arguments):
    api.create_app_ami(arguments['--app'], arguments['--env'])

def deploy_ami(arguments):
    api.deploy_latest_app_ami(arguments['--app'], arguments['--env'])

def update_config(arguments):
    api.deploy_config_update(arguments['--app'], arguments['--env'])
    deploy_ami(arguments)

def deploy_static(arguments):
    domain = arguments.get('--domain')
    if not domain:
        raise Exception("Must provide --domain <domain-name>")
    force = arguments.get('--force')
    api.deploy_static(arguments['--app'], arguments['--env'], domain, force)

def deploy_to_single_instance(arguments):
    api.deploy_to_single_instance(arguments['--app'], arguments['--env'])

def get_info(arguments):
    api.get_info(arguments['--app'], arguments['--env'])

def ssh(arguments):
    api.do_ssh(arguments['--instance-id'])

def dokku(arguments):
    cmd = ' '.join(arguments.get('<cmd>', ''))
    api.dokku(arguments['--instance-id'], cmd)

if __name__ == '__main__':
    arguments = docopt(__doc__, version='riker 1.0')
    main(arguments)
