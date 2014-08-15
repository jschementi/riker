"""Heroku-like deployments with AWS

Usage:
  infra deploy --app <app-name> --env <env-name> [--static --domain <domain-name>] [--force]
  infra create-new-ami --app <app-name> --env <env-name>
  infra deploy-ami --app <app-name> --env <env-name>
  infra update-config --app <app-name> --env <env-name>
  infra get-info --app <app-name> --env <env-name>
  infra (-h | --help)
  infra --version

Options:
  -a <app>, --app <app>           Name of app.
  -e <env>, --env <env>           Environment for app.
  -s, --static                    App is static.
  -d <domain>, --domain <domain>  Domain for app.
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
            else:
                deploy(arguments)
        if arguments.get('update-config') == True:
            update_config(arguments)
        if arguments.get('get-info') == True:
            get_info(arguments)
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

def get_info(arguments):
    api.get_info(arguments['--app'], arguments['--env'])

if __name__ == '__main__':
    arguments = docopt(__doc__, version='Infra 1.0')
    main(arguments)
