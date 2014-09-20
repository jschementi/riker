=====
Riker
=====

::

  Heroku-like deployments with AWS

  Usage:
    riker deploy [--app <app-name>] [--env <env-name>] [--scale] [--static --domain <domain-name>] [--force]
    riker create-new-ami [--app <app-name>] [--env <env-name>]
    riker deploy-ami [--app <app-name>] [--env <env-name>]
    riker update-config [--app <app-name>] [--env <env-name>]
    riker info [--app <app-name>] [--env <env-name>]
    riker ssh --instance-id <instance-id>
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


Advanced
--------

Update config of a single instance:

::

  python -c "from riker import api; api.env.key_filename = api.get_pem_filename(api.instance_key_pair_name); api.execute(api.update_config, 'myapp', 'myenv', hosts=['ec2-123-456-789-012.compute-1.amazonaws.com'])"
