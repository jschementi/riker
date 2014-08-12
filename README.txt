Create an AMI for an app:

    python infra/main.py create-new-ami --app myapp --env myenv

Deploy an app's latest AMI:

    python infra/main.py deploy-ami --app myapp --env myenv

Update config of a single instance:

    python -c "import infra.api; infra.api.env.key_filename = infra.api.get_pem_filename(infra.api.instance_key_pair_name); infra.api.execute(infra.api.update_config, 'myapp', 'myenv', hosts=['ec2-123-456-789-012.compute-1.amazonaws.com'])"
