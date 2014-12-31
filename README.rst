=====
Riker
=====

*You're the captain, and Riker is your "Number One"*


Heroku-like application deployments to Amazon Web Services.


Install
-------

::

  pip install riker


Configure
---------

::

  riker config


Usage
-----

Deploy a sample app to AWS with a single command:

::

  # Get Python sample app
  git clone git@github.com:heroku/python-sample.git
  cd python-sample

  riker deploy
  riker open

This will launch an EC2 instance running the python-sample app, and open it in
your default web browser.

The first time this is run in your AWS account, it will take some time, as it
needs to provision a base AMI which all EC2 instances will be launched from.
Subsequent deploys to the same app will be very quick, and new application
deployments will only need to wait for a new EC2 instance to boot.

Since Riker uses Heroku Buildpacks, the app can be written in any language.


You can also deploy a static website to S3 with the same command:

::

  # Generate simple website
  mkdir static-website && cd static-website
  echo "Hello, World" > index.html
  touch .s3 # indicates deployment to Amazon S3
  git init && git add -A && git commit -m "Initial commit"

  riker deploy
  riker open


The ``.s3`` file indicates that this app should be deployed to S3.

Riker also supports a production deploy mode, which ensures zero-downtime for
the application being deployed, and a configuration which supports auto-scaling.
Usually, Riker will deploy changes directly to existing instances. However, for
a production deployment, Riker will deploy changes to new instances, and only
swap old instances out for new instances when the new instances become healthy,
and the old instances no longer have active connections.

::

  riker deploy --scale


This will deploy the app behind a load-balancer and auto-scaling group.


Contributing
------------

Please report bugs, suggest features, and ask questions on GitHub:
https://github.com/jschementi/riker/issues

Pull requests welcome!
https://github.com/jschementi/riker/pulls


Additional Resources
--------------------

- `Riker - Heroku-like app deployments for AWS <http://jimmy.schementi.com/riker-heroku-like-app-deploy-for-aws/>`_
- `BrooklynJS talk: Get Your Infrastructure Right <http://jimmy.schementi.com/get-infrastructure-right/>`_
