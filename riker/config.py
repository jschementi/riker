import json
from os.path import expanduser, realpath, dirname, join
from contextlib import contextmanager

__dirname__ = dirname(realpath(__file__))

config_dir = '~/.riker'

@contextmanager
def suppress(exception_type):
    try:
        yield
    except exception_type:
        pass

def load_config():
    try:
        with open(join(expanduser(config_dir), 'config'), 'r') as config_file:
            return json.loads(config_file.read())
    except IOError:
        return prompt_for_config()

def prompt_for_config():
    print "Please copy config.example to {}/config and update it for your deployment.".format(config_dir)

