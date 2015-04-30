from os.path import isdir, join

from fabric.api import local
from fabric.context_managers import settings

from retry import synchronize

def push_repo(remote_name='origin', branch_name=None, local_branch_name=None, auto_confirm=False, force=False):
    if branch_name is None:
        branch_name = 'master'
    with settings(warn_only=True):
        if local('git branch | grep {}'.format(local_branch_name if local_branch_name is not None else branch_name)).return_code != 0:
            local_branch_name = 'HEAD'
    full_branch_name = branch_name if local_branch_name is None else '%s:%s' % (local_branch_name, branch_name)
    options = ' '
    if force:
        options += '-f'
    local('git push%s %s %s' % (options, remote_name, full_branch_name))

def clone_repo(remote_url, repo_dir, local_branch=None):
    branch_arg = "-b {}".format(local_branch) if local_branch is not None else ''
    local('git clone %s %s %s' % (branch_arg, remote_url, repo_dir))

@synchronize('ensure_remote.lock')
def ensure_remote(remote_name, remote_url):
    remotes = [l.strip() for l in local('git remote', capture=True).split("\n")]
    if remote_name in remotes:
        local('git remote remove %s' % (remote_name,))
    local('git remote add %s %s' % (remote_name, remote_url))

def get_head_commit_sha1():
    return local('git rev-parse HEAD', capture=True).strip()

def is_repo(repo_path):
    return isdir(join(repo_path, '.git'))

class NotGitRepoError(Exception):
    pass

def ensure_is_repo(repo_path):
    if not is_repo(repo_path):
        raise NotGitRepoError()
