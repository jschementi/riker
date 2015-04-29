import time
from functools import wraps
from os.path import exists as local_exists, join

from fabric.api import run, local
from fabric.contrib.files import exists

import config

def retry(tries=10, wait=0.5, on_none=False, on_empty=False, retry_message="."):
    def deco_retry(f):
        @wraps(f)
        def f_retry(*args, **kwargs):
            i = 0
            while i < tries - 1:
                try:
                    result = f(*args, **kwargs)
                    if on_none and result is None:
                        raise Exception()
                    if on_empty and hasattr(result, '__len__') and len(result) == 0:
                        raise Exception()
                    return result
                except:
                    i += 1
                    print retry_message
                    time.sleep(wait)
            return f(*args, **kwargs)
        return f_retry
    return deco_retry

def synchronize(lock_file_path, is_remote=False):
    lock_file_path = join(config.directory, lock_file_path)
    run_fn = run if is_remote else local
    exists_fn = exists if is_remote else local_exists
    def deco_sync(f):
        @wraps(f)
        def f_sync(*args, **kwargs):
            while True:
                if not exists_fn(lock_file_path):
                    try:
                        run_fn('mkdir -p $(dirname {0}) && touch {0}'.format(lock_file_path))
                        return f(*args, **kwargs)
                    finally:
                        run_fn('rm -f {}'.format(lock_file_path))
                time.sleep(5)
        return f_sync
    return deco_sync

