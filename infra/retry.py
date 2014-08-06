import time
from functools import wraps

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
