from time import sleep

class TimeoutError(Exception):
    def __init__(self, x):
        super(TimeoutError, self).__init__("Operation took longer than %s minutes" % x)

def poll_for_condition(fetch_callable, condition_callable, timeout=600, poll_delay=10):
    done = False
    max_iters = int(timeout / float(poll_delay))
    for i in xrange(max_iters):
        fetched = fetch_callable()
        done = condition_callable(fetched)
        if done:
            break
        sleep(poll_delay)
    if not done:
        raise TimeoutError(timeout / 60.0)

header = '-----> '
normal = '       '

def log(level, message, show_header=False):
    print((header if show_header else normal) +  message)

def first(iterable):
    for x in iterable:
        return x
    return None
