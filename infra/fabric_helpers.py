import subprocess
import socket
from fabric.state import default_channel

def remote_pipe(local_command, remote_command, buf_size=1024*1024):
    '''executes a local command and a remove command (with fabric), and
    sends the local's stdout to the remote's stdin'''
    local_p= subprocess.Popen(local_command, shell=True, stdout=subprocess.PIPE)
    channel= default_channel() #fabric function
    channel.set_combine_stderr(True)
    channel.settimeout(2)
    channel.exec_command( remote_command )
    try:
        read_bytes= local_p.stdout.read(buf_size)
        while read_bytes:
            channel.sendall(read_bytes)
            read_bytes= local_p.stdout.read(buf_size)
    except socket.error:
        local_p.kill()
        #fail to send data, let's see the return codes and received data...
    local_ret= local_p.wait()
    received= channel.recv(buf_size)
    channel.shutdown_write()
    channel.shutdown_read()
    remote_ret= channel.recv_exit_status()
    if local_ret!=0 or remote_ret!=0:
        raise Exception("remote_pipe failed. Local retcode: {0} Remote retcode: {1}  output: {2}".format(local_ret, remote_ret, received))

