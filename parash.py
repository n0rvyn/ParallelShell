#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2020-2022 by ZHANG ZHIJIE.
# All rights reserved.

# Created Time: 7/13/22 10:21
# Author: ZHANG ZHIJIE
# Email: norvyn@norvyn.com
# Git: @n0rvyn
# File Name: mm_init.py
# Tools: PyCharm

"""
---Initiate environment for GPFS installation---
---And setup GPFS cluster & filesystem---
"""

# todo add CTRL-C signal to method getoutput()

import logging
import os
import sys
import subprocess
import threading
import time
from getpass import getpass
import getopt
import socket
from yaml import safe_load
from yaml import dump

# define a parameter to decide weather initialize remote terminal with OpenSSH or paramiko
OPENSSH = True
try:
    import paramiko

    OPENSSH = False
except ModuleNotFoundError:
    print('Initialize remote terminal with OpenSSH instead of python module paramiko.')

_HOME_ = os.path.abspath(os.path.dirname(__file__))
_LOG_PATH_ = os.path.join(_HOME_, '.')
_LOG_FILE_ = os.path.join(_LOG_PATH_, '_parallel_shell.log')

PREVIEW = False
# define parameters for GPFS cluster creation
DEF_NODE_PREFIX = 'gpfs-'
DEF_MOUNT_POINT = '/home/app/data'
DEF_FS_NAME = 'gpfs_data'


class ColorLogFormatter(logging.Formatter):
    def __init__(self, level):
        color = {'debug': '\033[0;32m', 'info': '\033[0;37m',
                 'warn': '\033[0;33m', 'error': '\033[0;31m', 'critical': '\033[1;31m'}
        COLOR_EOL = '\033[0m'

        try:
            fmt = f'%(asctime)s: [%(name)s]: {color[level]}%(levelname)8s{COLOR_EOL}: %(message)s'
        except KeyError:
            raise TypeError('Wrong log level, must be one of debug, info, warn, error or critical.')

        logging.Formatter.__init__(self, fmt=fmt, datefmt='%Y-%m-%d %H:%M')

    def colorFormat(self, name, msg, level):
        record = logging.LogRecord(name=name, level=level, pathname='.', lineno=1, msg=msg, args=(), exc_info=None)
        return self.format(record)


class ColorLogger(logging.Logger):
    def __init__(self, name, filename, display=True):
        logging.Logger.__init__(self, name=name, level=logging.DEBUG)
        self.name = name
        self.display = display

        if self.display:
            screen = logging.StreamHandler(sys.stdout)
            self.addHandler(screen)

        logFile = logging.FileHandler(filename)
        self.addHandler(logFile)

    def colorlog(self, msg, level=None):
        level = level if level is not None else 'info'
        formatter = ColorLogFormatter(level)

        loglevel = {'debug': logging.DEBUG, 'info': logging.INFO, 'warn': logging.WARN,
                    'error': logging.ERROR, 'critical': logging.CRITICAL}

        try:
            self.info(formatter.colorFormat(self.name, msg, loglevel[level]))
        except KeyError:
            raise TypeError('Wrong log level!')


class PyTermOpenSSH(object):
    def __init__(self, host=None, user=None, port=22, debug=False):
        self.host = host if host is not None else 'localhost'
        self.user = user if user is not None else 'root'
        self.port = port

        self.local = True if self.host == 'localhost' else False

        self.term = None
        self.end_of_term = ('EOT', 'Password:',
                            'Connection refused',
                            """Permission denied (publickey,keyboard-interactive).""",
                            '#')
        # 'EOT' for ending manually
        # other two for ending terminal when login failed because of wrong password or sth else
        self.hostname = None

        logger_name = f'{__class__.__name__} {self.host:>16s}'
        self.logger = ColorLogger(name=logger_name, filename=_LOG_FILE_, display=debug)

        self.last_output = ''
        # change type from list to string for printing easily
        # self.last_output = []
        self.last_return_code = 0

    def init_term(self):
        if self.local:
            self.logger.colorlog('Local host detected, init /bin/bash for executing command')
            _args = '/bin/bash'
        else:
            self.logger.colorlog('Remote host detected, init OpenSSH client for further use')
            _args = f'/bin/ssh -p {self.port} -l {self.user} {self.host}'
            print(f'\nManually type password for host [{self.host}] user [{self.user}] after prompt.\n')

        try:
            self.term = subprocess.Popen(_args,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT,
                                         shell=True)

            self.term.stdin.write(b'export TMOUT=0\n')
            self.term.stdin.write(b'LANG=C\n')
            self.term.stdin.write(b'echo "EOT"\n')  # for subprocess catch the end of terminal
            self.term.stdin.flush()

            while True:
                _line = self.term.stdout.readline().decode().strip('\n')
                # if _line.strip() == 'EOT':
                # add endswith 'Password:' in case of hanging when wrong password input while init ssh to remote host
                if _line.strip().endswith(self.end_of_term):
                    self.logger.colorlog('met end of terminal mark, break loop', 'info')
                    break
        except BrokenPipeError as _e:
            self.logger.colorlog(_e, 'critical')
            # raise _e

        return self.term

    def exec_command(self, command: str):
        # command = f'{command}; echo $? EOT\n'.encode()
        command = f'{command}; echo " $? EOT"\n'.encode()  # output of command does end with New Line
        # EOT\n is for subprocess.Popen stdin flush ENTER, not part of echo arguments
        self.logger.colorlog(f'send command [{command}] to terminal', 'info')
        """
        # cat /proc/net/dev | grep -E ".*[0-9][0-9]*" | awk '{printf $1}'; echo $? EOT
        ens35:ens32:ens34:lo:virbr0-nic:virbr0:0 EOT
        """
        # reset parameter of last output
        self.last_output = ''

        try:
            self.term.stdin.write(command)
            self.term.stdin.flush()

            while True:
                line = self.term.stdout.readline().decode().strip('\n')

                # if line.strip().endswith(self.end_of_term):
                if line.strip().endswith('EOT'):
                    self.logger.colorlog(f'last line of output detected [{line}]', 'info')
                    try:
                        # self.last_return_code = int(line.strip().split()[0])

                        # add for new EOT --> echo " $? EOT"
                        __list = line.split()
                        self.last_return_code = int(__list[-2])

                        if len(__list) > 2:
                            self.logger.colorlog(f'last line of output [{line}] not ends with "\n"', 'warn')
                            self.last_output += line.rstrip(f'{__list[-2]} {__list[-1]}')
                        # end of adding

                        self.logger.colorlog(f'read last command return code [{self.last_return_code}]', 'info')
                    except ValueError:
                        self.logger.colorlog(f'read last command return code failed from line [{line}]', 'warn')
                        self.last_return_code = 99
                    finally:
                        break

                # self.last_output.append(line)
                self.last_output += line + '\n'

        except BrokenPipeError as _e:
            self.logger.colorlog(_e, 'critical')
            self.logger.colorlog(f'Error: socket pipe broken!', 'critical')
            # raise _e
            self.last_return_code = 11

        except AttributeError as _e:
            self.logger.colorlog(_e, 'critical')
            self.logger.colorlog(f'Connection not initialized!', 'critical')
            # raise _e
            self.last_return_code = 12

        return self.last_output.rstrip('\n')  # delete blank line after output

    def getoutput(self, command: str, timeout=5) -> str:  # timeout --> for compatible with PyTermParamiko.getoutput
        return self.exec_command(command)

    def getstatusoutput(self, command) -> tuple:
        self.exec_command(command)
        return self.last_return_code, self.last_output


class PyTermParamiko(object):
    def __init__(self, host, user=None, password=None, port=22, debug=False, timeout=5, retry=3):
        self.host = host
        self.user = user if user is not None else 'root'
        self.port = port
        self.password = password
        self.timeout = timeout

        self.term = None
        self.connected = False
        self.retry = retry
        self.pass_failed = False

        self.last_return_code = 0

        logger_name = f'{__class__.__name__} {self.host:>15s}'
        self.logger = ColorLogger(name=logger_name, filename=_LOG_FILE_, display=debug)

    def connect_ssh(self):
        try:
            self.term.connect(hostname=self.host,
                              username=self.user,
                              password=self.password,
                              timeout=self.timeout,
                              port=self.port)
            self.connected = True
            self.logger.colorlog(f'connection to host [{self.host}] established', 'info')
            return True

        except paramiko.ssh_exception.AuthenticationException as _e:
            self.logger.colorlog(_e, 'critical')
            self.pass_failed = True
        except paramiko.ssh_exception.BadHostKeyException as _e:
            self.logger.colorlog(_e, 'critical')
            self.logger.colorlog('remove all keys belonging to host from known_hosts file', 'warn')
            os.system(f'ssh-keygen -R {self.host}')
        except paramiko.ssh_exception.NoValidConnectionsError as _e:
            self.logger.colorlog(_e, 'critical')
            print(f'[{self.host}] not reachable.')
            self.retry = 0
        except socket.timeout as _e:
            self.logger.colorlog(_e, 'critical')
            print(f'[{self.host}] SSH connection timeout.')
        except OSError as _e:
            self.logger.colorlog(_e, 'critical')
            print(f'[{self.host}] host is down.')

        return False

    def init_term(self):
        self.term = paramiko.SSHClient()
        self.logger.colorlog('load system host keys', 'info')
        self.term.load_system_host_keys()
        self.logger.colorlog('set missing host key policy [AutoAddPolicy]', 'info')
        self.term.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.connect_ssh()

        if not self.connected:
            for i in range(0, self.retry):
                if self.pass_failed:  # only if got wrong password then try to read a new one
                    self.password = getpass(
                        f'Authorise failed, input password for host [{self.host}] usr [{self.user}]: ')
                if self.connect_ssh():
                    break

        return self.term

    def getoutput(self, command: str, timeout=5) -> str:
        if '&' in command:  # '&' is not support with method paramiko.exec_command()
            self.logger.colorlog(f'met & in command [{command}], which will case the wrong return state.', 'warn')

        if not self.connected:
            self.last_return_code = 127
            self.logger.colorlog('retry 3 times, host cannot be connected, run command failed', 'critical')
            return ''

        try:
            _stdin, _stdout, _stderr = self.term.exec_command(command, timeout=timeout)
        except paramiko.ssh_exception.SSHException as _e:
            self.logger.colorlog(_e, 'warn')
            self.logger.colorlog(f'waiting too much time for command [{command}] to return status', 'info')
            self.last_return_code = 1
            return ''

        self.last_return_code = _stdout.channel.recv_exit_status()  # fetch the return code
        self.logger.colorlog(f'receive return code [{self.last_return_code}] of last command [{command}]', 'info')

        _output = ''.join(_stdout.readlines()).rstrip('\n')
        _error = ''.join(_stderr.readlines()).rstrip('\n')

        # '' if _error is '' else self.logger.colorlog(_error, 'error')
        _ = [self.logger.colorlog(_err, 'warn') for _err in _error.split('\n')] if _error != '' else None
        return _output if _error == '' else _error

    def getstatusoutput(self, command: str, timeout=5) -> tuple:
        _output = self.getoutput(command, timeout)
        # return self.last_return_code, self.getoutput(command, timeout)
        # this return code is really the last one, not the current command returns;
        # because fetching return code earlier than exec the current command.
        return self.last_return_code, _output


class PyTermAutoSelect(object):
    def __init__(self, host=None, user=None, password=None, port=22, debug=False, openssh=False):
        self.host = host if host is not None else 'localhost'
        self.user = user if user is not None else 'root'
        self.port = port
        self.password = password
        self.debug = debug

        self.term = None
        self.local = True if self.host == 'localhost' else False
        self.openssh = openssh if OPENSSH is not True else OPENSSH

        logger_name = f'{__class__.__name__} {self.host:>13s}'
        self.logger = ColorLogger(name=logger_name, filename=_LOG_FILE_, display=debug)

    def init_term(self):
        if not self.local and not self.openssh:
            self.logger.colorlog('init terminal with Python module paramiko', 'info')
            self.term = PyTermParamiko(host=self.host,
                                       user=self.user,
                                       password=self.password,
                                       port=self.port,
                                       timeout=5,
                                       debug=self.debug)

        else:
            self.logger.colorlog('init terminal with system level OpenSSH', 'info')
            self.term = PyTermOpenSSH(host=self.host, user=self.user, port=self.port, debug=self.debug)

        self.term.init_term()
        return self.term

    def getoutput(self, command: str, timeout=5):
        return self.term.getoutput(command, timeout)

    def getstatusoutput(self, command: str):
        return self.term.getstatusoutput(command)


class MultiTerm(object):
    def __init__(self, hosts: tuple, debug=False):
        """
        Args:
            hosts: tuple of hosts tuple
            (('192.168.1.1', 'root', 'password', 'port'), ('192.168.1.2', 'root', 'password'), (None, ), (''))
            None or '' for local host, otherwise at least 3 parameters MUST be specified: IP, USER, PASSWORD

            debug: set True to display log on monitor
        """
        self.terms = []

        for host in hosts:
            try:
                _host = host[0]
                _host = None if _host == '' else _host
            except IndexError:
                continue

            try:
                _user = host[1]
            except IndexError:
                _user = None
            try:
                _pass = host[2]
            except IndexError:
                _pass = None
            try:
                _port = host[3]
            except IndexError:
                _port = 22

            self.terms.append(PyTermAutoSelect(host=_host, user=_user, password=_pass, port=_port, debug=debug))

        [_term.init_term() for _term in self.terms]

        logger_name = f'{__class__.__name__}'
        self.logger = ColorLogger(name=logger_name, filename=_LOG_FILE_, display=debug)

    def getoutput(self, command: str):
        # get output of command for TERMs one by one following the origin order
        return [_term.getoutput(command) for _term in self.terms]

    def getstatusoutput(self, command: str):
        # get state & output of command for TERMs one by one following the origin order
        return [_term.getstatusoutput(command) for _term in self.terms]

    def getoutput_thread(self, command: str):
        _return = {}

        def _getoutput_target(_term: PyTermAutoSelect, _command: str):
            _return.update({_term.host: _term.getoutput(_command)})

        _thread = [threading.Thread(target=_getoutput_target, args=(_term, command)) for _term in self.terms]
        [_t.start() for _t in _thread]
        [_t.join() for _t in _thread]

        return _return

    def getstatusoutput_thread(self, command: str) -> dict:
        """
        Returns: {'192.168.1.1': (0, 'stdout_output1'), '192.168.1.2': (1, 'stderr_output2')}
        """
        _return = {}

        def _getstatusoutput_target(_term: PyTermAutoSelect, _command: str):
            _return.update({_term.host: _term.getstatusoutput(_command)})

        _thread = [threading.Thread(target=_getstatusoutput_target, args=(_term, command)) for _term in self.terms]
        [_t.start() for _t in _thread]
        [_t.join() for _t in _thread]

        return _return

    def getstatus_bool(self, command: str):
        return [(_host, True if _code_output[0] == 0 else False)
                for _host, _code_output in self.getstatusoutput_thread(command).items()]

    def getstatus_sum(self, command: str):
        return sum([_code_output[0] for _code_output in self.getstatusoutput_thread(command).values()])

    def add_hosts(self, ip: str, host_name: str) -> int:
        """
        append file '/etc/hosts'
        Returns:    sum of all return codes
        """
        _add_host = f"""if ! grep "{ip}.*{host_name}" /etc/hosts; then echo "{ip:<15s} {host_name}" >> /etc/hosts; fi"""
        # return self.getstatusoutput(_script)
        # return self.getstatusoutput_thread(_add_host) if ip != '' and host_name != '' else self.getstatusoutput_thread('false')
        # return self.getstatus_bool(_add_host) if ip != '' and host_name != '' else self.getstatusoutput_thread('false')
        return self.getstatus_sum(_add_host) if ip != '' and host_name != '' else 127

    def add_ssh_key(self, ssh_pub_key):
        """
        Append specified ssh public key to each host
        Args:
            ssh_pub_key: ssh public key string
        Returns: sum of return codes from all hosts
        """
        _ssh_auth_keys_file = '~/.ssh/authorized_keys'
        _script = f"""if ! grep "{ssh_pub_key}" {_ssh_auth_keys_file}; then echo "{ssh_pub_key}" >> {_ssh_auth_keys_file}; fi"""
        # return self.getstatusoutput(_script)
        # return self.getstatusoutput_thread(_script)
        return self.getstatus_sum(_script)

    def gen_ssh_key(self, ssh_key_file=None):
        """
        Checking ssh key file, if not exist, generate one.
        Returns: return code list.
        """
        _ssh_key_file = ssh_key_file if ssh_key_file is not None else '~/.ssh/id_rsa'
        _ssh_pub_key_file = f'{_ssh_key_file}.pub'
        _ssh_keygen_no_prompt = f"""ssh-keygen -q -t rsa -N '' -f {_ssh_key_file} <<< y"""

        # if ssh pub key not exist, generate with command 'ssh-keygen'
        _script = f"""if ! ls "{_ssh_pub_key_file}" >/dev/null 2>&1; then {_ssh_keygen_no_prompt}; fi"""

        # return self.getstatusoutput(_script)
        return self.getstatusoutput_thread(_script)

    def _gather_ip_host(self, ip_prefix, nodename_prefix=None):
        """
        For generating 'IP nodename' string list
        Args:
            ip_prefix: prefix of ip address
            nodename_prefix: prefix of node name adding to host name
                hostname: rhel01 --> nodename: PREFIX-hostname (nodename_prefix: PREFIX-)

        Returns: [('192.168.1.1', 'hostname1'), ('192.168.1.2', 'hostname2'), ..]
                 [('192.168.1.1', 'prefix-hostname1'), ('192.168.1.2', 'prefix-hostname2'), ..]

        """
        _ip_host_all = [
            (
                _term.getoutput(
                    f'''ip a | grep -oE "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | grep -E "^{ip_prefix}" | head -1'''),
                # add hostname if no node name prefix specified
                _term.getoutput(
                    'hostname') if nodename_prefix is None else f"""{nodename_prefix}{_term.getoutput('hostname')}"""
            )
            for _term in self.terms
        ]

        return _ip_host_all

    def add_hosts_all(self, ip_prefix: str, nodename_prefix=None):
        """
        Add ip-hostname string to all hosts in the list, by default 'localhost' is ignored!!!
        Args:
            ip_prefix/nodename_prefix:  the same as parameter in method _gather_ip_host
            ip_prefix: if more than one ip address is assigned,
                specified the prefix such as '172.16',
                so that only ip address startswith '172.16' will be add the the file '/etc/hosts'
            nodename_prefix: by default, hostname (except localhost) will be added to the file '/etc/hosts',
                but if you want a special one different with the hostname,
                you can set the value to this parameter as a prefix based on `hostname`
        Returns: list of host-database if preview is set to True or return codes

        """
        _ip_hosts = self._gather_ip_host(ip_prefix, nodename_prefix=nodename_prefix)
        host_db = []

        for _ip_host in _ip_hosts:
            _ip, _host = _ip_host

            # if not _ip.split('.')[0].isnumeric() or _host == 'localhost' or _ip == '':
            #     _ip_hosts.remove(_ip_host)
            if _ip.split('.')[0].isnumeric() and _host != 'localhost' and len(_ip.split('.')) == 4:
                host_db.append((_ip, _host))

        return [self.add_hosts(_ip_host[0], _ip_host[1]) for _ip_host in host_db] if host_db != [] else [-1]

    def add_known_hosts(self, *host, remove_exist=False):
        """
        Add host[s] to file '~/.ssh/known_hosts'

        Args:
            host (tuple) - hostname [ or | and ] IP address belonging to the same host
            remove_exist (bool) - set to True run command 'ssh-keygen -R HOST'

        command used:
        # ssh-keygen -R HOSTNAME
        # ssh-keygen -R IPADDR
        # ssh-keygen -R HOSTNAME,IPADDR

        # ssh-keyscan -H HOSTNAME >> ~/.ssh/known_hosts
        # ssh-keyscan -H IPADDR >> ~/.ssh/known_hosts
        # ssh-keyscan -H HOSTNAME,IPADDR >> ~/.ssh/known_hosts
        """
        _return_code = 0

        # remove all keys belonging to the host or IP
        for _host in host:
            if _host == '':
                continue

            # remove all keys belonging to the '_host'
            # return non-zero code is ok because _host not exists in the file
            _script_gen = f"""ssh-keygen -R {_host}"""

            # hash the hostname, append to the file
            _script_scan = f"""ssh-keyscan -H {_host} >> ~/.ssh/known_hosts"""

            self.getstatusoutput_thread(_script_gen) if remove_exist is True else ''
            _return_code += self.getstatus_sum(_script_scan)

        # return True if _return_code == 0 else False
        return _return_code

    def add_known_hosts_all(self, ip_prefix, nodename_prefix=None, remove_exist=False):
        """
        Add IP address with prefix 'ip_prefix' and node_name with prefix 'nodename_prefix' to SSH known_hosts file
        Args:
            ip_prefix:
            nodename_prefix:
            remove_exist:

        Returns:

        """
        _ip_hosts = self._gather_ip_host(ip_prefix, nodename_prefix)

        for _ip_host in _ip_hosts:
            _ip, _host = _ip_host

            if not _ip.split('.')[0].isnumeric():
                _ip_hosts.remove(_ip_host)

            if _host == 'localhost':
                _ip_hosts.remove(_ip_host)

        return [self.add_known_hosts(_ip_host[0], _ip_host[1], remove_exist=remove_exist) for _ip_host in _ip_hosts]

    def add_ssh_whitelist(self, address):
        _script = f"""if ! grep "{address}" /etc/hosts.allow; then echo "sshd:{address}" >> /etc/hosts.allow; fi"""
        return self.getstatusoutput_thread(_script) if address.count('.') == 3 else False

    def add_ssh_whitelist_all(self, ip_prefix: str):
        _ip_hosts = self._gather_ip_host(ip_prefix)
        _hosts = list(set([_i_h[0] for _i_h in _ip_hosts]))
        return [self.add_ssh_whitelist(_host) for _host in _hosts]

    def ssh_authorize_all(self, ssh_key_file=None):
        _ssh_key_file = ssh_key_file if ssh_key_file is not None else '~/.ssh/id_rsa'
        _ssh_pub_key_file = f'{_ssh_key_file}.pub'

        self.gen_ssh_key(ssh_key_file=_ssh_key_file)

        # gather ssh pub keys for all hosts
        _keys = self.getoutput(f"""cat {_ssh_pub_key_file}""")

        # append all keys to each host
        return [self.add_ssh_key(_key) for _key in _keys]

    def fetch_nic_thread(self, nic_prefix=None, nic_ignore_prefix=None) -> dict:
        _host_with_nic = {}

        def fetch_nic_target(_term: PyTermAutoSelect, _prefix, _i_prefix):
            # trans prefix string to tuple,  so that method ''.startswith can recognise
            _nic_prefix_tuple = tuple(_prefix.split()) if _prefix is not None else ()
            self.logger.colorlog(f'met nic prefix [{_nic_prefix_tuple}]', 'info')

            _nic_ignore_prefix_tuple = tuple(_i_prefix.split()) if _i_prefix is not None else ()
            self.logger.colorlog(f'met nic ignore prefix [{_nic_ignore_prefix_tuple}]', 'info')

            # script to fetch NICs from each host, return strings such as 'ens35:ens32:ens34:lo:vir0-nic:vir0:'
            _gather_nic_script = f"""cat /proc/net/dev | grep -E ".*[0-9][0-9]*" | awk '{{printf $1}}'; echo"""

            _nic_one_host = _term.getoutput(_gather_nic_script).split(':')
            self.logger.colorlog(f'fetch NICs from host [{_term.host}]', 'info')

            _nic_filtered = []

            for _nic in _nic_one_host:
                if _nic.startswith(_nic_prefix_tuple):
                    self.logger.colorlog(f'[{_nic}] startswith prefix [{_nic_prefix_tuple}], append to list', 'info')
                    _nic_filtered.append(_nic)
                    continue

                if _nic == 'lo' or _nic == '' or _nic.startswith(_nic_ignore_prefix_tuple):
                    self.logger.colorlog(f'met filter, [{_nic}] is ignored', 'info')
                    continue

                if _nic_prefix_tuple == ():
                    self.logger.colorlog(f'no NIC prefix specified, add [{_nic}] to result', 'info')
                    _nic_filtered.append(_nic)

            _host_with_nic.update({_term.host: _nic_filtered})

        _thread = [threading.Thread(target=fetch_nic_target, args=(_term, nic_prefix, nic_ignore_prefix)) for _term in
                   self.terms]
        [_t.start() for _t in _thread]
        [_t.join() for _t in _thread]

        return _host_with_nic

    def assign_ip_to_nic_thread(self, *ip_addr_with_prefix, gateways: str,
                                default_route=False, add_static_routes=False,
                                bond=False,
                                nic_prefix=None, nic_ignore_prefix=None,
                                restart_network=False, backup=False, preview=True):
        """
        This method is deprecated, use 'assign_ip' instead.

        try assign IP addresses to each NIC on the host with command 'ip addr add IP_ADDR dev NIC',
        then test connection to the gateway specified with command 'ping -c1 -W1 -I DEV GATEWAY',
        if ip_addr assign to the NIC pass the test, write permanent configuration ifcfg-DEV.
        Args:
            ip_addr_with_prefix: 192.168.1.1/24
            gateways: all gateways of subnet, order insensitive '192.168.1.1, 172.16.1.1'
            default_route: set to True if the gateway specified is default route
            add_static_routes: set to True adding static route for these subnets
            bond: set to True configure BOND interface
            nic_prefix: the same prefix string of NICs you wanted, type: strings split with blank
                        'ens' or 'ens enp'
                        nic_prefix has the most high priority
            nic_ignore_prefix: the prefix of NIC need to be ignored, type: strings split with blank
                        'vir' or 'vir eth'
            restart_network: set to True restart service 'network'
            backup: set to True backup NIC configuration 'ifcfg-ens32'
            preview: set to False write ifcfg file

        Returns: [(ip_addr, correct_nic)...]
        """
        _return = {}

        # every IP address has 3 dots, otherwise exit with exception raised
        assert len(ip_addr_with_prefix) * 3 == ''.join(ip_addr_with_prefix).count('.')
        gateway_list = [_gw.strip() for _gw in gateways.split(',')]
        assert len(gateway_list) * 3 == gateways.count('.')

        def _choose_gw_for_addr(_address_with_prefix, _gateway_list: list):
            """
            choose correct GATEWAY for IP address from _gateway_list
            """
            _net_id, _host_min, _host_max, *_ = ipcalc(_address_with_prefix)

            for _gw in _gateway_list:
                _part_gw = _gw.split('.')
                _part_min = _host_min.split('.')
                _part_max = _host_max.split('.')

                if _part_gw[0:3] == _part_min[0:3] == _part_max[0:3] and _part_min[3] <= _part_gw[3] <= _part_max[3]:
                    return _gw

            return '0.0.0.0'

        # assign IP as the value of _term.host
        try:
            _host_with_ip_gw = {self.terms[_index].host: (ip_addr_with_prefix[_index],
                                                          _choose_gw_for_addr(ip_addr_with_prefix[_index],
                                                                              gateway_list)
                                                          )
                                for _index in range(len(self.terms))
                                }
        except IndexError:
            self.logger.colorlog('number of IPs not equal to number of TERMs, return False', 'error')
            return _return

        _all_hosts_nic = self.fetch_nic_thread(nic_prefix, nic_ignore_prefix)

        # define threading target for assigning IP to host
        def _assign_ip_target(_term: PyTermAutoSelect, _address_with_prefix, _gateway, _default_route, _nics):
            _perfect_nic = None

            try:
                _addr, _prefix = _address_with_prefix.split('/')
            except ValueError:
                return _return

            for _nic in _nics:
                _ip_fit_nic_script_1 = f"""ip addr add {_address_with_prefix} dev {_nic}"""
                _ip_fit_nic_script_2 = f"""ip link set {_nic} up"""
                _ip_fit_nic_script_3 = f"""ping -c1 -W2 -I {_nic} {_gateway}"""
                _ip_fit_nic_script_4 = f"""ip addr del {_address_with_prefix} dev {_nic}"""

                _code_ip_add, _output = _term.getstatusoutput(_ip_fit_nic_script_1)
                _term.getoutput(_ip_fit_nic_script_2)
                _return_code, _output = _term.getstatusoutput(_ip_fit_nic_script_3)

                # never delete the ip if it exists before 'ip addr add' command executed
                # do not delete the ip if met the fit NIC after 'ip addr add'
                # _term.getoutput(_ip_fit_nic_script_4) if _code_ip_add == 0 else ''
                if _code_ip_add == 0 and (_return_code != 0 or preview):
                    _term.getoutput(_ip_fit_nic_script_4)
                # _term.getoutput(_ip_fit_nic_script_4) if _code_ip_add == 0 and _return_code != 0 else ''

                if _return_code == 0:
                    _perfect_nic = _nic
                    _msg = f'[{_term.host}] met perfect NIC [{_perfect_nic}] for [{_address_with_prefix}]'
                    self.logger.colorlog(_msg, 'info')
                    break

            if _perfect_nic is None:
                self.logger.colorlog(f'[{_term.host}] no fit NIC found for {_address_with_prefix}', 'error')
                return False

            _ifcfg_txt = [
                'TYPE=Ethernet',
                'BOOTPROTO=static',
                f'NAME={_perfect_nic}',
                f'DEVICE={_perfect_nic}',
                'ONBOOT=yes',
                f'IPADDR={_addr}',
                f'PREFIX={_prefix}',
                f'GATEWAY={_gateway}' if _default_route is True else ''
            ]

            _ifcfg_path = '/etc/sysconfig/network-scripts/'
            _ifcfg_file = os.path.join(_ifcfg_path, f'ifcfg-{_perfect_nic}')
            _ifcfg_backup_file = os.path.join(_ifcfg_path, f'bak.ifcfg-{_perfect_nic}.`date +%m%d%H%M%S`')

            # backup the NIC exist configuration if 'backup' is set to True
            _backup_command = f"""mv {_ifcfg_file} {_ifcfg_backup_file}"""
            if backup:
                _term.getoutput(_backup_command)
            else:
                _term.getoutput(f'>{_ifcfg_file}')  # clean the configuration of _perfect_nic

            # fetch IP address on first suitable NIC before write ifcfg file
            _ip_on_perfect_nic = _term.getoutput(
                f'''ip addr show dev {_perfect_nic} | grep -oE "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/[0-9]*" | tr "\\n" " "''')
            # write the configuration to file if parameter 'preview' is set to False
            [_term.getoutput(f'echo {_line} >> {_ifcfg_file}') for _line in _ifcfg_txt] if not preview else []

            _return.update({_term.host: (_address_with_prefix, _perfect_nic, _ip_on_perfect_nic.strip())})
            return True

        # end of IP assign target defination

        # add static routes threading target
        def _add_static_routes_target(_term: PyTermAutoSelect, _addrs_with_prefix, _gateway):

            _target_subnet_ids = list(set([ipcalc(_addr)[0] for _addr in _addrs_with_prefix]))
            _config_file = '/etc/sysconfig/static-routes'
            _static_routes = []

            for _net_id in _target_subnet_ids:
                _add_route_command = f'route add -net {_net_id} gw {_gateway}'
                _return_code = _term.getstatusoutput(_add_route_command)[0]  # add temporary route

                if _return_code == 0:  # append static routes ONLY those can be added by command 'route add -net'
                    _static_routes.append(f'any net {_net_id} gw {_gateway}')

            for _route in _static_routes:
                _script = f"""if ! grep "{_route}" {_config_file}; then echo "{_route}" >> {_config_file}; fi"""
                _term.getoutput(_script)

        # end of static routes adding target defination

        _thread = [threading.Thread(target=_assign_ip_target,
                                    args=(_term,
                                          _host_with_ip_gw[_term.host][0],
                                          _host_with_ip_gw[_term.host][1],
                                          default_route,
                                          _all_hosts_nic[_term.host]
                                          )
                                    )
                   for _term in self.terms]

        [_t.start() for _t in _thread]
        [_t.join() for _t in _thread]

        if add_static_routes:  # auto add static routes ONLY the parameter is set to True
            _thread_routes = [threading.Thread(target=_add_static_routes_target,
                                               args=(_term,
                                                     ip_addr_with_prefix,
                                                     _host_with_ip_gw[_term.host][1]
                                                     )
                                               )
                              for _term in self.terms]

            [_t.start() for _t in _thread_routes]
            [_t.join() for _t in _thread_routes]

        if restart_network:
            self.logger.colorlog('restart_network is set to True, restart the service', 'info')
            self.getstatusoutput_thread('systemctl restart network')

        return _return

    def assign_ip(self, *ip_addr_with_prefix, gateways: str,
                  default_route=False, add_static_routes=False,
                  bonding=False, bonding_mode=1,
                  nic_prefix=None, nic_ignore_prefix=None,
                  restart_network=False, backup=False, preview=True):
        """
        try assign IP addresses to each NIC on the host with command 'ip addr add IP_ADDR dev NIC',
        then test connection to the gateway specified with command 'ping -c1 -W1 -I DEV GATEWAY',
        if ip_addr assign to the NIC pass the test, write permanent configuration ifcfg-DEV.
        Args:
            ip_addr_with_prefix: 192.168.1.1/24
            gateways: all gateways of subnet, order insensitive '192.168.1.1, 172.16.1.1'
            default_route: set to True if the gateway specified is default route
            add_static_routes: set to True adding static route for these subnets
            bonding: set to True configure BOND interface
            bonding_mode: 1 -> active-backup; 5 -> balance-tlb ...
            nic_prefix: the same prefix string of NICs you wanted, type: strings split with blank
                        'ens' or 'ens enp'
                        nic_prefix has the most high priority
            nic_ignore_prefix: the prefix of NIC need to be ignored, type: strings split with blank
                        'vir' or 'vir eth'
            restart_network: set to True restart service 'network'
            backup: set to True backup NIC configuration 'ifcfg-ens32'
            preview: set to False write ifcfg file

        Returns: [(ip_addr, correct_nic)...]
        """
        _return = {}

        # every IP address has 3 dots, otherwise exit with exception raised
        assert len(ip_addr_with_prefix) * 3 == ''.join(ip_addr_with_prefix).count('.')
        gateway_list = [_gw.strip() for _gw in gateways.split(',')]
        assert len(gateway_list) * 3 == gateways.count('.')

        def _choose_gw_for_addr(_address_with_prefix, _gateway_list: list):
            """
            choose correct GATEWAY for IP address from _gateway_list
            """
            _net_id, _host_min, _host_max, *_ = ipcalc(_address_with_prefix)

            for _gw in _gateway_list:
                _part_gw = _gw.split('.')
                _part_min = _host_min.split('.')
                _part_max = _host_max.split('.')

                if _part_gw[0:3] == _part_min[0:3] == _part_max[0:3] and _part_min[3] <= _part_gw[3] <= _part_max[3]:
                    return _gw

            return '0.0.0.0'

        # {_term.host: (address_to_assign, gateway), ...}
        try:
            _host_with_ip_gw = {self.terms[_index].host: (ip_addr_with_prefix[_index],
                                                          _choose_gw_for_addr(ip_addr_with_prefix[_index],
                                                                              gateway_list)
                                                          )
                                for _index in range(len(self.terms))
                                }
        except IndexError:
            self.logger.colorlog('number of IPs not equal to number of TERMs, return False', 'error')
            return _return

        _all_hosts_nic = self.fetch_nic_thread(nic_prefix, nic_ignore_prefix)

        # define threading target for assigning IP to host
        def _assign_ip_target(_term: PyTermAutoSelect,
                              _address_with_prefix,
                              _gateway,
                              _default_route,
                              _nics,
                              _bonding=bonding,
                              _mode=bonding_mode):
            _perfect_nic = None
            _bond_name = None
            _bond_nic = []
            _ifcfg_path = '/etc/sysconfig/network-scripts/'

            def __write_config(__interface_name, __ifcfg_line: list, __backup_config=backup):
                __ifcfg_file = os.path.join(_ifcfg_path, f'ifcfg-{__interface_name}')
                __ifcfg_backup_file = os.path.join(_ifcfg_path, f'bak.ifcfg-{__interface_name}.`date +%m%d%H%M%S`')

                # backup the NIC exist configuration if 'backup' is set to True
                __backup_command = f"""mv {__ifcfg_file} {__ifcfg_backup_file}"""
                if __backup_command:
                    _term.getoutput(__backup_command)
                else:
                    _term.getoutput(f'>{__ifcfg_file}')  # clean the configuration of __interface_name

                # fetch IP address on first suitable NIC before write ifcfg file
                __show_ip = f'''ip addr show dev {__interface_name} 2>/dev/null | grep -oE "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/[0-9]*" | tr "\\n" " "'''
                __ip_on_interface = _term.getoutput(__show_ip)
                # write the configuration to file if parameter 'preview' is set to False
                [_term.getoutput(f'echo {_line} >> {__ifcfg_file}') for _line in __ifcfg_line] if not preview else []

                return __ip_on_interface

            # end of sub method defination

            try:
                _addr, _prefix = _address_with_prefix.split('/')
            except ValueError:
                return _return

            for _nic in _nics:
                _ip_fit_nic_script_1 = f"""ip addr add {_address_with_prefix} dev {_nic}"""
                _ip_fit_nic_script_2 = f"""ip link set {_nic} up"""
                _ip_fit_nic_script_3 = f"""ping -c1 -W2 -I {_nic} {_gateway}"""
                _ip_fit_nic_script_4 = f"""ip addr del {_address_with_prefix} dev {_nic}"""

                _code_ip_add, _output = _term.getstatusoutput(_ip_fit_nic_script_1)
                _term.getoutput(_ip_fit_nic_script_2)
                _return_code, _output = _term.getstatusoutput(_ip_fit_nic_script_3)

                # never delete the ip if it exists before 'ip addr add' command executed
                # do not delete the ip if met the fit NIC after 'ip addr add'
                # _term.getoutput(_ip_fit_nic_script_4) if _code_ip_add == 0 else ''
                # delete address on local NIC if bonding=True, otherwise 2nd NIC not connectable!!!
                if _code_ip_add == 0 and (_return_code != 0 or preview or bonding):
                    _term.getoutput(_ip_fit_nic_script_4)

                if _return_code == 0:
                    _perfect_nic = _nic if _nic != '' else _perfect_nic
                    _msg = f'[{_term.host}] met perfect NIC [{_perfect_nic}] for [{_address_with_prefix}]'
                    self.logger.colorlog(_msg, 'info')

                    if not _bonding:
                        break
                    else:
                        _bond_nic.append(_perfect_nic) if _perfect_nic is not None else ''
                        continue

            if _perfect_nic is None:
                self.logger.colorlog(f'[{_term.host}] no suitable NIC found for {_address_with_prefix}', 'error')
                return False

            # todo naming a bonding interface to be started from bond0 instead of bond1
            _name_a_bond = f'''echo $((`ls {_ifcfg_path}/ifcfg-bond* 2>/dev/null | grep -Eo "[0-9]$" | sort -h | tail -1`+1))'''
            if _bonding:
                _bond_name = f'bond{_term.getoutput(_name_a_bond)}'

                if len(_bond_nic) != 2:
                    self.logger.colorlog(f'naming a bonding interface [{_bond_name}] failed,'
                                         f'or less than 2 NIC <{_bond_nic}> is connectable '
                                         f'of host [{_term.host}]', 'warn')
                    return False

                _ifcfg_bond = [
                    f'DEVICE={_bond_name}',
                    'TYPE=Bond',
                    f'NAME={_bond_name}',
                    'BONDING_MASTER=yes',
                    'BOOTPROTO=none',
                    'ONBOOT=yes',
                    f'BONDING_OPTS="mode={_mode} miimon=100"',
                    f'PRIMARY={_bond_nic[0]}',
                    f'IPADDR={_addr}',
                    f'PREFIX={_prefix}',
                    f'GATEWAY={_gateway}' if _default_route is True else ''
                ]

                _ifcfg_slave_1 = [
                    'TYPE=Ethernet',
                    'BOOTPROTO=none',
                    f'DEVICE={_bond_nic[0]}',
                    'ONBOOT=yes',
                    f'MASTER={_bond_name}',
                    'SLAVE=yes'
                ]

                _ifcfg_slave_2 = [
                    'TYPE=Ethernet',
                    'BOOTPROTO=none',
                    f'DEVICE={_bond_nic[1]}',
                    'ONBOOT=yes',
                    f'MASTER={_bond_name}',
                    'SLAVE=yes'
                ]

                _ip_on_bond = __write_config(_bond_name, _ifcfg_bond)
                __write_config(_bond_nic[0], _ifcfg_slave_1)
                __write_config(_bond_nic[1], _ifcfg_slave_2)

                _return.update({_term.host: (_address_with_prefix,
                                             f'{_bond_name}/{_bond_nic[0]}/{_bond_nic[1]}',
                                             _ip_on_bond.strip())})

            else:
                # configuration for non-bonding interface
                _ifcfg_txt = [
                    'TYPE=Ethernet',
                    'BOOTPROTO=static',
                    f'NAME={_perfect_nic}',
                    f'DEVICE={_perfect_nic}',
                    'ONBOOT=yes',
                    f'IPADDR={_addr}',
                    f'PREFIX={_prefix}',
                    f'GATEWAY={_gateway}' if _default_route is True else ''
                ]

                _ip_on_nic = __write_config(_perfect_nic, _ifcfg_txt)
                _return.update({_term.host: (_address_with_prefix,
                                             _perfect_nic,
                                             _ip_on_nic.strip())})

            return True

        # end of IP assign target defination

        # add static routes threading target
        def _add_static_routes_target(_term: PyTermAutoSelect, _addrs_with_prefix, _gateway):

            _target_subnet_ids = list(set([ipcalc(_addr)[0] for _addr in _addrs_with_prefix]))
            _config_file = '/etc/sysconfig/static-routes'
            _static_routes = []

            for _net_id in _target_subnet_ids:
                _add_route_command = f'route add -net {_net_id} gw {_gateway}'
                _return_code = _term.getstatusoutput(_add_route_command)[0]  # add temporary route

                if _return_code == 0:  # append static routes ONLY those can be added by command 'route add -net'
                    _static_routes.append(f'any net {_net_id} gw {_gateway}')

            for _route in _static_routes:
                _script = f"""if ! grep "{_route}" {_config_file}; then echo "{_route}" >> {_config_file}; fi"""
                _term.getoutput(_script)

        # end of static routes adding target defination

        _thread = [threading.Thread(target=_assign_ip_target,
                                    args=(_term,
                                          _host_with_ip_gw[_term.host][0],
                                          _host_with_ip_gw[_term.host][1],
                                          default_route,
                                          _all_hosts_nic[_term.host]
                                          )
                                    )
                   for _term in self.terms]

        [_t.start() for _t in _thread]
        [_t.join() for _t in _thread]

        if add_static_routes:  # auto add static routes ONLY the parameter is set to True
            _thread_routes = [threading.Thread(target=_add_static_routes_target,
                                               args=(_term,
                                                     ip_addr_with_prefix,
                                                     _host_with_ip_gw[_term.host][1]
                                                     )
                                               )
                              for _term in self.terms]

            [_t.start() for _t in _thread_routes]
            [_t.join() for _t in _thread_routes]

        if restart_network:
            self.logger.colorlog('restart_network is set to True, restart the service', 'info')
            self.getstatusoutput_thread('systemctl restart network')

        return _return

    def add_static_route(self, target_addr_with_prefix, source_gateway):
        """
        append static routes from 'source' to 'target' via 'gateway' to file '/etc/sysconfig/static-routes'
        Args:
            target_addr_with_prefix: target network_id/prefix
            source_gateway: source subnet gateway
        Returns:
        """
        # todo must verify source_gateway is connectable!!!!
        _target_subnet_id_prefix, *_ = ipcalc(target_addr_with_prefix)

        _config_file = '/etc/sysconfig/static-routes'
        _static_routes = f'any net {_target_subnet_id_prefix} gw {source_gateway}'

        _add_route_command = f'route add -net {_target_subnet_id_prefix} gw {source_gateway}'
        _script = f"""if ! grep "{_static_routes}" {_config_file}; then echo "{_static_routes}" >> {_config_file}; fi"""

        # add temporary routes via command 'route add -net IP/prefix via GATEWAY'
        # only routes successfully added should append to configuration file '/etc/sysconfig/static-routes'
        _return1 = self.getstatusoutput_thread(_add_route_command)
        _return2 = self.getstatusoutput_thread(_script)

        _return = {_key: _return1[_key][0] + _return2[_key][0] for _key in _return1.keys()}

    def set_timezone(self, timezone='Asia/Shanghai'):
        """
        set OS timezone, default 'Asia/Shanghai'
        """
        return self.getstatus_bool(f'timedatectl set-timezone {timezone}')

    def disable_ssh_dns(self):
        return self.getstatus_bool(
            """sed -i 's/#useDNS yes/useDNS no/g' /etc/ssh/sshd_config && systemctl restart sshd""")

    def add_yum_repo(self, baseurl, repo_name='rhel', repo_desc='RHEL Base Repo'):
        """

        Args:
            baseurl:
            repo_name:
            repo_desc:

        Returns: sum of return codes

        """
        _repo_file = f'/etc/yum.repos.d/{repo_name}.repo'
        _repo_config = [f'[{repo_name}]',
                        f'name = {repo_desc}',
                        f'baseurl = {baseurl}',
                        'enable = 1',
                        'gpgcheck = 0']

        self.getoutput_thread(f'>{_repo_file}')

        for _txt_line in _repo_config:
            self.getoutput_thread(f'echo "{_txt_line}" >> {_repo_file}')

        # return self.getstatus_bool('yum clean all && yum install -y net-tools')
        return self.getstatus_sum('yum clean all && yum install -y net-tools')


def ipcalc(address, netmask='24'):
    """
    input '192.168.1.1/24' or '192.168.1.1', '24'
    output ('192.168.1.0/24', '192.168.1.1', '192.168.1.254', '192.168.1.255', 254)

    Args:
        address: IP address or IP address with subnet prefix, such as '192.168.1.1' or '192.168.1.1/24'
        netmask: subnet mask, such as '24' or '255.255.255.0'

    Returns: tuple('network_id/prefix', 'host_min', 'host_max', 'broadcast', 'number_of_hosts')

    """
    if '/' in address:
        address, netmask = address.split('/')

    def trans_ip_bin(_address):
        _address = _address.split('.')
        try:
            _address_bin = ''.join([f'{int(_num):0>8b}' for _num in _address])
        except ValueError:
            _address_bin = ''
        return _address_bin

    def trans_netmask_bin(_netmask):
        if str(_netmask).isnumeric():
            _host_bit = '1' * int(_netmask)
            _net_bit = '0' * (32 - int(_netmask))
            return f'{_host_bit}{_net_bit}'
        else:
            return trans_ip_bin(_netmask)

    def netmask_to_bit(_netmask):
        _netmask_bit = 0
        if str(_netmask).isnumeric():
            return _netmask

        else:
            _netmask_bin = trans_netmask_bin(_netmask)
            for _bit in _netmask_bin:
                if _bit == '1':
                    _netmask_bit += 1

            return _netmask_bit

    def trans_bin_ip(_ip_bin):
        _part_1 = int(_ip_bin[0:8], 2)
        _part_2 = int(_ip_bin[8:16], 2)
        _part_3 = int(_ip_bin[16:24], 2)
        _part_4 = int(_ip_bin[24:32], 2)

        return f'{_part_1}.{_part_2}.{_part_3}.{_part_4}'

    _addr_bin = list(trans_ip_bin(address))
    _mask_bin = list(trans_netmask_bin(netmask))
    _network_id = ''
    _host_min = ''
    _host_max = ''
    _broadcast = ''
    _no_hosts = '0'  # change from '' to '0' for being compatible with ip with 32 bit netmask '192.168.1.1/32'

    for _index in range(0, 32):
        if _mask_bin[_index] == '1':
            _network_id += _addr_bin[_index]
            _host_min += _addr_bin[_index]
            _host_max += _addr_bin[_index]
            _broadcast += _addr_bin[_index]
        else:
            _network_id += '0'
            _broadcast += '1'
            _host_min += '1' if _index == 31 else '0'
            _host_max += '0' if _index == 31 else '1'
            _no_hosts += '1'

    _network_id = trans_bin_ip(_network_id)
    _host_min = trans_bin_ip(_host_min)
    _host_max = trans_bin_ip(_host_max)
    _broadcast = trans_bin_ip(_broadcast)
    _no_hosts = int(_no_hosts, 2) - 1

    return f'{_network_id}/{netmask_to_bit(netmask)}', _host_min, _host_max, _broadcast, _no_hosts


def normalize_addr(*address):
    """
    transform address in format '192.168.1.1/2/3=24' to '192.168.1.1/24,192.168.1.2/24,192.168.1.3/24'
        from '192.168.1.1/2/3' to '192.168.1.1, 192.168.1.2, 192.168.1.3'

    Args:
        address: IP address

    Returns: list of addresses
    """
    _return = []

    for _addr in address:

        if '=' in _addr:
            try:
                _prefix = '.'.join(_addr.split('.')[0:3])
                _netmask = _addr.split('=')[-1]

                _last_part = [_part for _part in _addr.split('=')[0].split('.')[3].split('/')]

                _ = [_return.append(f"""{_prefix}.{_part}/{_netmask}""") for _part in _last_part]

            except IndexError:
                pass

        elif '/' in _addr and '=' not in _addr:
            try:
                _prefix = '.'.join(_addr.split('.')[0:3])
                _last_part = [_part for _part in _addr.split('.')[3].split('/')]

                _ = [_return.append(f"""{_prefix}.{_part}""") for _part in _last_part]

            except IndexError:
                pass

        elif _addr.count('.') == 3:
            _return.append(_addr)

        elif _addr == 'localhost':
            _return.append(_addr)

    return _return


class GpfsManager(MultiTerm):
    def __init__(self, hosts,
                 *datacenter_and_hostnames,
                 pri_node=None, sec_node=None,
                 fs_name=None, mount_point=None,
                 preview=True, debug=False):
        """
        Initiater IBM GPFS Cluster Configuration
        Parameters:
            hosts (tuple) - tuple of 4-tuple include host, user, password and port
            debug (bool) - set to True display logs on monitor
        """
        # prefix of nodename append to hostname of OS
        # prefix of heartbeats IP addresses
        # prefix of management IP addresses
        # read value from method verify_config()
        self.node_prefix = self.hb_prefix = self.mgmt_ip_prefix = None

        self.hostnames = self.nodenames = self.mgmt_ips = self.hb_ips = None

        self.datacenter = [_dc_host.split(':')[0] for _dc_host in datacenter_and_hostnames]

        num_of_datacenter = len(self.datacenter)
        if num_of_datacenter <= 1:  # must have at least one disk share the same SCSI ID
            pass

        else:  # the disk belongs to the same DC must share the same SCSI ID
            pass

        self.stage = {
            'verify_hosts': False,
            'add_hosts': False,
            'authorise_ssh': False,
            'add_known_hosts': False,
            'config_yum': False,
            'inst_pkgs': False,
            'inst_gpfs': False,
            'build_module': False,
            'append_path': False,
            'create_cls_cfg': False,
            'create_cls': False,
            'accept_lns': False,
            'startup_cls': False,
            'create_nsd_cfg': False,
            'create_nsd': False,
            'add_tiebreaker': False,
            'create_fs': False,
            'mount_fs': False
        }
        self._stage_file = os.path.join(_HOME_, '_stage.yaml')

        self.preview = preview

        self.cls_cfg = []
        self.node_file = '/etc/gpfs/node.cfg'

        self.nsd_cfg = []
        # self.nsd_cfg = {'mmfs1': }
        self.stanzas_file = '/etc/gpfs/nsd.cfg'
        self.tiebreaker_disks="gpfs1nsd;gpfs2nsd;gpfs3nsd"

        self.fs_name = fs_name if fs_name is not None else DEF_FS_NAME
        self.mount_point = mount_point if mount_point is not None else DEF_MOUNT_POINT

        MultiTerm.__init__(self, hosts, debug=debug)

        # primary node of the GPFS cluster
        self.pri_node = pri_node if pri_node is not None else self.terms[0].getoutput('hostname')
        self.sec_node = sec_node if sec_node is not None else self.terms[1].getoutput('hostname')

        self.cls_name = f'{self.pri_node.strip(self.pri_node.strip(self.sec_node))}_cluster'

        self.pri_term = None

        for term in self.terms:
            if term.host == self.pri_node or term.getoutput('hostname') == self.pri_node:
                self.pri_term = term

    def write_stage(self, key=None, value=False):
        if key in self.stage.keys():
            self.stage[key] = value

        with open(self._stage_file, 'w') as f:
            dump(self.stage, f)

        return value

    def recover_stage(self):
        """
        Read stage from file '_stage.yaml'
        Returns: self.stage: dict
        """
        with open(self._stage_file, 'r+') as f:
            self.stage = safe_load(f)

        return self.stage

    def verify_config(self,
                      prod_addresses=None,
                      heartbeats=None, heartbeats_prefix=None,
                      hostnames=None,
                      nodename_prefix=None):
        """
        Read addresses and names from parameters
        Returns:
            True if all addresses have been assigned to the hosts
            and all hostnames are the same as the value of args.
        """
        if self.stage['verify_hosts']:
            return True

        assert heartbeats is not None or heartbeats_prefix is not None

        prod_addresses = [] if prod_addresses is None else prod_addresses
        heartbeats = [] if heartbeats is None else heartbeats
        hostnames = [] if hostnames is None else hostnames

        mgmt_addresses = []
        _ = [mgmt_addresses.append(_term.host) if _term.host != 'localhost' else '' for _term in self.terms]

        _return_code = 0
        addrlist = []
        hostname_list = [_name for _name in self.getoutput_thread('hostname').values()]

        _ = [addrlist.extend(_addr.split('\n')) for _addr in
             self.getoutput_thread('''ip a | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"''').values()]

        _return_code += 0 if set(prod_addresses).issubset(set(addrlist)) else 1
        _return_code += 0 if set(heartbeats).issubset(set(addrlist)) else 1
        _return_code += 0 if set(hostnames).issubset(set(hostname_list)) else 1

        self.node_prefix = nodename_prefix if nodename_prefix is not None else DEF_NODE_PREFIX

        # fetch prefix[ex] of heartbeats IP addresses
        if heartbeats_prefix is not None:
            self.hb_prefix = heartbeats_prefix
        else:
            self.hb_prefix = tuple(set(['.'.join(_addr.split('.')[0:2]) for _addr in heartbeats]))

        # fetch prefix[es] of management IP addresses
        self.mgmt_ip_prefix = tuple(set(['.'.join(_addr.split('.')[0:2]) for _addr in mgmt_addresses]))

        if _return_code == 0:
            self.hostnames = hostname_list
            self.nodenames = [f'{self.node_prefix}{_name}' for _name in self.hostnames]
            self.mgmt_ips = mgmt_addresses
            self.hb_ips = []
            _ = [self.hb_ips.append(_addr) if _addr.startswith(self.hb_prefix) else '' for _addr in addrlist]

        return self.write_stage('verify_hosts', True) if _return_code == 0 else self.write_stage('verify_hosts', False)

    def add_cls_hosts_db(self):
        if self.stage['add_hosts']:
            return True

        _return_code = 0

        if self.preview:

            _title = 'Host Database Info'
            print('-'*30, f'{_title:^20s}', '-'*30, sep='')
            print(f'Management address: [{"|".join(self.mgmt_ips)}]\n'
                  f'Heartbeats address: [{"|".join(self.hb_ips)}]\n'
                  f'Hostnames: [{"|".join(self.hostnames)}]\n'
                  f'Nodenames: [{"|".join(self.nodenames)}]\n')
            return True

        for _pre in self.mgmt_ip_prefix:
            _return_code += sum(self.add_hosts_all(ip_prefix=_pre))

        for _pre in self.hb_prefix:
            _return_code += sum(self.add_hosts_all(ip_prefix=_pre,
                                                   nodename_prefix=self.node_prefix))

        return self.write_stage('add_hosts', True) if _return_code == 0 else self.write_stage('add_hosts', False)

    def authorize_cls_ssh_all(self):
        _stage_key = 'authorise_ssh'
        if self.stage[_stage_key]:
            return True

        if self.preview:
            _title = 'SSH Authorization'
            print('-'*30, f'{_title:^20s}', '-'*30, sep='')
            print('Key-based SSH authorization ignored as [preview] is set to True.')
            return True

        _return_code = sum(self.ssh_authorize_all())

        return self.write_stage(_stage_key, True) if _return_code == 0 else self.write_stage(_stage_key, False)

    def add_cls_ssh_known_hosts(self):
        _stage_key = 'add_known_hosts'
        if self.stage[_stage_key]:
            return True

        _return_code = 0

        if self.preview:
            print(f'Addresses [{"|".join(self.hb_ips)}]\n'
                  f'And nodenames [{"|".join(self.nodenames)}] will be appended to known_hosts.\n')
            return True

        for _pre in self.hb_prefix:
            _return_code += sum(self.add_known_hosts_all(ip_prefix=_pre, nodename_prefix=self.node_prefix))

        return self.write_stage(_stage_key, True) if _return_code == 0 else self.write_stage(_stage_key, False)

    def setup_cls_yum(self, baseurl, name=None, desc=None):
        _stage_key = 'config_yum'
        if self.stage[_stage_key]:
            return True

        if self.preview:
            _title = 'YUM & Packages'
            print('-'*30, f'{_title:^20s}', '-'*30, sep='')
            print(f'Baseurl {baseurl}')
            return True

        _return_code = self.add_yum_repo(baseurl, repo_name=name, repo_desc=desc)

        return self.write_stage(_stage_key, True) if _return_code == 0 else self.write_stage(_stage_key, False)

    def inst_cls_required_pkgs(self):
        _stage_key = 'inst_pkgs'
        _return_code = 0
        if self.stage[_stage_key]:
            return True

        _required_pkgs = ['kernel-headers', 'kernel-devel', 'libgomp', 'glibc-headers', 'glibc-devel',
                          'gcc', 'gcc-c++', 'libstdc++', 'cpp', 'binutils', 'm4', 'net-tools', 'ksh']

        if self.preview:
            print(f'Required packages: [{"|".join(_required_pkgs)}]')
            return True

        for _pkg in _required_pkgs:
            _return_code += self.getstatus_sum(f'yum install -y {_pkg}')

        return self.write_stage(_stage_key, True) if _return_code == 0 else self.write_stage(_stage_key, False)

    def inst_gpfs_rpm(self):
        _stage_key = 'inst_gpfs'
        _return_code = 0
        if self.stage[_stage_key]:
            return True

        _gpfs_rpms = ['gpfs.adv*.rpm', 'gpfs.base*.rpm', 'gpfs.compression*.rpm', 'gpfs.crypto*.rpm',
                      'gpfs.docs*.rpm', 'gpfs.gpl*.rpm', 'gpfs.gskit*.rpm', 'gpfs.license*.rpm', 'gpfs.msg*.rpm']
        _gpfs_loc = '/usr/lpp/mmfs/*.*.*.*/gpfs_rpms'

        if self.preview:
            print(f'GPFS packages: [{"|".join(_gpfs_rpms)}]\n'
                  f'GPFS rpm location: [{_gpfs_loc}]')
            return True

        for _rpm in _gpfs_rpms:
            _return_code += self.getstatus_sum(f'rpm -ivh {_gpfs_loc}/{_rpm}')

        return self.write_stage(_stage_key, True) if _return_code == 0 else self.write_stage(_stage_key, False)

    def build_gpfs(self):
        _stage_key = 'build_module'
        if self.stage[_stage_key]:
            return True

        if self.preview:
            print('build GPFS kernel module ignored.\n')
            return True

        _return_code = self.getstatus_sum('/usr/lpp/mmfs/bin/mmbuildgpl')
        _return_code += self.getstatus_sum('ls -l /lib/modules/`uname -r`/extra')

        return self.write_stage(_stage_key, True) if _return_code == 0 else self.write_stage(_stage_key, False)

    def add_command_path(self):
        _stage_key = 'append_path'
        if self.stage[_stage_key]:
            return True

        _mmfs_path = '/usr/lpp/mmfs/bin'
        _path_append = f'export PATH=$PATH:{_mmfs_path}'
        _bash_pro = '~/.bash_profile'
        _add_path_command = f"""if ! grep '{_mmfs_path}' {_bash_pro}; then echo '{_path_append}' >> {_bash_pro}; fi"""

        if self.preview:
            _title = 'Environment'
            print('-' * 30, f'{_title:^20s}', '-' * 30, sep='')
            print(f'GPFS bin path: [{_mmfs_path}]\n'
                  f'Bash profile: [{_bash_pro}]\n'
                  f'Command to append PATH: [{_add_path_command}]\n')
            return True

        _return_code = self.getstatus_sum(_add_path_command)
        _return_code += self.getstatus_sum(f'source {_bash_pro}')

        return self.write_stage(_stage_key, True) if _return_code == 0 else self.write_stage(_stage_key, False)

    def create_cls_cfg(self, *node_and_role):
        """
        Create GPFS cluster node configuration.
        If nodes are quorum-manager, the left are noquorum-client
        Args:
            *node_and_role: node1:quorum-manager, node2:noquorum-client

        Returns:

        """
        _stage_key = 'create_cls_cfg'
        _return_code = 0

        if self.stage[_stage_key]:
            return True

        for _node_str in node_and_role:
            if ':' not in _node_str or '-' not in _node_str:
                continue

            self.cls_cfg.append(_node_str)

        if node_and_role == ():
            self.cls_cfg = [f"""{self.node_prefix}{_term.getoutput('hostname')}:quorum-manager""" for _term in self.terms[0:7]]
            self.cls_cfg.extend([f"""{self.node_prefix}{_term.getoutput('hostname')}:quorum-manager""" for _term in self.terms[7:]])

        if self.preview:
            _title = 'GPFS Configuration'
            print('-' * 30, f'{_title:^20s}', '-' * 30, sep='')
            print(f'Node configuration: ')
            _ = [print(f'\t{_line}') for _line in self.cls_cfg]
            return True

        for _txt_line in self.cls_cfg:
            _code, _output = self.pri_term.getstatusoutput(f"""echo {_txt_line} >> {self.node_file}""")
            _return_code += _code

        return self.write_stage(_stage_key, True) if _return_code == 0 else self.write_stage(_stage_key, True)

    def create_cls(self, node_file=None):
        # NodeName:NodeDesignations:AdminNodeName
        _stage_key = 'create_cls'
        if self.stage[_stage_key]:
            return True

        node_file = self.node_file if node_file is None else node_file
        _create_cls = f"""mmcrcluster -A -N {node_file} -p {self.pri_node} -s {self.sec_node} -r /usr/bin/ssh -R /usr/bin/scp -C {self.cls_name}"""

        if self.preview:
            print(f'Command creating cluster: [{_create_cls}]')
            return True

        _code, _output = self.pri_term.getstatusoutput(_create_cls)

        return self.write_stage(_stage_key, True) if _code == 0 else self.write_stage(_stage_key, True)

    def accept_license(self, node_name=None):
        _stage_key = 'accept_lns'
        if self.stage[_stage_key]:
            return True

        node_name = 'all' if node_name is None else node_name
        _accept_license = f"""mmchlicense server --accept -N {node_name}"""

        if self.preview:
            print(f'Command accepting license: [{_accept_license}]')
            return True

        _code, _output = self.pri_term.getstatusoutput(_accept_license)

        return self.write_stage(_stage_key, True) if _code == 0 else self.write_stage(_stage_key, False)

    def create_nsd_cfg(self):
        _stage_key = 'create_nsd_cfg'
        if self.stage[_stage_key]:
            return True

        if self.preview:
            print(f'NSD configuration:')
            _ = [print(f'\t{_nsd}') for _nsd in self.nsd_cfg]
            return True

        # fixme
        return self.write_stage(_stage_key, True) if _code == 0 else self.write_stage(_stage_key, False)

    def create_nsd(self, stanzas_file=None):
        _stage_key = 'create_nsd'
        if self.stage[_stage_key]:
            return True

        stanzas_file = stanzas_file if stanzas_file is not None else self.stanzas_file
        _cr_nsd = f"""mmcrnsd -F {stanzas_file}"""

        if self.preview:
            print(f'Command creating NSD: [{_cr_nsd}]')
            return True

        _code, _output = self.pri_term.getstatusoutput(_cr_nsd)

        return self.write_stage(_stage_key, True) if _code == 0 else self.write_stage(_stage_key, False)

    def config_tiebreak(self, tiebreaker_disks=None):
        # tiebreakerDisks="gpfs1nsd;gpfs2nsd;gpfs3nsd"
        _stage_key = 'add_tiebreaker'
        if self.stage[_stage_key]:
            return True

        _disk = tiebreaker_disks if tiebreaker_disks is not None else self.tiebreaker_disks
        _add_tie = f"""mmchconfig tiebreakerDisks={_disk}"""

        if self.preview:
            print(f'Tiebreaker disks: [{_disk}]')
            print(f'Command modifying config: {_add_tie}')
            return True

        _code, _output = self.pri_term.getstatusoutput(_add_tie)

        return self.write_stage(_stage_key, True) if _code == 0 else self.write_stage(_stage_key, False)

    def create_filesystem(self, fs_name=None, stanzas_file=None, block_size='4M', mount_point=None):
        _stage_key = 'create_fs'
        if self.stage[_stage_key]:
            return True

        fs_name = fs_name if fs_name is not None else self.fs_name
        nsd_cfg = stanzas_file if stanzas_file is not None else self.stanzas_file
        mount_point = mount_point if mount_point is not None else self.mount_point

        _cr_fs = f"""mmcrfs {fs_name} -F {nsd_cfg} -A yes -B {block_size} -T {mount_point}"""

        if self.preview:
            print(f'Filesystem: [{fs_name}]')
            print(f'Mount point: [{mount_point}]')
            print(f'Command creating filesystem: [{_cr_fs}]')
            return True

        _code, _output = self.pri_term.getstatusoutput(_cr_fs)

        return self.write_stage(_stage_key, True) if _code == 0 else self.write_stage(_stage_key, False)

    def mount_filesystem(self, fs_name, node_name=None):
        _stage_key = 'mount_fs'
        if self.stage[_stage_key]:
            return True

        fs_name = fs_name if fs_name is not None else 'all'
        node_opts = '-a' if node_name is None else f'-N {node_name}'

        _mount_fs = f"""mmmount {fs_name} {node_opts}"""

        if self.preview:
            print(f'Command mounting filesystem [{_mount_fs}]')
            return True

        _code, _output = self.pri_term.getstatusoutput(_mount_fs)

        return self.write_stage(_stage_key, True) if _code == 0 else self.write_stage(_stage_key, False)

    def all_in_one(self, recovery=False):
        self.recover_stage() if recovery else ''

        # verify configuration and read value for parameters
        self.verify_config(heartbeats_prefix=('99', '199', ))
        self.add_cls_hosts_db()
        self.authorize_cls_ssh_all()
        self.add_cls_ssh_known_hosts()
        self.setup_cls_yum(baseurl='file:///media', name='cdrom', desc='ISO Base System')
        self.inst_cls_required_pkgs()
        self.inst_gpfs_rpm()
        self.build_gpfs()
        self.add_command_path()
        self.create_cls_cfg()
        self.create_cls()
        self.accept_license()
        self.create_nsd_cfg()
        self.create_nsd()
        self.config_tiebreak()
        self.create_filesystem()
        # self.mount_filesystem()


def module_ipcalc(*args):
    _addr_info = ipcalc(*args)
    print('-' * 40)
    print('Network:   ', _addr_info[0])
    print('HostMin:   ', _addr_info[1])
    print('HostMax:   ', _addr_info[2])
    print('Broadcast: ', _addr_info[3])
    print('Hosts:     ', _addr_info[4])
    print('-' * 40)

    exit(0)


def module_multerm(*args):
    _end = ('exit', 'quit', 'q')
    _command_ignore = ('top', 'man', 'vi')

    _multi_term = MultiTerm(*args)
    _origin_multi_term = _multi_term

    def _fetch_names(_multerm: MultiTerm):
        _name_list = _multerm.getoutput('hostname')
        _names_with_index = [f'{_i}.{_name_list[_i]}' for _i in range(len(_name_list))]
        _names = '|'.join(_names_with_index)

        return _names

    _hostnames = _fetch_names(_multi_term)

    def _read_command():
        return input(f'[{_hostnames}] # ')

    while True:
        _hostname_dict = _multi_term.getstatusoutput_thread('hostname')
        _terms_dict = {_term.host: _term for _term in _multi_term.terms}
        _command = _read_command()

        if _command in _end:
            exit(0)

        if _command == '':
            continue

        if _command.startswith(_command_ignore):
            print(f'command [{_command}] not supported.')
            continue

        if _command == 'help':
            print('',
                  'host set <hostname | address> [hostname | address] ...',
                  'host del host1 [host2] [host3] ...',
                  'host add host1 [host2] [host3] ...',
                  'host reset',
                  'index set index1 [index2] [index3] ...',
                  '', sep='\n')
            continue

        if _command.startswith('host set'):
            _names_to_set = _command.split()[2:]
            _terms_to_set = []

            for _host, _hostname in _hostname_dict.items():
                if _host in _names_to_set or _hostname in _names_to_set:
                    _terms_to_set.append(_terms_dict[_host])

            _multi_term.terms = _terms_to_set

        if _command.startswith('host del'):
            pass

        if _command.startswith('host add'):
            pass

        if _command.startswith('host reset'):
            _multi_term = _origin_multi_term
            _hostnames = _fetch_names(_multi_term)

        if _command.startswith('index set'):
            pass

        if _command.startswith('set host'):
            _sub_host = _command.split()[-1]
            _single_term = None

            for _term in _multi_term.terms:
                if _term.host == _sub_host or _term.getoutput('hostname') == _sub_host:
                    _single_term = _term

            while _single_term is not None:
                _sub_command = input(f'[{_sub_host}] # ')

                if _sub_command in _end:
                    break

                print(_single_term.getoutput(_sub_command))

            continue

        _command = _command.replace('ping', 'ping -c3', 1)

        for _host, _code_output in _multi_term.getstatusoutput_thread(_command).items():
            _code, _output = _code_output
            print('-' * 40, f'{_host:^15s} {_code:^3d}', '-' * 40)
            print(_output)


def usage(module):
    if module == 'ipcalc':
        print(MODULE_IPCALC_USAGE)
    elif module == 'ifcfg':
        print(MODULE_IFCFG_USAGE)
    elif module == 'multerm':
        print(MODULE_IFCFG_USAGE)
    elif module == 'gpfs':
        print(MODULE_GPFS_USAGE)
    else:
        print(USAGE)
    exit(0)


_FILENAME_ = os.path.relpath(__file__)

MODULE_IPCALC_USAGE = f"""
Modules:
  ipcalc - calculate subnet for given <IP/Prefix> | [Netmask]
    {_FILENAME_} ipcalc 192.168.0.1/24
    {_FILENAME_} ipcalc 192.168.0.1 24
    {_FILENAME_} ipcalc 192.168.0.1/255.255.255.0
    {_FILENAME_} ipcalc 192.168.0.1 255.255.255.0"""

MODULE_IFCFG_USAGE = f"""
  ifcfg - automatically assign IP address[es] to the first suitable interface
    {_FILENAME_} ifcfg -h 192.168.1.1/2 -a 10.10.10.1/2=28 -g '10.10.10.14' -p 'SHARED_PASS' --default-route --restart-network
    {_FILENAME_} ifcfg 
        <-h HOST[s]> 
        [-u USER[s]] [-p PASSWORD[s]]
        <-a ADDRESS[es]> <-g GATEWAY[s]>
        [-r | --default-route] [-w | --restart-network]
        [-o | --bond]
        [--preview]
    {_FILENAME_} ifcfg 
        <-h HOST[s]> 
        [-u USER[s]] [-p PASSWORD[s]]
        <-i interface> --show"""

MODULE_GPFS_USAGE = f"""
  gpfs - create GPFS cluster, NSD, filesystem
    {_FILENAME_} gpfs 
        <-h HOST[s]> 
        [-u USER[s]] [-p PASSWORD[s]] [-s ADDRESSES] [-b HEARTBEATS]
        <--hb-prefix STR>
        [-n HOSTNAMES] [-x PREFIX] 
        [-f DIRECTORY] [-g MMFS] [-d /dev/sdx] 
        [-P PRIMARY] [-s SECONDARY] 
        [--preview]"""

MODULE_MULTERM_USAGE = f"""
  multerm -- command line interface for fetching output of command from multiple hosts
    {_FILENAME_} multerm
        <-h HOST[s]>
        [-u USER[s]] [-p PASSWORD[s]]"""

USAGE = f"""
Usage:
  {_FILENAME_} [module] [options] [action]
  {MODULE_IPCALC_USAGE}
  {MODULE_IFCFG_USAGE}          
  {MODULE_GPFS_USAGE}
  {MODULE_MULTERM_USAGE}

Options:

  -h HOST[s]            address[es] or domain[s] to login via SSH, 
                        both of '192.168.1.1/2' or '192.168.1.1, 192.168.1.2' are allowed
  -u USER[s]            username[s] of the host[s], the default value is 'root' 'USER1, USER2 ...'
  -p PASSWORD[s]        password[s] of the user[s] 'PASS1 PASS2'
                        one string for all or specify every different PASSWORD for each
                        
  For module ifcfg only:
  -a ADDRESSES          address[es] to be assigned
                        format 1: '192.168.1.1/24, 192.168.1.2/24'
                        format 2: '192.168.1.1/2=24'
  -g GATEWAY[s]         gateway[s] for the address[es] to be assigned, such as '192.168.1.1, 192.168.2.1'
  -t, --default-route   set the GATEWAY specified default 
  -r, --restart-network restart service 'network' via command 'systemctl restart network' 
  -i INTERFACE          name of network interface card
  -o, --bond            create bond configuration if more than 2 NICs suitable for the address

  For module gpfs only:
  -s ADDRESSES          service IP addresses '192.168.1.1/2, 192.168.2.1/2'
                        prefix of address such as '192.168' is acceptable for verifying network configuration
                        both of prefix and full address are used to identified host, assigning IP with '-a' option
  -b HEARTBEATS         heartbeats IP addresses '192.168.1.1/2, 192.168.2.1/2'
                        prefix of address such as '192.168' is acceptable for verifying network configuration
                        both of prefix and full address are used to identified host, assigning IP with '-a' option
  --hb-prefix STR       prefix of heartbeats IP addresses for all hosts in the cluster
  
  -n [DC:]HOST[/HOST]   hostnames 'DATACENTER1:host1/host2, DATACENTER2:host3/host4'
                        for double checking host configuration, never try to set hostname here
  -x NODENAME_PREFIX    nodename prefix, append to the beginning of the OS hostname 'prefix-'
                        this option overwrite the global parameter defined at the beginning 
                        
  -m MOUNT_POINT        GPFS filesystem mount point
  -f FS_NAME            the name of GPFS filesystem
  -d DISK               the name of hard driver used for create NSD

  -P NODENAME           the primary node of the GPFS cluster
  -S NODENAME           the secondary node of the cluster
  -Q NODENAME           the 3-party node of the cluster, quorum only, never supply NSD service

Actions:
  --show                display NICs configuration
  --preview             preview generated configuration for GPFS installation
  --help                print help messages and exit
"""


def read_args():
    global PREVIEW

    ip_user_pass = None

    hosts = passwords = addresses = []
    passwords = ['']
    users = ['root']
    gateways = ''
    default_route = False
    restart_network = False
    bonding = False
    interface = ''
    show = False

    service_ips = heartbeats_ips = hostnames = []
    node_prefix = NODE_PREFIX
    hb_prefix = None

    mount_point = fs_name = disk = None
    pri_node = sec_node = q_node = None

    HELP = False

    try:
        module = sys.argv[1]
        options = sys.argv[2:]

        # option has a value h:
        # long option has value 'long-args='
        opts, args = getopt.getopt(options,
                                   'h:u:p:a:g:s:b:n:x:f:m:d:P:S:Q:rwi:o',
                                   ['preview', 'help', 'default-route',
                                    'restart-network', 'show', 'bond',
                                    'hb-prefix'])

        for _opt, _arg in opts:
            _arg_list = [_a.strip() for _a in _arg.split(',')]
            if _opt == '-h':
                hosts = normalize_addr(*_arg_list)
            elif _opt == '-u':
                users = _arg_list
            elif _opt == '-p':
                passwords = _arg.split()
            elif _opt == '-a':
                addresses = normalize_addr(*_arg_list)
            elif _opt == '-g':
                gateways = _arg
            elif _opt in ['-t', '--default-route']:
                default_route = True
            elif _opt in ['-r', '--restart-network']:
                restart_network = True
            elif _opt in ['-o', '--bond']:
                bonding = True
            elif _opt == '-i':
                interface = f'dev {_arg}'
            elif _opt == '--show':
                show = True
            elif _opt == '-s':
                service_ips = normalize_addr(*_arg_list)
            elif _opt == '-b':
                heartbeats_ips = normalize_addr(*_arg_list)
            elif _opt == '--hb-prefix':
                hb_prefix = _arg
            elif _opt == '-n':
                hostnames = _arg
            elif _opt == '-x':
                node_prefix = _arg
            elif _opt == '-m':
                mount_point = _arg
            elif _opt == '-f':
                fs_name = _arg
            elif _opt == '-d':
                disk = _arg
            elif _opt == '-P':
                pri_node = _arg
            elif _opt == '-S':
                sec_node = _arg
            elif _opt == '-Q':
                q_node = _arg
            elif _opt == '--preview':
                PREVIEW = True
            elif _opt == '--help':
                HELP = True

        if module in ['-h', '--help', 'help', 'h']:
            print(USAGE)

        usage(module=module) if HELP else None

        if module == 'ipcalc':
            module_ipcalc(sys.argv[2])

        try:
            ip_user_pass = tuple(
                [(hosts[_i], users[_i] if len(users) > 1 else users[0],
                  passwords[_i] if len(passwords) > 1 else passwords[0])
                 for _i in range(len(hosts))
                 ]
            )  # todo add support for specifying SSH port
        except IndexError:
            print(USAGE)
            exit(1)

        if module == 'multerm':
            module_multerm(ip_user_pass)

        if module == 'ifcfg':
            # assert len(hosts) != 0
            # assert len(addresses) != 0
            # assert gateways is not None
            # assert len(hosts) == len(addresses)

            _multi_term = MultiTerm(ip_user_pass)
            _hostnames = _multi_term.getoutput_thread('hostname')

            if show:
                for _host, _info in _multi_term.getoutput_thread(f'ip addr show {interface}').items():
                    print('-' * 40, f'{_host:^15s}', '-' * 40)
                    print(_info)
                exit(0)

            print('\nAs option "--preview" is set, nothing will be changed.\n') if PREVIEW else ''
            # _result = _multi_term.assign_ip_to_nic_thread(*addresses,
            #                                               gateways=gateways,
            #                                               default_route=default_route,
            #                                               restart_network=restart_network,
            #                                               preview=PREVIEW)

            _result = _multi_term.assign_ip(*addresses,
                                            gateways=gateways,
                                            default_route=default_route,
                                            restart_network=restart_network,
                                            preview=PREVIEW,
                                            bonding=bonding,
                                            backup=True)

            for _host, _ip_after_nic_ip_before in _result.items():
                _ip_after, _nic, _ip_before = _ip_after_nic_ip_before
                print(f'{_host}/{_hostnames[_host]}: '
                      f'IP to be assign: [{_ip_after:<16s}] '
                      f'suitable NIC: [{_nic:<8s}] '
                      f'current IP: [{_ip_before:<16s}]')

    except IndexError:
        print(USAGE)

    except TypeError as _e:
        print(USAGE)
        raise _e

    except getopt.GetoptError as _e:
        print(_e)
        exit(1)


if __name__ == '__main__':
    read_args()

