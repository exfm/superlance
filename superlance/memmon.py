#!/usr/bin/env python -u
##############################################################################
#
# Copyright (c) 2007 Agendaless Consulting and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the BSD-like license at
# http://www.repoze.org/LICENSE.txt.  A copy of the license should accompany
# this distribution.  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL
# EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND
# FITNESS FOR A PARTICULAR PURPOSE
#
##############################################################################

# A event listener meant to be subscribed to TICK_60 (or TICK_5)
# events, which restarts any processes that are children of
# supervisord that consume "too much" memory.  Performs horrendous
# screenscrapes of ps output.  Works on Linux and OS X (Tiger/Leopard)
# as far as I know.

# A supervisor config snippet that tells supervisor to use this script
# as a listener is below.
#
# [eventlistener:memmon]
# command=python memmon.py [options]
# events=TICK_60

doc = """\
memmon.py [-p processname=byte_size]  [-g groupname=byte_size] 
          [-a byte_size] [-s sendmail] [-m email_address]

Options:

-p -- specify a process_name=byte_size pair.  Restart the supervisor
      process named 'process_name' when it uses more than byte_size
      RSS.  If this process is in a group, it can be specified using
      the 'process_name:group_name' syntax.
      
-g -- specify a group_name=byte_size pair.  Restart any process in this group
      when it uses more than byte_size RSS.
      
-a -- specify a global byte_size.  Restart any child of the supervisord
      under which this runs if it uses more than byte_size RSS.

-s -- the sendmail command to use to send email
      (e.g. "/usr/sbin/sendmail -t -i").  Must be a command which accepts
      header and message data on stdin and sends mail.
      Default is "/usr/sbin/sendmail -t -i".

-m -- specify an email address.  The script will send mail to this
      address when any process is restarted.  If no email address is
      specified, email will not be sent.

-k -- amazon cloudwatch access key

-c -- amazon cloudwatch secret key


The -p and -g options may be specified more than once, allowing for
specification of multiple groups and processes.

Any byte_size can be specified as a plain integer (10000) or a
suffix-multiplied integer (e.g. 1GB).  Valid suffixes are 'KB', 'MB'
and 'GB'.

A sample invocation:

memmon.py -p program1=200MB -p theprog:thegroup=100MB -g thegroup=100MB -a 1GB -s "/usr/sbin/sendmail -t -i" -m chrism@plope.com
"""

import os
import sys
import time
import xmlrpclib
import boto
import socket
from datetime import datetime
import psutil

import logging
logging.basicConfig(level=logging.DEBUG)

hdlr = logging.FileHandler('/home/lucas/exfm/superlance/memmon.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)

log = logging.getLogger(__name__)
log.addHandler(hdlr) 


from supervisor import childutils
from supervisor.datatypes import byte_size

def usage():
    print doc
    sys.exit(255)

def shell(cmd):
    return os.popen(cmd).read()

class Memmon:
    def __init__(self, programs, groups, any, sendmail, email, rpc, aws_access_key, aws_secret_key):
        self.programs = programs
        self.groups = groups
        self.any = any
        self.sendmail = sendmail
        self.email = email
        self.rpc = rpc
        self.stdin = sys.stdin
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        self.pscommand = 'ps -orss= -p %s'
        self.mailed = False # for unit tests
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self._hostname = socket.gethostname()

        self.cloudwatch = None
        if self.aws_access_key and self.aws_secret_key:
            self.cloudwatch = boto.connect_cloudwatch(self.aws_access_key, self.aws_secret_key)


    
    def _log_usage(self, name, memory, cpu_percent):
        if self.cloudwatch:
            self.cloudwatch.put_metric_data('App', "Memory Usage: %s" % name, value=memory, 
                timestamp=datetime.utcnow(), unit='Kilobytes', 
                dimensions={'Host': self._hostname})
            
            self.cloudwatch.put_metric_data('App', "CPU Usage: %s" % name, value=cpu_percent, 
                timestamp=datetime.utcnow(), unit='Percent', 
                dimensions={'Host': self._hostname})
    
    def _log_restart(self, name):
        if self.cloudwatch:
            self.cloudwatch.put_metric_data('App', "Restart %s" % name, 
                value=1, 
                timestamp=datetime.utcnow(), unit='Count', 
                dimensions={'Host': self._hostname})
    
    def _log_machine_state(self):
        if self.cloudwatch:
            usage = psutil.phymem_usage()
            self.cloudwatch.put_metric_data('App', "Memory Usage", 
                value=usage.percent, 
                timestamp=datetime.utcnow(), unit='Percent', 
                dimensions={'Host': self._hostname})

    def runforever(self, test=False):
        while 1:
            # we explicitly use self.stdin, self.stdout, and self.stderr
            # instead of sys.* so we can unit test this code
            headers, payload = childutils.listener.wait(self.stdin, self.stdout)

            if not headers['eventname'].startswith('TICK'):
                # do nothing with non-TICK events
                childutils.listener.ok(self.stdout)
                log.debug('Got tick event')
                if test:
                    break
                continue

            
            status = []
            if self.programs:
                status.append(
                    'Checking programs %s' % ', '.join(
                    [ '%s=%s' % x for x in self.programs.items() ] )
                    )

            if self.groups:
                status.append(
                    'Checking groups %s' % ', '.join(
                    [ '%s=%s' % x for x in self.groups.items() ] )
                    )
            if self.any is not None:
                status.append('Checking any=%s' % self.any)

            self.stderr.write('\n'.join(status) + '\n')

            infos = self.rpc.supervisor.getAllProcessInfo()

            for info in infos:
                pid = info['pid']
                name = info['name']
                group = info['group']
                pname = '%s:%s' % (group, name)

                if not pid:
                    # ps throws an error in this case (for processes
                    # in standby mode, non-auto-started).
                    continue

                p = psutil.Process(pid)
                rss = int(p.get_memory_info().rss)
                percent_cpu = p.get_cpu_percent()

                for n in name, pname:
                    if n in self.programs:
                        self.stderr.write('RSS of %s is %s\n' % (pname, rss))
                        self._log_usage(pname, rss, percent_cpu)

                        if  rss > self.programs[name]:
                            self.restart(pname, rss)
                            self._log_restart(pname)
                            continue

                if group in self.groups:
                    self.stderr.write('RSS of %s is %s\n' % (pname, rss))
                    if rss > self.groups[group]:
                        self.restart(pname, rss)
                        self._log_restart(pname)
                        continue

                if self.any is not None:
                    self.stderr.write('RSS of %s is %s\n' % (pname, rss))

                    if rss > self.any:
                        self.restart(pname, rss)
                        self._log_restart(pname)
                        continue
            
            self._log_machine_state()

            self.stderr.flush()
            childutils.listener.ok(self.stdout)
            if test:
                break

    def restart(self, name, rss):
        self.stderr.write('Restarting %s\n' % name)

        try:
            self.rpc.supervisor.stopProcess(name)
        except xmlrpclib.Fault, what:
            msg = ('Failed to stop process %s (RSS %s), exiting: %s' %
                   (name, rss, what))
            self.stderr.write(str(msg))
            if self.email:
                subject = 'memmon: failed to stop process %s, exiting' % name
                self.mail(self.email, subject, msg)
            raise

        try:
            self.rpc.supervisor.startProcess(name)
        except xmlrpclib.Fault, what:
            msg = ('Failed to start process %s after stopping it, '
                   'exiting: %s' % (name, what))
            self.stderr.write(str(msg))
            if self.email:
                subject = 'memmon: failed to start process %s, exiting' % name
                self.mail(self.email, subject, msg)
            raise

        if self.email:
            now = time.asctime()
            msg = (
                'memmon.py restarted the process named %s at %s because '
                'it was consuming too much memory (%s bytes RSS)' % (
                name, now, rss)
                )
            subject = 'memmon: process %s restarted' % name
            self.mail(self.email, subject, msg)

    def mail(self, email, subject, msg):
        body =  'To: %s\n' % self.email
        body += 'Subject: %s\n' % subject
        body += '\n'
        body += msg
        m = os.popen(self.sendmail, 'w')
        m.write(body)
        m.close()
        self.mailed = body
        
def parse_namesize(option, value):
    try:
        name, size = value.split('=')
    except ValueError:
        print 'Unparseable value %r for %r' % (value, option)
        usage()
    size = parse_size(option, size)
    return name, size

def parse_size(option, value):
    try:
        size = byte_size(value)
    except:
        print 'Unparseable byte_size in %r for %r' % (value, option)
        usage()
        
    return size

def main():
    import getopt
    short_args="hp:g:a:s:m:k:c:"
    long_args=[
        "help",
        "program=",
        "group=",
        "any=",
        "sendmail_program=",
        "email=",
        "aws_access_key=",
        "aws_secret_key=",
        "env_prefix="
        ]
    arguments = sys.argv[1:]
    if not arguments:
        usage()
    try:
        opts, args=getopt.getopt(arguments, short_args, long_args)
    except:
        print __doc__
        sys.exit(2)

    programs = {}
    groups = {}
    any = None
    sendmail = '/usr/sbin/sendmail -t -i'
    email = None
    aws_access_key = None
    aws_secret_key = None

    for option, value in opts:

        if option in ('-h', '--help'):
            usage()

        if option in ('-p', '--program'):
            name, size = parse_namesize(option, value)
            programs[name] = size

        if option in ('-g', '--group'):
            name, size = parse_namesize(option, value)
            groups[name] = size

        if option in ('-a', '--any'):
            size = parse_size(option, value)
            any = size

        if option in ('-s', '--sendmail_program'):
            sendmail = value

        if option in ('-m', '--email'):
            email = value
        
        if option in ('-k', '--aws_access_key'):
            aws_access_key = value
        
        if option in ('-c', '--aws_secret_key'):
            aws_secret_key = value
    
    log.debug('Starting memmon')
    log.debug('aws_access_key:%s' % (aws_access_key))
    log.debug('aws_secret_key:%s' % (aws_secret_key))
    
    rpc = childutils.getRPCInterface(os.environ)
    memmon = Memmon(programs, groups, any, sendmail, email, rpc, aws_access_key, aws_secret_key)
    memmon.runforever()

if __name__ == '__main__':
    main()
    
    
    
