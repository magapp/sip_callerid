SIP caller id
=============
This is a simple program that register itself to a SIP server. On incoming calls an URL will be called with the incoming caller id as argument.

Tested to register with Asterisk and wx3 pbx.

Installation
============
Most of the time it is good to use a virtualenv. Type something like this:

	git clone https://github.com/magapp/sip_callerid.git
	virtualenv env
	env/bin/pip install twisted requests
	env/bin/python sip_callerid.py --server asterisk.domain.com --number 0812345678 --authname 0812345678 --password secret --url 'www.host.com/&callerid=CALLERID'

sip_callerid will now register itself to asterisk.domain.com and call www.host.com on incoming calls.


Usage
=====
There are some arguments you can use. Type --help for more information.

You can for example trigg a Jenkins job that do some caller id lookup and other nice stuff if you like. Example:

	... --url 'https://jenkins.domain.com/buildByToken/buildWithParameters/?job=callerid&token=abc&cause=sip_callerid&FROM_NUMBER=CALLERID'

Bugs
====
Note that sometimes the port is not released correct on exit. I don't know exaclty why. If that happens, just run a tool like "iptstate" and remove all sockets in TIME_WAIT on port 5060.

