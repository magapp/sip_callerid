SIP caller id
=============
This is a simple program that register itself to a SIP server. On incoming calls a script will be executed with the incoming caller id as argument.

Tested to register with Asterisk and wx3 pbx.

Installation
============
Most of the time it is good to use a virtualenv. Type something like this:

	git clone https://github.com/magapp/sip_callerid.git
	virtualenv env
	env/bin/pip install twisted
	env/bin/python sip_callerid.py --server asterisk.domain.com --number 0812345678 --authname 0812345678 --password secret --execute 'echo CALLERID is calling'

sip_callerid will now register itself to asterisk.domain.com and for example print the text below on incoming phone calls:

	0887654321 is calling


Usage
=====
There are some arguments you can use. Type --help for more information.

You can for example trigg a Jenkins job that do some caller id lookup and other nice stuff if you like. Example:

	... --execute 'curl "https://jenkins.domain.com/buildByToken/buildWithParameters/?job=callerid&token=abc&cause=sip_callerid&FROM_NUMBER=CALLERID"'

Note that sometimes the port is not released correct on exit. I don't know exaclty why. If that happens, just run a tool like "iptstate" and remove all sockets in TIME_WAIT on port 5060.

Todo
===
Add arguements so the program can become a daemon. You can always execute in background by appending &.

