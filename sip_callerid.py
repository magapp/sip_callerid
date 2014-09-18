import argparse, sys, os, re, string, random, hashlib, socket
import logging, logging.handlers
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.names import client
from twisted.internet.task import LoopingCall

app_name="sip_callerid"
app_version="1.0"

def main():
    parser = argparse.ArgumentParser(prog=app_name, description="Magnus 2014-08-18")
    parser.add_argument('--server', dest='server', action='store', required=True, help='SIP server to connect to')
    parser.add_argument('--port', dest='port', action='store', type=int, required=False, default=5060, help='SIP server port to use')
    parser.add_argument('--number', dest='number', action='store', required=True, help='Number to authenticate with')
    parser.add_argument('--authname', dest='authname', action='store', required=True, help='Name to authenticate with')
    parser.add_argument('--password', dest='password', action='store', required=True, help='Password to use')
    parser.add_argument('--realm', dest='realm', action='store', required=False, help='Realm')
    parser.add_argument('--execute', dest='execute', action='store', required=False, help='Script to execute on incoming call. CALLERID will be replace with callerid.')
    parser.add_argument('-V', '--version', action='version', version="%(prog)s version "+app_version)

    args = parser.parse_args()

    hostname, alias, ips = socket.gethostbyaddr(args.server)
    args.server = ips.pop()

    logger = logging.getLogger(app_name)
    logger.setLevel(logging.DEBUG)
    handler = logging.handlers.SysLogHandler(address = '/dev/log')
    logger.addHandler(handler)

    sip = SipClient(logger, args.server, args.port, args.number, args.authname, args.password, args.realm, args.execute)
    reactor.listenUDP(0, sip)

    def register_task():
        logger.info("Sending registration...")
        sip.sendsip(sip.msg_register)

    register_timer = LoopingCall(register_task)
    register_timer.start(180)

    print "Connecting to SIP server. See syslog for more information."

    reactor.run()

    sys.exit(0)


class SipClient(DatagramProtocol):

    msg_register = """REGISTER sip:$server SIP/2.0
CSeq: $seq REGISTER
Via: SIP/2.0/UDP $myip:$port; branch=$branch;rport
User-Agent: """+app_name+""" / """+app_version+""" 
From: <sip:$number@$server>;tag=$tag
Call-ID: $callid
To: <sip:$number@$server>
Contact: <sip:$number@$myip>;q=1
Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING
Expires: 3600
Content-Length: 0
Max-Forwards: 70
"""

    msg_register_auth = """REGISTER sip:$server SIP/2.0
CSeq: $seq REGISTER
Via: SIP/2.0/UDP $myip:$port; branch=$branch;rport
User-Agent: """+app_name+""" / """+app_version+""" 
Authorization: Digest username="$authname", realm="$realm", nonce="$nonce", uri="sip:$server", algorithm=MD5, response="$response"
From: <sip:$number@$server>;tag=$tag
Call-ID: $callid
To: <sip:$number@$server>
Contact: <sip:$number@$myip>;q=1
Expires: 3600
Content-Length: 0
Max-Forwards: 70
"""
    msg_options = """SIP/2.0 200 OK
Via: SIP/2.0/UDP $server:$port;branch=$branch;rport
From: "$realm" <sip:$realm@$server>;tag=$remote_tag
To: <sip:$number@$myip:5060>;tag=$tag
Call-ID: $callid
CSeq: $seq OPTIONS
Supported: replaces
User-Agent: """+app_name+""" / """+app_version+""" 
Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, REFER, SUBSCRIBE, NOTIFY
Content-Length: 0
"""

    def __init__(self, logger, server, port, number, authname, password, realm=None, execute=None):
        self.logger = logger
        self.realm = realm
        self.execute = execute
        self.server = server
        self.port = port
        self.number = number
        self.authname = authname
        self.password = password
        self.tag = ''.join([random.choice(string.digits) for i in range(10)])
        self.seq = 1
	self.response = ""
        self.nonce = ""
        self.callerid_branch = ""
        self.myip="0.0.0.0"
        self.registration_counter = 0
 
    def datagramReceived(self, data, (host, port)):
        if host != self.server: 
            return
        lines = data.split("\n")
        self.logger.debug(lines[0])
        if lines[0][0:7] == "SIP/2.0":
            status = lines[0][8:11]
            if status == "401":
                if self.registration_counter > 5:
                    self.logger.error("Could not register. Exit.")
                    sys.exit(1)
                self.registration_counter += 1 
                m = re.search(".*nonce=\"(\w+)\".*", data)
                if m: self.nonce = m.groups()[0]
                if not self.realm:
                    m = re.search(".*realm=\"([\w\d\.]+)\".*", data)
                    if m: self.realm = m.groups()[0]
                ha1 = hashlib.md5(b""+self.authname+":"+self.realm+":"+self.password).hexdigest()
                ha2 = hashlib.md5(b"REGISTER:sip:"+self.server).hexdigest()
                self.response = hashlib.md5(b""+ha1+":"+self.nonce+":"+ha2).hexdigest()
                self.sendsip(self.msg_register_auth)
        if lines[0][0:7] == "OPTIONS":
            self.registration_counter = 0
            m = re.search(".*tag=(\w+).*", data)
            if m: remote_tag = m.groups()[0]
            m = re.search(".*branch=(\w+).*", data)
            if m: branch = m.groups()[0]
            m = re.search(".*Call-ID: ([\w@\.\:]+).*", data)
            if m: callid = m.groups()[0]
            m = re.search(".*CSeq: ([\d]+).*", data)
            if m: self.seq = int(m.groups()[0])
            m = re.search(".*CSeq: ([\d]+).*", data)
            self.sendsip(self.msg_options, branch=branch, callid=callid, remote_tag=remote_tag)

        if lines[0][0:6] == "INVITE":
            callerid = "unknown"
            m = re.search('.*From: \"(\w+)\".*', data)
            if m: callerid = m.groups()[0]
            m = re.search(".*branch=(\w+).*", data)
            if m: 
                if self.callerid_branch and self.callerid_branch == m.groups()[0]:
                    # already got this call
                    return
                else:
                    self.callerid_branch = m.groups()[0]
            self.logger.info("Incoming call from '%s'" % callerid)
            if self.execute:
                self.logger.debug("Executing %s" % self.execute.replace("CALLERID", callerid))
                os.system(self.execute.replace("CALLERID", callerid))

        
    def sendsip(self, msg, branch=None, callid=None, remote_tag=None):
        if self.transport.getHost().host == "0.0.0.0":
            self.transport.connect(self.server, self.port)
            self.myip = self.transport.getHost().host
            
        if not callid:
            callid = "1234"+self.tag
        if not branch:
            branch = "z9hG4bK7894"+''.join([random.choice(string.letters + string.digits) for i in range(32)])
        if not remote_tag:
            remote_tag = ''.join([random.choice(string.digits) for i in range(10)])

        self.transport.write(string.Template(msg).substitute({"authname": self.authname,
                                                              "branch": branch,
                                                              "tag": self.tag,
                                                              "callid": callid,
                                                              "remote_tag": remote_tag,
                                                              "myip": self.myip,
                                                              "number": self.number,
                                                              "realm": self.realm,
                                                              "server": self.server,
                                                              "seq": self.seq,
                                                              "port": self.port,
                                                              "response": self.response,
                                                              "nonce": self.nonce}))
        return


if __name__ == "__main__":
    main()
