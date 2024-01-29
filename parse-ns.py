#!/usr/bin/python3

################################################################################
#
# parse-ns.py
# 
# v1.0 15/09/2016 - Josep Fontana - Initial version
#
# Parse running/saved configuration of Citrix Netscaler in the provided files
# and output 2 csv files:
# one for load balancing with the backend IP(s) and their correspondence with frontend IP
# a second one for global server load balance with the domains and their corresponding IP(s)
#


"""
 Handy definitions from:
  http://support.citrix.com/article/CTX120318
  https://www.syxin.com/2014/03/netscaler-nsipsnipmipvip/

 NIP: Netscaler IP (management interface, also NSIP)
 VIP: Virtual IP (used for client-side connections)
 SNIP: SubNet IP (used for server-side connections)
 MIP: Mapped IP (default SNIP)


                          +-----------+            +-----------+
  +----------+            |           |            |           |
  |          |        VIP |           |SNIP      IP|   Front   |
  |  Client  +<---------->+ Netscaler +<---------->+           |
  |          |            |           |            | Server(s) |
  +----------+            |           |            |           |
                          +-----------+            +-----------+


 This is the path we will take from the IP to the VIP
  1. ip->name (add server)
     add server [serverName] [IP] -comment ["some code or explanation"]
  2. name->serviceGroup (bind serviceGroup)
     bind serviceGroup [serviceGroup] [serverName] [port] -CustomServerID ["some code"]

  OR # because not everything is in a group

  2. name->service (add service)
     add service [serviceName] [serverName] [serviceType] [port] [other parameters]

  3. serviceGroup->vserver (bind lb vserver)
     bind lb vserver [vserver] [serviceGroup]
  4. vserver->vip (add lb vserver)
     add lb vserver [vserver] [serviceType] [VIP] [port] -comment ["some code"] [other parameters]


And then we have GSLB (Global Server Load Balancing). A lot of information can be found on https://support.citrix.com/servlet/KbServlet/download/22506-102-671576/gslb-primer_FINAL_1019.pdf
Here we go from the server to the domainName that the Netscaler will solve:
  1. ip->name (add server) same as above
     add server [serverName] [IP] -comment ["some code or explanation"]
  2. name->service (add gslb service)
     add gslb service [gslbservice] [serverName] [serviceType] [port] [other parameters] -comment ["some code or explanation"]
  3. service->vserver (bind gslb vserver)
     bind gslb vserver [vserver] -serviceName [gslbservice]
  4. vserver->domainName
     bind gslb vserver [vserver] -domainName [domainName] [other parameters]
"""


################################################################################
# init and argument parsing
################################################################################


#####
# imports
import pprint
import shlex

import sys
import os
import csv
import datetime


#####
# dictionaries

# common
servers=dict()		# [srvName, srvComment]=servers[ip]
srvs=dict()	        # [serviceGroup/gslbService, 'LB'/serviceType, port, srvComment]=srvs[srvName]
vServers=dict()		# vServer=vServers[serviceGroup/gslbService]
# lb
VIPs=dict()		# [VIP, serviceType, port, VIPcomment]=VIPs[vServer]
# gslb
domains=dict()         # domain=domains[vserver]
unParseable=dict() # Undefined lines
sslFiles=dict() # SSL File descriptions
sslLinks=dict() # SSL Links
sslBinds=dict() # SSL Binds


#####
# argument parsing

confFiles=sys.argv
del confFiles[0]

if (confFiles==[]):
    # no parameter where given
    print("\n *** ERROR: no configuration files were provided in the command line\n")
    print("Please use the following syntax:")
    print(" parse-ns.py conf1.txt conf2.txt ...\n")
    exit(1)


################################################################################
# parsing functions
################################################################################

def ssl_service_resolve_links(sslLink):
    results = []
    finalresults = []
    if (sslLink not in sslLinks):
        # This is end of recursion
        return results

    for item in sslLinks[sslLink]:
        results.append(item)
        tempresults = []
        tempresults = ssl_service_resolve_links(item)
        results = results + tempresults
    return results


"""
readline(line)
 read line and parse accordingly
"""
def readline(line):
    # the first one is for lb and gslb
    if (line.lower().startswith('add server')):
        server_parse(line)
    # the three next are for lb
    elif (line.lower().startswith('bind servicegroup')): 
        bind_servicegroup_parse(line)

    elif (line.lower().startswith('bind lb vserver')):
        bind_lb_parse(line)

    elif (line.lower().startswith('add lb vserver')):
        lb_vserver_parse(line)

    elif (line.lower().startswith('add service')):
        lb_service_parse(line)

    elif (line.lower().startswith('add lb monitor')):
        monitor_parse(line)

    elif (line.lower().startswith('add ssl certkey')):
        # This creates a key with a name, linking to a file
        ssl_service_certKey_parse(line)
    elif (line.lower().startswith('link ssl certkey')):
        ssl_service_link_parse(line)
    elif (line.lower().startswith('bind ssl vserver')):
        ssl_service_bind_parse(line)
    # here we start with gslb-specific stuff
    elif (line.lower().startswith('add gslb service')):
        gslb_parse(line)
    elif (line.lower().startswith('bind gslb vserver')):
        gslb_vserver_parse(line)
    else:
        undefined_parse(line)

"""
Save lines that couldn't be identified
"""
def undefined_parse(l):
    unParseable[l]=l

"""
add lb monitor prodnet.dom_dns DNS -query prodnet.dom -queryType Address -LRTM DISABLED -IPAddress 192.168.252.21 192.168.252.20
add lb monitor http_Onewebsite_Stage_Web HTTP -respCode 80 200 403 -httpRequest "HEAD /css/logon/style.css" -customHeaders "host:cs.stage.companydomain.com\r\n" -LRTM DISABLED
add lb monitor http_Onewebsite_Web HTTP -respCode 80 200 403 -httpRequest "HEAD /css/logon/style.css" -customHeaders "host:cs.companydomain.com\r\n" -LRTM DISABLED -downTime 100 MSEC
add lb monitor http_Umbraco HTTP -respCode 200 -httpRequest "GET /umbraco/ping.aspx" -customHeaders "hostname:www.companydomain.com\r\n" -LRTM DISABLED -sslProfile ns_default_ssl_profile_backend
add lb monitor http_testwebserver2 HTTP -respCode 80 200 403 -httpRequest "GET /iisstart.htm" -LRTM DISABLED -downTime 100 MSEC
add lb monitor http_CSGWEB14 HTTP -respCode 200 -httpRequest "HEAD /live/fidportallive/login.aspx" -customHeaders "host:fid.companydomain.com\r\n" -LRTM DISABLED
add lb monitor <monitorName> <monitorType> [<interval>]

"""
def monitor_parse(l):
    monitorName=shlex.split(l)[3]
    monitorType=shlex.split(l)[4]
    ##if (monitorType != "TCP" && monitorType != "HTTP"):
        # We don't understand this monitor yet, go to unparseable
      #  undefined_parse(l)



"""
link ssl certKey cs.companydomain.com_CKP GeoTrust_InterCA
"""
def ssl_service_link_parse(l):
    certName=shlex.split(l)[3]
    linkName=shlex.split(l)[4]
    if certName not in sslLinks:
        sslLinks[certName] = []

    sslLinks[certName].append(linkName)


"""
bind ssl vserver vserverName -certkeyName certName -SNICert
"""
def ssl_service_bind_parse(l):
    vServer = shlex.split(l)[3]
    certNamePart = l.partition('-certkeyName ')[2].strip('\n')
    if (certNamePart == ""):
        undefined_parse(l)
        return
    certName = shlex.split(certNamePart)[0]
    # We do this because there might be more than one linke with the same vServer so the certificates need to be an array
    if vServer not in sslBinds:
        sslBinds[vServer] = []
    sslBinds[vServer].append(certName)

"""
add ssl certKey (-cert [-password]) [-key | -fipsKey | -hsmKey ] [-inform ] [-expiryMonitor ( ENABLED | DISABLED ) [-notificationPeriod ]] [-bundle ( YES | NO )]
add ssl certKey "DigiCert RSA CA" -cert "DigiCert TLS RSA SHA256 2020 CA1.pem" -expiryMonitor DISABLED -CertKeyDigest 
add ssl certKey <certName> -cert <fileName>
"""
def ssl_service_certKey_parse(l):
    certName=shlex.split(l)[3]
    certFilePart=l.partition('-cert ')[2].strip('\n')
    # It might happen that the text is "-cert file.cert -key key.pem" so we need to strip the key or anyhting beyond
    certFile=certFilePart.partition(' -')[0].strip('"\n')

    keyFilePart=l.partition('-key ')[2].strip('\n')
    keyFile=keyFilePart.partition(' -')[0].strip('"\n')

    sslFiles[certName]=[certFile, keyFile]
    


"""
add server [serverName] [IP] -comment ["some code or explanation"]
"""
def server_parse(l):
    srvName=shlex.split(l)[2]
    IP=shlex.split(l)[3]
    srvComment=l.partition('-comment ')[2].strip('"\n')
    
    servers[IP]=[srvName, srvComment]
    

"""
bind serviceGroup [serviceGroup] [serverName] [port] -CustomServerID ["some code"]
these lines are sometimes followed by:
    bind serviceGroup [serviceGroup] -monitorName [monitor]
which may delete the data we want to get from the dictionary!
"""
def bind_servicegroup_parse(l):
    if '-monitorName' in l:
        # nothing to do here
        return
    
    serviceGroup=shlex.split(l)[2]
    srvName=shlex.split(l)[3]
    port=shlex.split(l)[4]
    srvComment=l.partition('-CustomServerID ')[2].strip('"\n')

    srvs[srvName]=[serviceGroup, 'LB', port, srvComment, ""]

"""
add service [serviceName] [serverName] [serviceType] [port] [other parameters] -comment ["some code or explanation"]
"""
def lb_service_parse(l):
    serviceGroup=shlex.split(l)[2]
    srvName=shlex.split(l)[3]
    serviceType=shlex.split(l)[4]
    port=shlex.split(l)[5]
    srvComment=l.partition('-comment ')[2].strip('"\n')
    # First split into max of 6 arguments which will include comments and then strip the comment
    srvOther=l.split(" ", 6)[6].partition("-comment ")[0].strip('"\n')

    srvs[srvName]=[serviceGroup, serviceType, port, srvComment, srvOther]

"""
bind lb vserver [vserver] [serviceGroup]
"""
def bind_lb_parse(l):
    vServer=shlex.split(l)[3]
    serviceGroup=shlex.split(l)[4]

    vServers[serviceGroup]=vServer

"""
add lb vserver [vserver] [serviceType] [VIP] [port] [-other parameters] -comment ["some code"]
"""
def lb_vserver_parse(l):
    vServer=shlex.split(l)[3]
    serviceType=shlex.split(l)[4]
    VIP=shlex.split(l)[5]
    port=shlex.split(l)[6]
    VIPcomment=l.partition('-comment ')[2].strip('"\n')

    VIPs[vServer]=[VIP, serviceType, port, VIPcomment]

"""
add gslb service [gslbservice] [serverName] [serviceType] [port] [other parameters] -comment ["some code or explanation"]
"""
def gslb_parse(l):
    gslbService=shlex.split(l)[3]
    srvName=shlex.split(l)[4]
    serviceType=shlex.split(l)[5]
    port=shlex.split(l)[6]
    srvComment=l.partition('-comment ')[2].strip('"\n')
    # First split into max of 6 arguments which will include comments and then strip the comment
    srvOther=l.split(" ", 6)[6].partition("-comment ")[0].strip('"\n')

    srvs[srvName]=[gslbService, serviceType, port, srvComment, srvOther]


"""
bind gslb vserver [vserver] -serviceName [gslbservice]
bind gslb vserver [vserver] -domainName [domainName] [other parameters]
"""
def gslb_vserver_parse(l):
    if '-serviceName' in l:
        vServer=shlex.split(l)[3]
        gslbService=shlex.split(l)[5]

        vServers[gslbService]=vServer
    elif '-domainName' in l:
        vserver=shlex.split(l)[3]
        domain=shlex.split(l)[5]

        # if there's already a domain for this vserver just add it
        try:
            domains[vserver]=domains[vserver]+'\n'+domain
        except KeyError:
            domains[vserver]=domain



################################################################################
# information input
################################################################################

# go through each file provided in the command line
for confFile in confFiles:
    print("Reading "+confFile+"...")
    # open file and read it line by line
    with open(confFile,'r') as f:
        for line in f:
            readline(line)


################################################################################
# information output
################################################################################

# create the filenames from the date/time
d=datetime.datetime
# nasty one-liner to get a 'YYY-MM-DD_HH.MM' string
#f_basename=d.now().isoformat('_').partition('.')[0].replace(':','.').rstrip('1234567890').rstrip('.')
# ok, ok, it's better to use strftime!
f_basename=d.now().strftime('%Y-%m-%d_%H.%M')

f_lb=f_basename+'_LB.csv'
f_gslb=f_basename+'_GSLB.csv'
f_unparseable=f_basename+'_UNPARSEABLE.csv'

with open(f_unparseable,'w') as f:
    print("Writing "+f_unparseable+"...")

    # loop through the servers and get those that are LB'ed
    for l in unParseable.keys():
        f.write(unParseable[l])
    f.close()


with open(f_lb,'w') as f:
    print("Writing "+f_lb+"...")
    # create the csv writer
    w=csv.writer(f)

    # write the header row
    w.writerow( ('VIP', 'serviceType', 'frontendPort', 'VIPcomment', 'vServer', 'serviceGroup', 'backendPort', 'CustomServerID', 'srvName', 'srvComment', 'IP', 'sslCertificates', 'other Params') )

    # loop through the servers and get those that are LB'ed
    for IP in servers.keys():
        [srvName, srvComment]=servers[IP]
        try:
            [serviceGroup, notUsed, port, CustomServerID, srvOther]=srvs[srvName]
        except(KeyError):
            continue
        try:
            vServer=vServers[serviceGroup]
        except(KeyError):
            vServer="None"
            continue
        try:
            [VIP, serviceType, VIPport, VIPcomment]=VIPs[vServer]
        except(KeyError):
            VIP=serviceType=VIPport=VIPcomment="None"
        try:
            sslBindDefs = sslBinds[vServer]
            # sslBindDefs is now an array of all the SSL certificates linked to this vServer
            # Next, we need to resolve the links
            sslLinkDefs = []
            sslCertificates = []
            # This means we loop through every sslBindDefs
            for sslBindItem in sslBindDefs:
                # sslBindItem is our first certificate, let's add it
                sslCertificates.append(sslBindItem)
                # But this might have links - we need to find this certificate in the links
                if sslBindItem in sslLinks:
                    tempitems = []
                    tempitems = ssl_service_resolve_links(sslBindItem)
                    sslCertificates = sslCertificates + tempitems

        except(KeyError):
            continue

        sslFileNames = []
        for cert in sslCertificates:
            sslFileNames.append(sslFiles[cert][0])

        w.writerow( (VIP, serviceType, VIPport, VIPcomment, vServer, serviceGroup, port, CustomServerID, srvName, srvComment, IP, ";".join(sslFileNames),srvOther) )


with open(f_gslb,'w') as f:
    print("Writing "+f_gslb+"...")
    # create the csv writer
    w=csv.writer(f)

    # write the header row
    w.writerow( ('domain', 'vServer', 'gslbService', 'serviceType', 'port', 'srvcComment', 'srvComment', 'srvName', 'IP', 'other Params') )

    # loop through the servers and get those that are GSLB'ed
    for IP in servers.keys():
        [srvName, srvComment]=servers[IP]
        try:
            [gslbService, serviceType, port, srvcComment, srvOther]=srvs[srvName]
        except(KeyError):
            continue
        try:
            vServer=vServers[gslbService]
        except(KeyError):
            continue
        try:
            domain=domains[vServer]
        except(KeyError):
            continue

        w.writerow( (domain, vServer, gslbService, serviceType, port, srvcComment, srvComment, srvName, IP, srvOther) )

print("...and done! Enjoy!")

