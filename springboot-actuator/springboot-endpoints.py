#!/usr/bin/env python3
# _*_ coding:utf-8 _*_

import argparse
import re
import requests
from multiprocessing import Pool, Manager
from concurrent.futures import ThreadPoolExecutor
import ipaddress

requests.packages.urllib3.disable_warnings()

headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0",
           "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",}

executor = ThreadPoolExecutor()

# Spring Boot <1.5 default unauthorized access to all endpoints
# Spring Boot> = 1.5 By default, only access to / health and / info endpoints is allowed, but this security is usually disabled by application developers
# In addition, considering the situation of manually closing the default endpoint and opening the non-default endpoint, in summary, the brute force mode is used here with asynchronous concurrency (asynchronous child threads are nested in child processes) to solve.
pathlist=['/autoconfig','/beans','/configprops','/dump','/health','/info','/mappings','/metrics','/trace',]

def getinfo(filepath):
    fr = open(filepath, 'r')
    ips=fr.readlines()
    fr.close()
    return ips

def saveinfo(result):
    if result:
        fw=open('result.txt','a')
        fw.write(result+'\n')
        fw.close()

def sbcheck(ip):
    url= str(ip)
    try:
        r = requests.get(url+ '/404', headers=headers,timeout=10,verify=False)
        if r.status_code==404 or r.status_code==403:
            if 'Whitelabel Error Page' in r.text  or 'There was an unexpected error'in r.text:
                print("It's A Spring Boot Web APP: {}".format(url))
                saveinfo( "It's A Spring Boot Web APP: {}".format(url))
                executor.submit(sb_Actuator,url)
                return 1
    except requests.exceptions.ConnectTimeout:
        return 0.0
    except requests.exceptions.ConnectionError:
        return 0.1


def isSB(ip,q):
    print('>>>>> {}'.format(ip))
    sbcheck (ip)
    q.put(ip)


#Most Actuator only supports GET requests and displays only sensitive configuration data. If Jolokia endpoints are used, XXE or even RCE security issues may arise.
#Just check by checking the Mbeans in / jolokia / list and whether there is the reloadByURL method provided by the logback library.
def Jolokiacheck(url):
    url_tar = url + '/jolokia/list'
    r = requests.get(url_tar, headers=headers, verify=False)
    if r.status_code == 200:
        print ("The target site has enabled unauthorized access to the jolokia endpoint, the path is: {}". format (url_tar))
        saveinfo ("The target site has enabled unauthorized access to the jolokia endpoint, the path is: {}". format (url_tar))
        if 'reloadByURL' in r.text:
            print ("The target site has the jolokia endpoint enabled and there is a reloadByURL method, which can be used for XXE / RCE testing. The path is: {}". format (url_tar))
            saveinfo ("jolokia endpoint is enabled on the target site and the reloadByURL method exists, XXE / RCE test can be performed, the path is: {}". format (url_tar))
        if 'createJNDIRealm' in r.text:
            print ("The target site has opened the jolokia endpoint and there is a createJNDIRealm method, which can be used for JNDI injection RCE testing, the path is: {}". format (url_tar))
            saveinfo ("jolokia endpoint is enabled on the target site and the createJNDIRealm method exists. JNDI injection RCE test can be performed, the path is: {}". format (url_tar))


#Spring Boot env endpoint has environment property coverage and XStream deserialization vulnerability
def Envcheck_1(url):
    url_tar = url + '/env'
    r = requests.get(url_tar, headers=headers, verify=False)
    if r.status_code == 200:
        print ("The target site has enabled unauthorized access to the env endpoint, the path is: {}". format (url_tar))
        saveinfo ("The target site has enabled unauthorized access to the env endpoint, the path is: {}". format (url_tar))
        if 'spring.cloud.bootstrap.location' in r.text:
            print ("The target site has the env endpoint turned on and the spring.cloud.bootstrap.location property is turned on, and the RCE test for environment property coverage can be performed. The path is: {}". format (url_tar))
            saveinfo ("env endpoint is enabled on the target site and the spring.cloud.bootstrap.location property is enabled. You can perform RCE testing for environment property coverage. The path is: {}". format (url_tar))
        if 'eureka.client.serviceUrl.defaultZone' in r.text:
            print ("The target site has the env endpoint enabled and the eureka.client.serviceUrl.defaultZone attribute is enabled. XStream deserialization RCE test can be performed. The path is: {}". format (url_tar))
            saveinfo ("env endpoint is enabled on the target site and the eureka.client.serviceUrl.defaultZone property is enabled, XStream deserialization RCE test can be performed, the path is: {}". format (url_tar))

#Spring Boot 1.x version endpoint is registered under the root URL.
def sb1_Actuator(url):
    key=0
    Envcheck_1(url)
    Jolokiacheck(url)
    for i in pathlist:
        url_tar = url + i
        r = requests.get(url_tar, headers=headers, verify=False)
        if r.status_code==200:
            print ("The target site has enabled unauthorized access to the {} endpoint, the path is: {}". format (i.replace ('/', ''), url_tar))
            saveinfo ("The target site has enabled unauthorized access to the {} endpoint, the path is: {}". format (i.replace ('/', ''), url_tar))
            key=1
    return key

#Spring Boot 2.x version has RCE caused by improper H2 configuration, currently non-regular judgment, test phase
#In addition, I think that only the 1. * version of the environment attribute coverage and XStream deserialization vulnerability exists
#Later confirmed that 2. * also exists, data needs to be sent in json format, I will give a specific exp later
def Envcheck_2(url):
    url_tar = url + '/actuator/env'
    r = requests.get(url_tar, headers=headers, verify=False)
    if r.status_code == 200:
        print ("The target site has enabled unauthorized access to the env endpoint, the path is: {}". format (url_tar))
        saveinfo ("The target site has enabled unauthorized access to the env endpoint, the path is: {}". format (url_tar))
        if 'spring.cloud.bootstrap.location' in r.text:
            print ("The target site has the env endpoint turned on and the spring.cloud.bootstrap.location property is turned on, and the RCE test for environment property coverage can be performed. The path is: {}". format (url_tar))
            saveinfo ("env endpoint is enabled on the target site and the spring.cloud.bootstrap.location property is enabled. You can perform RCE testing for environment property coverage. The path is: {}". format (url_tar))
        if 'eureka.client.serviceUrl.defaultZone' in r.text:
            print ("The target site has the env endpoint enabled and the eureka.client.serviceUrl.defaultZone attribute is enabled. XStream deserialization RCE test can be performed. The path is: {}". format (url_tar))
            saveinfo ("env endpoint is enabled on the target site and the eureka.client.serviceUrl.defaultZone property is enabled, XStream deserialization RCE test can be performed, the path is: {}". format (url_tar))
        headers["Cache-Control"]="max-age=0"
        rr = requests.post(url+'/actuator/restart', headers=headers, verify=False)
        if rr.status_code == 200:
            print ("The target site has env endpoints enabled and supports restart endpoint access, H2 RCE testing is possible, the path is: {}". format (url + '/ actuator / restart'))
            saveinfo ("The target site has env endpoint enabled and supports restart endpoint access, H2 RCE test is available, the path is: {}". format (url + '/ actuator / restart'))



#Spring Boot 2.x version endpoint moved to / actuator / path.
def sb2_Actuator(url):
    Envcheck_2(url)
    Jolokiacheck(url+'/actuator')
    for i in pathlist:
        url_tar = url+'/actuator'+i
        r = requests.get(url_tar, headers=headers, verify=False)
        if r.status_code==200:
            print ("The target site has enabled unauthorized access to the {} endpoint, the path is: {}". format (i.replace ('/', ''), url_tar))
            saveinfo ("The target site has enabled unauthorized access to the {} endpoint, the path is: {}". format (i.replace ('/', ''), url_tar))




def sb_Actuator(url):
    try:
        if sb1_Actuator(url)==0:
            sb2_Actuator(url)
    except:
        pass

def Cidr_ips (cidr):
    ips=[]
    for ip in ipaddress.IPv4Network(cidr):
        ips.append('%s'%ip)
    return ips


def cidrscan(cidr):
    if re.match(r"^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2]\d|3[0-2])$",cidr):
        curls = []
        ips = Cidr_ips (cidr)
        for i in ips:
            curls.append('http://'+i)
            curls.append('https://'+i)
        poolmana (curls)
    else:
        print ("CIDR format input is bad")


def poolmana (ips):
    p = Pool(10)
    q = Manager().Queue()
    for i in ips:
        i=i.replace('\n','')
        p.apply_async(isSB, args=(i,q,))
    p.close()
    p.join()
    print ('Search completed >>>>> \ nPlease check the file under the current path: result.txt')


def run(filepath):
    ips=getinfo(filepath)
    poolmana (ips)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument ("-u", "--url", dest = 'url', help = "single target scan")
    parser.add_argument ("-s", "--surl", dest = 'surl', help = "single target scan (skip fingerprint)")
    parser.add_argument("-c", "--cidr", dest='cidr', help="port(80/443/custom)")
    parser.add_argument ("-f", "--file", dest = 'file', help = "load target from file")

    args = parser.parse_args()
    if args.url:
        res=sbcheck(args.url)
        if res==1:
            pass
        elif res == 0.0:
            print ("The connection to the target network is abnormal, the timeout is 10s by default, please change it according to the network environment")
        elif res == 0.1:
            print ("The connection to the target network is abnormal, the target computer actively refuses to connect,")
        else:
            print ("The target does not use spring boot or the script recognition module is fucked.")
    elif args.surl:
        sb_Actuator(args.surl)
    elif args.cidr:
        cidrscan(args.cidr)
    elif args.file:
        run(args.file)
