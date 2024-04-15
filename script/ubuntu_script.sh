#!/bin/bash

report="report_$(date +%Y-%m-%d_%H-%M-%S).txt"



# - Restrict remote access to root account: High U-01

echo "----Restrict remote access to root account: High U-01----" >> $report 2>&1

##Telnet 동작 확인 후 루트 권한 접속 제한 여부 확인
if ps aux | grep -v grep | grep -q telnet 
then 
    if [ -f /etc/pam.d/login ]
    then
        if grep -v '^#' /etc/pam.d/login | tr -s ' ' | grep -q 'auth required /lib/security/pam_securetty.so'
        then 
            echo "[양호] 텔넷이 활성화 되어있으나 루트 권한 접속이 제한되어있습니다." >> $report 2>&1
        else 
            echo "[취약] 텔넷이 활성화 되어있으며 루트 권한 접속 제한이 설정되어있지 않습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/pam.d/login 파일에 'auth required /lib/security/pam_securetty.so' 를 삽입하세요" >> $report 2>&1
        fi
    
    else
        echo "[기타] /etc/pam.d/login 파일이 존재하지 않습니다." >> $report 2>&1
    fi
    if [ -f /etc/securetty ]
    then 
        if grep -v '^#' /etc/securetty | grep -q '^pts/[0-9]\+' 
        then 
            echo "[양호] 텔넷이 활성화 되어있으나 루트 권한 접속이 제한되어있습니다." >> $report 2>&1
        else 
            echo "[취약] 텔넷이 활성화 되어있으며 루트 권한 접속 제한이 설정되어있지 않습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/securetty 파일에 pts/0 ~ pts/x 설정을 제거하세요 " >> $report 2>&1
        fi
    
    else
        echo "[기타] /etc/securetty 파일이 존재하지 않습니다." >> $report 2>&1
    fi
fi


##ssh 동작 확인 후 루트 권한 접속 제한 여부 확인

if ps aux | grep -v grep | grep -q sshd 
then 
    if [ -f /etc/ssh/sshd_config ]
    then
        if grep -v '^#' /etc/ssh/sshd_config | tr -s ' '|grep -q 'PermitRootLogin no' 
        then 
            echo "[양호] ssh가 활성화 되어있으나 루트 권한 접속이 제한되어있습니다." >> $report 2>&1
        else 
            echo "[취약] ssh가 활성화 되어있으나 루트 권한 접속 제한이 설정되어있지 않습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/ssh/sshd_config 파일에 'PermitRootLogin no' 를 삽입하세요" >> $report 2>&1
        fi
    
    else
        echo "[기타] /etc/ssh/sshd_config 파일이 존재하지 않습니다." >> $report 2>&1
    fi
fi

if ! ps aux | grep -v grep | grep -E -q "sshd|telnet" 
then 
    echo "[양호] 원격 터미널이 활성화 되어있지 않습니다" >> $report 2>&1
fi    

# - Password complexity settings: High U-02
echo " " >> $report 2>&1
echo "----Password complexity settings: High U-02----" >> $report 2>&1

#login.defs 파일 점검
if [ -f /etc/login.defs ]
    then
    
        min_len=$(grep ^PASS_MIN_LEN /etc/login.defs | tr -s ' ' | cut -d ' ' -f2)

        if [ -n "$min_len" ] && [ "$min_len" -ge 8 ]
        then
            echo "[양호] /etc/login.defs 비밀번호 설정이 8자 이상으로 설정되어있습니다." >> $report 2>&1
        else
            echo "[취약] /etc/login.defs 비밀번호 설정이 8자 이하거나 존재하지 않습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/login.defs 파일에서 비밀번호 최소값을 8자 이상으로 설정하세요." >> $report 2>&1
        fi
    else
         echo "[기타] /etc/login.defs 파일이 존재하지 않습니다." >> $report 2>&1

fi

#common-password 파일 점검

if [ -f /etc/pam.d/common-password ]
then
    if grep -q "pam_pwquality.so" /etc/pam.d/common-password
    then
        if  grep -q "minlen=[0-9]*" /etc/pam.d/common-password && \
            grep -q "dcredit=-[0-9]*" /etc/pam.d/common-password && \
            grep -q "ucredit=-[0-9]*" /etc/pam.d/common-password && \
            grep -q "lcredit=-[0-9]*" /etc/pam.d/common-password && \
            grep -q "ocredit=-[0-9]*" /etc/pam.d/common-password
        then
            echo "[양호] /etc/pam.d/common-password의 pam_pwquality.so 모듈이 비밀번호 설정 요구사항을 충족합니다." >> $report 2>&1
        else
            echo "[취약] /etc/pam.d/common-password의 pam_pwquality.so 모듈이 비밀번호 설정 요구사항을 충족하지 않습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/pam.d/common-password 파일에서 pam_pwquality.so 설정 부분에 비밀번호 최소값을 8자 이상과 영문·숫자·특수문자 최소 입력 기능을 추가하세요." >> $report 2>&1
        fi
    else
        echo "[기타]/etc/pam.d/common-password 파일에서 pam_pwquality.so 모듈을 찾을 수 없습니다." >> $report 2>&1
    fi
    
else
        echo "[기타] /etc/pam.d/common-password 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Account lockout threshold settings: High U-03

echo " " >> $report 2>&1
echo "----Account lockout threshold settings: High U-03----" >> $report 2>&1

if [ -f /etc/pam.d/common-auth ]
then
    # pam_tally2.so 모듈 확인
    if grep -q pam_tally2.so /etc/pam.d/common-auth
    then 
        if [ $(grep pam_tally2.so /etc/pam.d/common-auth |  grep -o 'deny=[0-9]*' | cut -d= -f2) -ge 10 ]
        then
            echo "[취약] /etc/pam.d/common-auth 의 pam_tally2.so 모듈에 설정된 잠금 임계값이 10 이상입니다." >> $report 2>&1
            echo "[[조치방법]] /etc/pam.d/common-auth 의 pam_tally2.so 모듈에 dney 값을 10 이하로 설정하세요." >> $report 2>&1
        else
            if [ $(grep pam_tally2.so /etc/pam.d/common-auth | grep -o 'deny=[0-9]*' | cut -d= -f2) -eq 0 ]
            then
                echo "[취약] /etc/pam.d/common-auth 의 pam_tally2.so 모듈에 설정된 잠금 임계값이 설정되어있지 않습니다." >> $report 2>&1
                echo "[[조치방법]] /etc/pam.d/common-auth 의 pam_tally2.so 모듈에 dney 값을 10 이하로 설정하세요." >> $report 2>&1
            else    
                echo "[양호] /etc/pam.d/common-auth 의 pam_tally2.so 모듈에 설정된 잠금 임계값이 10 이하입니다." >> $report 2>&1
            fi
        fi
    # pam_faillock.so 모듈 확인
    elif grep -q pam_faillock.so /etc/pam.d/common-auth
    then
        if grep -q deny= /etc/pam.d/common-auth 
        then
            grep deny= /etc/pam.d/common-auth > /tmp/denies.txt
            u_03_deny_val=0
            while IFS= read -r line
            do
                u_03_deny_val=$(echo $line | grep -oP 'deny=\K\d+')
                if [ $u_03_deny_val -ge 10 ]
                then
                    echo "[취약] /etc/pam.d/common-auth 의 pam_faillock.so 모듈에 잠금 임계값이 10 이상인 설정이 존재합니다." >> $report 2>&1
                    echo "[[조치방법]] /etc/pam.d/common-auth 의 pam_faillock.so 모듈에 모든 dney 값을 10 이하로 설정하세요." >> $report 2>&1
                    break
                elif [ $u_03_deny_val -eq 0 ]
                then 
                    echo "[취약] /etc/pam.d/common-auth 의 pam_faillock.so 모듈에 잠금 임계값이 설정되어있지 않습니다." >> $report 2>&1
                    echo "[[조치방법]] /etc/pam.d/common-auth 의 pam_faillock.so 모듈에 모든 dney 값을 10 이하로 설정하세요." >> $report 2>&1
                    break
        
                else  
                    u_03_deny_val=0
                fi
            done < /tmp/denies.txt
            rm /tmp/denies.txt

            if [ $u_03_deny_val -eq 0 ]
            then 
                echo "[양호] /etc/pam.d/common-auth 의 pam_faillock.so 모듈에 잠금 임계값이 모두 10 이하로 설정되어있습니다." >> $report 2>&1
            fi
            
        fi
    else
        echo "[기타] 비밀번호 잠금 임계값 관련 모듈을 찾을 수 없습니다." >> $report 2>&1
    fi
else 
    echo "[기타] /etc/pam.d/common-auth 파일이 존재하지 않습니다." >> $report 2>&1
fi

# - Protection of password files: High U-04

echo " " >> $report 2>&1
echo "----Protection of password files: High U-04----" >> $report 2>&1

if [ -f /etc/passwd ]
then
    vuln=0
    while IFS=: read -r user pass junk 
    do
        if [ $pass != "x" ]
        then
            vuln=1
            break
        fi
    done < /etc/passwd

    if [ $vuln -eq 1 ]
    then 
        echo "[취약] 패스워드가 암호화되어 저장되어있지 않습니다."  >> $report 2>&1
        echo "[[조치방법]] 셸에서 'pwconv' 명령어를 실행하여 shadow 파일을 활성화 하세요."  >> $report 2>&1
    else    
        echo "[양호] 패스워드가 암호화되어 저장되어있습니다." >> $report 2>&1
    fi
else
    echo "[기타] /etc/passwd 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Set permissions and path for root home and path directories: High U-05

echo " " >> $report 2>&1
echo "----Set permissions and path for root home and path directories: High U-05----" >> $report 2>&1


OIFS="$IFS"
IFS=":"
path_arr=($PATH)
IFS="$OIFS"

good_len=$((${#path_arr[@]} * 2 / 3))

for i in "${!path_arr[@]}"
do 
    if [ $i -ge $good_len ]
    then
        echo "[양호] PATH 환경변수에 “.” 이 앞이나 중간에 포함되어 있지 않습니다."  >> $report 2>&1
        break
    else
        if [ ${path_arr[$i]} == "." ] 
        then    
            echo "[취약] PATH 환경변수에 “.” 이 앞이나 중간에 포함되어 있습니다. "  >> $report 2>&1
            echo "[[조치방법]] 환경변수 설정파일을 수정하여 “.” 을 삭제하거나 맨 뒤에 위치하도록 수정하세요. "  >> $report 2>&1
            break
        fi
    fi
done


# - Set file and directory owner: High U-06
echo " " >> $report 2>&1
echo "----Set file and directory owner: High U-06----" >> $report 2>&1

u_02_count=$(find / \( -nouser -or -nogroup \) -print 2>/dev/null | wc -l)

if [ "$u_02_count" -gt 0 ]
then 
    echo "[취약] 소유자가 없는 파일 및 디렉터리가 존재합니다."  >> $report 2>&1
    echo "[[조치방안]] 'find ( -nouser -or -nogroup ) -print' 명령어를 입력한 후 출력된 파일들을 삭제하세요"  >> $report 2>&1
else 
    echo "[양호] 소유자가 없는 파일 및 디렉터리가 존재하지 않습니다." >> $report 2>&1
fi


# - Set owner and permissions for /etc/passwd file: High U-07
echo " " >> $report 2>&1
echo "----Set owner and permissions for /etc/passwd file: High U-07----" >> $report 2>&1

if [ -f /etc/passwd ]
then

    if [ $(ls -l /etc/passwd | awk '{print $3}') != 'root' ]
    then
        echo "[취약] /etc/passwd 파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
        echo "[[조치방법]] 'chown root /etc/passwd' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
        if [ $(ls -l /etc/passwd | awk '{print $1}') != '-rw-r--r--' ]
        then
            echo "[취약] /etc/passwd 파일의 권한이 644가 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 644 /etc/passwd' 를 입력하여 권한을 644 로 변경하세요 "  >> $report 2>&1
        fi
    else 
        if [ $(ls -l /etc/passwd | awk '{print $1}') != '-rw-r--r--' ]
        then
            echo "[취약] /etc/passwd 파일의 권한이 644가 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 644 /etc/passwd' 를 입력하여 권한을 644 로 변경하세요 "  >> $report 2>&1
        else 
            echo "[양호] /etc/passwd 파일의 소유주가 root 계정이고 권한이 644로 설정되어있습니다."  >> $report 2>&1
        fi

    fi

else
    echo "[기타] /etc/passwd 파일이 존재하지 않습니다." >> $report 2>&1
fi

# - Set owner and permissions for /etc/shadow file: High U-08
echo " " >> $report 2>&1
echo "----Set owner and permissions for /etc/shadow file: High U-08----" >> $report 2>&1

if [ -f /etc/shadow ]
then

    if [ $(ls -l /etc/shadow | awk '{print $3}') != 'root' ]
    then
        echo "[취약] /etc/shadow 파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
        echo "[[조치방법]] 'chown root /etc/shadow' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
        if [ $(ls -l /etc/shadow | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/shadow 파일의 권한이 400이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 400 /etc/shadow' 를 입력하여 권한을 400 으로 변경하세요 "  >> $report 2>&1
        fi
    else 
        if [ $(ls -l /etc/shadow | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/shadow 파일의 권한이 400이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 400 /etc/shadow' 를 입력하여 권한을 400 으로 변경하세요 "  >> $report 2>&1
        else 
            echo "[양호] /etc/shadow 파일의 소유주가 root 계정이고 권한이 400으로 설정되어있습니다."  >> $report 2>&1
        fi

    fi

else
    echo "[기타] /etc/shadow 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Set owner and permissions for /etc/hosts file: High U-09
echo " " >> $report 2>&1
echo "----Set owner and permissions for /etc/hosts file: High U-09----" >> $report 2>&1

if [ -f /etc/hosts ]
then

    if [ $(ls -l /etc/hosts | awk '{print $3}') != 'root' ]
    then
        echo "[취약] /etc/hosts 파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
        echo "[[조치방법]] 'chown root /etc/hosts' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
        if [ $(ls -l /etc/hosts | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/hosts 파일의 권한이 600가 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 600 /etc/hosts' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
        fi
    else 
        if [ $(ls -l /etc/hosts | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/hosts 파일의 권한이 600가 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 600 /etc/hosts' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
        else 
            echo "[양호] /etc/hosts 파일의 소유주가 root 계정이고 권한이 600으로 설정되어있습니다."  >> $report 2>&1
        fi

    fi

else
    echo "[기타] /etc/hosts 파일이 존재하지 않습니다." >> $report 2>&1
fi



# - Set owner and permissions for /etc/(x)inetd.conf file: High U-10
echo " " >> $report 2>&1
echo "----Set owner and permissions for /etc/(x)inetd.conf file: High U-10----" >> $report 2>&1


if [ -f /etc/inetd.conf ]
then

    if [ $(ls -l /etc/inetd.conf  | awk '{print $3}') != 'root' ]
    then
        echo "[취약] /etc/inetd.conf  파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
        echo "[[조치방법]] 'chown root /etc/inetd.conf ' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
        if [ $(ls -l /etc/inetd.conf  | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/inetd.conf  파일의 권한이 600이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 600 /etc/inetd.conf ' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
        fi
    else 
        if [ $(ls -l /etc/inetd.conf  | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/inetd.conf  파일의 권한이 600이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 600 /etc/inetd.conf ' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
        else 
            echo "[양호] /etc/inetd.conf  파일의 소유주가 root 계정이고 권한이 600으로 설정되어있습니다."  >> $report 2>&1
        fi

    fi

else
    echo "[기타] /etc/inetd.conf  파일이 존재하지 않습니다." >> $report 2>&1
fi


if [ -f /etc/xinetd.conf ]
then

    if [ $(ls -l /etc/xinetd.conf  | awk '{print $3}') != 'root' ]
    then
        echo "[취약] /etc/xinetd.conf  파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
        echo "[[조치방법]] 'chown root /etc/xinetd.conf ' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
        if [ $(ls -l /etc/xinetd.conf  | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/xinetd.conf  파일의 권한이 600이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 600 /etc/xinetd.conf ' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
        fi
    else 
        if [ $(ls -l /etc/xinetd.conf  | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/xinetd.conf  파일의 권한이 600이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 600 /etc/xinetd.conf ' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
        else 
            echo "[양호] /etc/xinetd.conf  파일의 소유주가 root 계정이고 권한이 600으로 설정되어있습니다."  >> $report 2>&1
        fi

    fi

else
    echo "[기타] /etc/xinetd.conf  파일이 존재하지 않습니다." >> $report 2>&1
fi

if [ -d /etc/xinetd.d ]
then
    for file in /etc/xinetd.d/*
    do 
        if [ -e $file ]
        then
            if [ $(ls -l $file  | awk '{print $3}') != 'root' ]
            then
                echo "[취약] $file  파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
                echo "[[조치방법]] 'chown root $file ' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
                if [ $(ls -l $file  | awk '{print $1}') != '-r--------' ]
                then
                    echo "[취약] $file  파일의 권한이 600이 아닙니다."  >> $report 2>&1
                    echo "[[조치방법]] 'chmod 600 $file ' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
                fi
            else 
                if [ $(ls -l $file  | awk '{print $1}') != '-r--------' ]
                then
                    echo "[취약] $file  파일의 권한이 600이 아닙니다."  >> $report 2>&1
                    echo "[[조치방법]] 'chmod 600 $file ' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
                else 
                    echo "[양호] $file  파일의 소유주가 root 계정이고 권한이 600으로 설정되어있습니다."  >> $report 2>&1
                fi

            fi
        fi
    done
else
    echo "[기타] /etc/xinetd.d 디렉토리가 존재하지 않습니다." >> $report 2>&1
fi



# - Set owner and permissions for /etc/syslog.conf file: High U-11
echo " " >> $report 2>&1
echo "----Set owner and permissions for /etc/syslog.conf file: High U-11----" >> $report 2>&1


if [ -f /etc/syslog.conf ]
then

    if [ $(ls -l /etc/syslog.conf  | awk '{print $3}') != 'root' ]
    then
        echo "[취약] /etc/syslog.conf  파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
        echo "[[조치방법]] 'chown root /etc/syslog.conf ' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
        if [ $(ls -l /etc/syslog.conf  | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/syslog.conf  파일의 권한이 640이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 640 /etc/syslog.conf ' 를 입력하여 권한을 640 으로 변경하세요 "  >> $report 2>&1
        fi
    else 
        if [ $(ls -l /etc/syslog.conf  | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/syslog.conf  파일의 권한이 640이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 640 /etc/syslog.conf ' 를 입력하여 권한을 640 으로 변경하세요 "  >> $report 2>&1
        else 
            echo "[양호] /etc/syslog.conf  파일의 소유주가 root 계정이고 권한이 640으로 설정되어있습니다."  >> $report 2>&1
        fi

    fi

else
    echo "[기타] /etc/syslog.conf  파일이 존재하지 않습니다." >> $report 2>&1
fi

if [ -f /etc/rsyslog.conf ]
then

    if [ $(ls -l /etc/rsyslog.conf  | awk '{print $3}') != 'root' ]
    then
        echo "[취약] /etc/rsyslog.conf  파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
        echo "[[조치방법]] 'chown root /etc/rsyslog.conf ' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
        if [ $(ls -l /etc/rsyslog.conf  | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/rsyslog.conf  파일의 권한이 640이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 640 /etc/rsyslog.conf ' 를 입력하여 권한을 640 으로 변경하세요 "  >> $report 2>&1
        fi
    else 
        if [ $(ls -l /etc/rsyslog.conf  | awk '{print $1}') != '-r--------' ]
        then
            echo "[취약] /etc/rsyslog.conf  파일의 권한이 640이 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 640 /etc/rsyslog.conf ' 를 입력하여 권한을 640 으로 변경하세요 "  >> $report 2>&1
        else 
            echo "[양호] /etc/rsyslog.conf  파일의 소유주가 root 계정이고 권한이 640으로 설정되어있습니다."  >> $report 2>&1
        fi

    fi

else
    echo "[기타] /etc/rsyslog.conf  파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Set owner and permissions for /etc/services file: High U-12
echo " " >> $report 2>&1
echo "----Set owner and permissions for /etc/services file: High U-12----" >> $report 2>&1


if [ -f /etc/services ]
then

    if [ $(ls -l /etc/services | awk '{print $3}') != 'root' ]
    then
        echo "[취약] /etc/services 파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
        echo "[[조치방법]] 'chown root /etc/services' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
        if [ $(ls -l /etc/services | awk '{print $1}') != '-rw-r--r--' ]
        then
            echo "[취약] /etc/services 파일의 권한이 644가 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 644 /etc/services' 를 입력하여 권한을 644 로 변경하세요 "  >> $report 2>&1
        fi
    else 
        if [ $(ls -l /etc/services | awk '{print $1}') != '-rw-r--r--' ]
        then
            echo "[취약] /etc/services 파일의 권한이 644가 아닙니다."  >> $report 2>&1
            echo "[[조치방법]] 'chmod 644 /etc/services' 를 입력하여 권한을 644 로 변경하세요 "  >> $report 2>&1
        else 
            echo "[양호] /etc/services 파일의 소유주가 root 계정이고 권한이 644로 설정되어있습니다."  >> $report 2>&1
        fi

    fi

else
    echo "[기타] /etc/services 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Check files for SUID, SGID, Sticky bit settings: High U-13
echo " " >> $report 2>&1
echo "----Check files for SUID, SGID, Sticky bit settings: High U-13----" >> $report 2>&1

u_13_file_arr=(
    "/sbin/dump"
    "/usr/bin/lpq-lpd"
    "/usr/bin/newgrp"
    "/sbin/restore"
    "/usr/bin/lpr"
    "/usr/sbin/lpc"
    "/sbin/unix_chkpwd"
    "/usr/bin/lpr-lpd"
    "/usr/sbin/lpc-lpd"
    "/usr/bin/at"
    "/usr/bin/lprm"
    "/usr/sbin/traceroute"
    "/usr/bin/lpq"
    "/usr/bin/lprm-lpd"
)

for i in "${u_13_file_arr[@]}"
do
    if [ -f $i ]
    then
        if ls -l $i | awk '{print $1}' | grep -q s
        then
            echo "[취약] $i 파일에 sticky bit가 설정되어 있습니다. " >> $report 2>&1
            echo "[[조치방법]] 'chmod -s $i' 명령어를 입력하여 스티키 비트를 제거하세요. " >> $report 2>&1
        else
            echo "[양호] $i 파일에 sticky bit가 설정되어있지 않습니다. " >> $report 2>&1
        fi
    else
        echo "[기타] $i 파일이 존재하지 않습니다. "  >> $report 2>&1
    fi

done

# - Set owner and permissions for user, system startup, and environment files: High U-14
echo " " >> $report 2>&1
echo "----Set owner and permissions for user, system startup, and environment files: High U-14----" >> $report 2>&1

u_14_file_arr=(
    ".bashrc" 
    ".profile" 
    ".bash_profile" 
    ".bash_logout" 
    ".cshrc" 
    ".kshrc" 
    ".login" 
    ".logout" 
    ".zshrc"
)


u_14_path="/home/*"
u_14_vuln=0

for p in $u_14_path
do
    for f in "${u_14_file_arr[@]}"
    do
        u_14_path_file="$p/$f"
        if [ -f $u_14_path_file ]
        then 
            u_14_perm=$(ls -l $u_14_path_file | awk '{print $1}')
            u_14_usr=$(ls -l $u_14_path_file | awk '{print $3}')

            if [[ $u_14_asr != "root" && $u_14_usr != $(basename "$p") ]]
            then
                echo "[취약] $u_14_path_file 의 파일 소유자가 루트나 계정주가 아닙니다.">> $report 2>&1
                echo "[[조치방법]] 'chown {username} $u_14_path_file' 명려어를 통해 소유자를 변경하세요 .">> $report 2>&1
                u_14_vuln=1
            fi

            if [[ $u_14_perm =~ ^.....w  || $u_14_perm =~ ^.......w ]]
            then
                echo "[취약] $u_14_path_file 파일 소유자 외 쓰기가 허용되어있습니다.">> $report 2>&1
                 echo "[[조치방법]] 'chmod o-w $u_14_path_file' 명려어를 통해 파일 쓰기권한을 제거하세요 .">> $report 2>&1
                u_14_vuln=1
            fi

        fi
    done
done

if [ $u_14_vuln -eq 0 ] 
then
    echo "[양호] 모든 환경변수 파일이 루트나 계정 소유로 되어있으며 소유주만 쓰기가 가능합니다.">> $report 2>&1
fi



# - Check for world writable files: High U-15
echo " " >> $report 2>&1
echo "----Check for world writable files: High U-15----" >> $report 2>&1

if [ $(find / -type f -perm –2 –exec ls –l {} \;) -gt 0 ]
then 
    echo "[취약] 다음과 같은 파일에 world writable 파일이 존재합니다.">> $report 2>&1
    echo "$(find / -type f -perm –2 –exec ls –l {} \;)">> $report 2>&1
    echo "[[조치방법]]'chmod o-w {file_name}' 명령어를 사용하여 쓰기권한을 제거하세요"
else 
    echo "[양호] world writable 파일이 존재하지 않습니다.">> $report 2>&1
fi

# - Check for device files not in /dev: High U-16
echo " " >> $report 2>&1
echo "----Check for device files not in /dev: High U-16----" >> $report 2>&1

if [ $(find /dev –type f –exec ls –l {} \;) -gt 0 ]
then 
    echo "[기타] 다음과 같이 /dev에 device 파일이 존재합니다.">> $report 2>&1
    echo "$(find /dev –type f –exec ls –l {} \;)">> $report 2>&1
    echo "[[조치방법]]major, minor number를 가지지 않는 파일들을 제거하세요"
else 
    echo "[양호] world writable 파일이 존재하지 않습니다.">> $report 2>&1
fi


# - Prohibit the use of $HOME/.rhosts, hosts.equiv: High U-17
echo " " >> $report 2>&1
echo "----Prohibit the use of $HOME/.rhosts, hosts.equiv: High U-17----" >> $report 2>&1

if [ 사용안하면 ]
then
    echo "[양호]"
else
    if[]
    
fi

# - Restrict login IP and port: High U-18
echo " " >> $report 2>&1
echo "----Restrict login IP and port: High U-18----" >> $report 2>&1


# - Prohibit UIDs of '0' other than root: Medium U-44

echo " " >> $report 2>&1
echo "----Prohibit UIDs of '0' other than root: Medium U-44----" >> $report 2>&1



# - Restrict root account's use of su: Low U-45
# - Set minimum password length: Medium U-46
# - Set maximum password lifetime: Medium U-47
# - Set minimum password lifetime: Medium U-48
# - Removal of unnecessary accounts: Low U-49
# - Include a minimal number of accounts in the admin group: Low U-50
# - Prohibit GIDs without accounts: Low U-51
# - Prohibit identical UIDs: Medium U-52
# - Check user shells: Low U-53
# - Set Session Timeout: Low U-54


# - Set owner and permissions for hosts.lpd file: Low U-55
# - Manage UMASK settings: Medium U-56
# - Set owner and permissions for home directories: Medium U-57
# - Manage the existence of directories designated as home directories: Medium U-58
# - Search for and remove hidden files and directories: Low U-59

# Service Management
# - Disable finger service: High U-19
# - Disable Anonymous FTP: High U-20
# - Disable r series services: High U-21
# - Set owner and permissions for cron files: High U-22
# - Disable services vulnerable to Dos attacks: High U-23
# - Disable NFS services: High U-24
# - Control access to NFS: High U-25
# - Remove automountd: High U-26
# - Check RPC services: High U-27
# - Check NIS, NIS+: High U-28
# - Disable tftp, talk services: High U-29
# - Check Sendmail version: High U-30
# - Limit spam mail relay: High U-31
# - Prevent general users from executing Sendmail: High U-32
# - Patch DNS security version: High U-33
# - Configure DNS Zone Transfer settings: High U-34
# - Remove directory listing from web services: High U-35
# - Limit web service process permissions: High U-36
# - Prohibit access to web service's upper directories: High U-37
# - Remove unnecessary files from web services: High U-38
# - Prohibit the use of links in web services: High U-39
# - Limit file upload and download in web services: High U-40
# - Segregate web service areas: High U-41
# - Allow remote SSH access: Medium U-60
# - Check FTP service: Low U-61
# - Limit shell access for FTP accounts: Medium U-62
# - Set owner and permissions for Ftpusers file: Low U-63
# - Configure Ftpusers file: Medium U-64
# - Set owner and permissions for at files: Medium U-65
# - Check for running SNMP services: Medium U-66
# - Set complexity for SNMP service community strings: Medium U-67
# - Provide login warning message: Low U-68
# - Restrict access to NFS configuration files: Medium U-69
# - Limit expn, vrfy commands: Medium U-70
# - Hide Apache web service information: Medium U-71

# Patch Management
# - Apply the latest security patches and vendor recommendations: High U-42

# Log Management
# - Regularly review and report logs: High U-43
# - Set system logging according to policy: Low U-72 
