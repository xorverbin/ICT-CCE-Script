#!/bin/bash

report="report_$(date +%Y-%m-%d_%H-%M-%S).txt"



# - Restrict remote access to root account: High U-01
echo " "
echo "----Restrict remote access to root account: High U-01----" >> $report 2>&1


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


if ps aux | grep -v grep | grep -q sshd
then 
    if [ -f /etc/ssh/sshd_config ]
    then
        if grep -v '^#' /etc/ssh/sshd_config | grep -q 'PermitRootLogin.*no' 
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


if [ -f /etc/login.defs ]
then
    u_02_output=$( grep 'PASS_MIN_LEN' /etc/login.defs| grep -v '^#' | awk '{print $2}')
    if [ ! -z $u_02_output ]
    then 
        if [ $u_02_output -ge 8 ]
        then
            echo "[양호] /etc/login.defs 비밀번호 설정이 8자 이상으로 설정되어있습니다." >> $report 2>&1
        else
            echo "[취약] /etc/login.defs 비밀번호 설정이 8자 이하거나 존재하지 않습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/login.defs 파일에서 비밀번호 최소값을 8자 이상으로 설정하세요." >> $report 2>&1
        fi
    else 
        echo "[취약] /etc/login.defs 비밀번호 글자수 설정이 존재하지 않습니다." >> $report 2>&1
        echo "[[조치방법]] /etc/login.defs 파일에서 비밀번호 최소값을 8자 이상으로 설정하고 주석을 제거하세요." >> $report 2>&1
    
    fi
else
    echo "[기타] /etc/login.defs 파일이 존재하지 않습니다." >> $report 2>&1
fi


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


read -r -a u_05_path_arr <<< "$(echo $PATH | tr ':' '\n')"

u_05_good_len=$((${#u_05_path_arr[@]} * 2 / 3))

for i in "${!u_05_path_arr[@]}"
do 
    if [ $i -ge $u_05_good_len ]
    then
        echo "[양호] PATH 환경변수에 “.” 이 앞이나 중간에 포함되어 있지 않습니다."  >> $report 2>&1
        break
    else
        if [ ${u_05_path_arr[$i]} == "." ] 
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


if find / \( -nouser -or -nogroup \) 2>/dev/null | grep -q .
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
    for i in /etc/xinetd.d/*
    do 
        if [ -e $i ]
        then
            if [ $(ls -l $i  | awk '{print $3}') != 'root' ]
            then
                echo "[취약] $i  파일의 소유주가 root 계정이 아닙니다."  >> $report 2>&1
                echo "[[조치방법]] 'chown root $i ' 를 입력하여 소유주를 root 로 변경하세요 "  >> $report 2>&1
                if [ $(ls -l $i  | awk '{print $1}') != '-r--------' ]
                then
                    echo "[취약] $i  파일의 권한이 600이 아닙니다."  >> $report 2>&1
                    echo "[[조치방법]] 'chmod 600 $i ' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
                fi
            else 
                if [ $(ls -l $i  | awk '{print $1}') != '-r--------' ]
                then
                    echo "[취약] $i  파일의 권한이 600이 아닙니다."  >> $report 2>&1
                    echo "[[조치방법]] 'chmod 600 $i ' 를 입력하여 권한을 600 으로 변경하세요 "  >> $report 2>&1
                else 
                    echo "[양호] $i  파일의 소유주가 root 계정이고 권한이 600으로 설정되어있습니다."  >> $report 2>&1
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

u_13_chk=0
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
    "/usr/bin/lprm-lpd")

for i in "${u_13_file_arr[@]}"
do
    if [ -f $i ]
    then
        if ls -l $i | awk '{print $1}' | grep -q s
        then
            echo "[취약] $i 파일에 sticky bit가 설정되어 있습니다. " >> $report 2>&1
            echo "[[조치방법]] 'chmod -s $i' 명령어를 입력하여 스티키 비트를 제거하세요. " >> $report 2>&1
            u_13_chk=1
        else
            echo "[양호] $i 파일에 sticky bit가 설정되어있지 않습니다. " >> $report 2>&1
            u_13_chk=1
        fi
    fi

done

if [ $u_13_chk -eq 0 ]
then 
    echo "[기타] 관련 파일이 존재하지 않습니다. "  >> $report 2>&1
fi

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

            if [[ $u_14_usr != "root" && $u_14_usr != $(basename "$p") ]]
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

if find / -type f -perm -002 2>/dev/null | grep -q .
then 
    echo "[취약] 다음과 같은 파일에 world writable 파일이 존재합니다.">> $report 2>&1
    echo "$(find / -type f -perm -002 -exec ls -l {} \; 2>/dev/null)">> $report 2>&1
    echo "[[조치방법]]'chmod o-w {file_name}' 명령어를 사용하여 쓰기권한을 제거하세요">> $report 2>&1
else 
    echo "[양호] world writable 파일이 존재하지 않습니다.">> $report 2>&1
fi

# - Check for device files not in /dev: High U-16
echo " " >> $report 2>&1
echo "----Check for device files not in /dev: High U-16----" >> $report 2>&1

if find / -type f -perm -002 2>/dev/null | grep -q .
then 
    echo "[기타] 다음과 같이 /dev에 device 파일이 존재합니다.">> $report 2>&1
    echo "$(find /dev -type f -exec ls -l {} \; 2>/dev/null)">> $report 2>&1
    echo "[[조치방법]]major, minor number를 가지지 않는 파일들을 제거하세요">> $report 2>&1
else 
    echo "[양호] /dev에 device 파일이 존재하지 않습니다.">> $report 2>&1
fi


# - Prohibit the use of $HOME/.rhosts, hosts.equiv: High U-17
echo " " >> $report 2>&1
echo "----Prohibit the use of $HOME/.rhosts, hosts.equiv: High U-17----" >> $report 2>&1

declare -a u_17_usrdir_arr 
declare -a u_17_rhosts_arr
declare -a u_17_rhosts_usr_arr
u_17_vuln=0

while IFS=: read -r usr _ uid _ _ dir _ 
do
    if [ $uid -ge 1000 ]
    then 
        u_17_usrdir_arr+=("$dir")

        u_17_dir_path="$dir/.rhosts" 
        if [ -f $u_17_dir_path ]
        then 
            u_17_rhosts_arr+=$u_17_dir_path
            u_17_rhosts_usr_arr+=$usr
        fi
    fi

done < /etc/passwd
  

if [[ -f /etc/hosts.equiv && ${#u_17_rhosts_arr[@]} -eq 0 ]]
then
    echo "[양호] hosts.equive 와 .rhosts 파일이 존재하지 않습니다.">> $report 2>&1
else
    if [ -f /etc/hosts.equiv ]
    then 
        if [ $(ls -l /etc/hosts.equiv | awk '{print $3}') != 'root' ]
        then 
            echo "[취약] /etc/hosts.equiv 파일의 소유주가 root 가 아닙니다.">> $report 2>&1
            echo "[[조치방법]] chown root /etc/hosts.equiv 명령어를 실행하세요">> $report 2>&1
            u_17_vuln=1
        fi

        if [ $(stat -c "%a" /etc/hosts.equiv) -gt 600 ]
        then 
            echo "[취약] /etc/hosts.equiv 파일의 권한이 600 이상입니다.">> $report 2>&1
            echo "[[조치방법]] chown root /etc/hosts.equiv 명령어를 실행하세요">> $report 2>&1
            u_17_vuln=1
        fi

        if grep -q "+" /etc/hosts.equiv
        then
            echo "[취약] /etc/hosts.equiv 파일에 '+' 설정이 존재합니다.">> $report 2>&1
            u_17_vuln=1
        fi
        
        if [ $u_17_vuln -eq 0 ]
        then 
            echo "[양호] hosts.equive 파일이 존재하지만 보안설정이 양호하게 적용되어있습니다.">> $report 2>&1
        fi
    fi
        
    if [ ${#u_17_rhosts_arr[@]} -gt 0 ]
    then
        u_17_vuln=0
        for i in "${!u_17_rhosts_arr[@]}"
        do 
            if [[ "$(ls -l ${u_17_rhosts_arr[$i]} | awk '{print $3}')" != "${u_17_rhosts_usr_arr[$i]}" && "$(ls -l ${u_17_rhosts_arr[$i]} | awk '{print $3}')" != "root" ]]
            then 
                echo "[취약] ${u_17_rhosts_arr[$i]} 파일의 소유주가 계정주나 root가 아닙니다.">> $report 2>&1
                u_17_vuln=1
            fi

            if [ $(stat -c "%a" ${u_17_rhosts_arr[$i]}) -gt 600 ]
            then 
                echo "[취약] ${u_17_rhosts_arr[$i]} 파일의 권한이 600 이상입니다.">> $report 2>&1
                u_17_vuln=1
            fi

            if grep -q "+" ${u_17_rhosts_arr[$i]}
            then
                echo "[취약] ${u_17_rhosts_arr[$i]} 파일에 '+' 설정이 존재합니다.">> $report 2>&1
                u_17_vuln=1
            fi
        done        

        if [ $u_17_vuln -eq 0 ]
        then 
            echo "[양호] .rhosts 파일이 존재하지만 보안설정이 양호하게 적용되어있습니다.">> $report 2>&1
        fi
    fi
fi

# - Restrict login IP and port: High U-18
echo " " >> $report 2>&1
echo "----Restrict login IP and port: High U-18----" >> $report 2>&1

# tcp wrapper 를 사용할 경우
if [ -f /etc/hosts.deny ]
then
    if grep -v '^#' /etc/hosts.deny | grep -i -q ALL:ALL 
    then
        echo "[양호] /etc/hosts.deny 파일에 설정이 올바르게 되어있습니다.">> $report 2>&1
    else
        echo "[취약] /etc/hosts.deny 파일에 설정이 올바르게 되어있지 않습니다.">> $report 2>&1
        echo "[[조치방법]] /etc/hosts.deny 파일에 'ALL:ALL'을 설정하세요.">> $report 2>&1
    fi
else
    echo "[기타] /etc/hosts.deny 파일이 존재하지 않습니다.">> $report 2>&1
fi


# - Disable finger service: High U-19

echo " " >> $report 2>&1
echo "----Disable finger service: High U-19----" >> $report 2>&1

if [ -f /etc/inetd.conf ]
then
    if grep '^#' /etc/inetd.conf | grep -i -q finger 
    then
        echo "[취약] /etc/inetd.conf 파일에 finger 서비스가 활성화 되어있습니다.">> $report 2>&1
        echo "[[조치방법]] /etc/inetd.conf 파일에서 finger 서비스를 주석처리하거나 삭제한 후 서비스를 재시작하세요.">> $report 2>&1
    else
        echo "[양호] /etc/inetd.conf 파일에 finger 서비스가 활성화 되어있지않습니다.">> $report 2>&1
    fi
else
    echo "[기타] /etc/inetd.conf 파일이 존재하지 않습니다.">> $report 2>&1
fi

if [ -f /etc/xinetd.d/finger ]
then
    if grep -iq "disable.*no" /etc/xinetd.d/finger 
    then
        echo "[취약] /etc/xinetd.d/finger 파일에 finger 서비스가 활성화 되어있습니다.">> $report 2>&1
        echo "[[조치방법]] /etc/xinetd.d/finger 파일에서 'disable = yes'로 변경한 후 서비스를 재시작하세요.">> $report 2>&1
    else
        echo "[양호] /etc/xinetd.d/finger 파일에 finger 서비스가 활성화 되어있지않습니다.">> $report 2>&1
    fi
else
    echo "[기타] /etc/xinetd.d/finger 파일이 존재하지 않습니다.">> $report 2>&1
fi


# - Disable Anonymous FTP: High U-20

echo " " >> $report 2>&1
echo "----Disable Anonymous FTP: High U-20----" >> $report 2>&1


if [ -f /etc/passwd ]
then
    if grep 'disable' /etc/passwd | grep -q ftp 
    then
        echo "[취약] /etc/passwd 파일에 ftp 계정이 활성화 되어있습니다.">> $report 2>&1
        echo "[[조치방법]] /etc/passwd 파일에서 ftp 계정을 삭제하세요.">> $report 2>&1
    else
        echo "[양호] /etc/passwd 파일에 ftp 계정이 존재하지 않습니다.">> $report 2>&1
    fi
     if grep 'disable' /etc/passwd | grep -q anonymous 
    then
        echo "[취약] /etc/passwd 파일에 anonymous 계정이 활성화 되어있습니다.">> $report 2>&1
        echo "[[조치방법]] /etc/passwd 파일에서 anonymous 계정을 삭제하세요. ">> $report 2>&1
    else
        echo "[양호] /etc/passwd 파일에 anonymous 계정이 존재하지 않습니다.">> $report 2>&1
    fi
else
    echo "[기타] /etc/passwd 파일이 존재하지 않습니다.">> $report 2>&1
fi

if [ -f /etc/proftpd/proftpd.conf ]
then 
    if [ $(awk '/<Anonymous ~ftp>/{x=NR+10} NR<=x' /etc/proftpd/proftpd.conf| tr -s ' '| grep -v '^#' |grep -q "User ftp" )]
        then
            echo "[취약] /etc/proftpd/proftpd.conf 파일에 user ftp 가 활성화되어 있습니다.">> $report 2>&1
            echo "[[조치방법]] /etc/proftpd/proftpd.conf 파일에 user ftp 를 주석처리 하세요.">> $report 2>&1
        else
            echo "[양호] /etc/proftpd/proftpd.conf 파일에 user ftp 가 주석처리 되어있습니다.">> $report 2>&1
    fi

    if [ $(awk '/<Anonymous ~ftp>/{x=NR+10} NR<=x' /etc/proftpd/proftpd.conf| tr -s ' '| grep -v '^#' |grep -q "UserAlias ftp") ]
        then
            echo "[취약] /etc/proftpd/proftpd.conf 파일에 UserAlias ftp 가 활성화되어 있습니다.">> $report 2>&1
            echo "[[조치방법]] /etc/proftpd/proftpd.conf 파일에 UserAlias ftp 를 주석처리 하세요.">> $report 2>&1
        else
            echo "[양호] /etc/proftpd/proftpd.conf 파일에 UserAlias ftp 가 주석처리 되어있습니다.">> $report 2>&1
    fi
fi

if [ -f /etc/vsftpd/vsftpd.conf ]
then 
    if grep -q -i anonymous_enable=YES
        then
            echo "[취약] /etc/vsftpd/vsftpd.conf 파일에 anonymous_enable이 활성화되어 있습니다.">> $report 2>&1
            echo "[[조치방법]] /etc/vsftpd/vsftpd.conf 파일에 'anonymous_enable=NO'로 설정 하세요.">> $report 2>&1
        else
            echo "[양호] /etc/vsftpd/vsftpd.conf 파일에 anonymous_enable 가 NO로 설정 되어있습니다.">> $report 2>&1
    fi

fi




# - Disable r series services: High U-21
echo " " >> $report 2>&1
echo "----Disable r series services: High U-21----" >> $report 2>&1

u_21_dir_arr=("rsh" "rlogin" "rexec")
u_21_vuln=0

if [ -f /etc/inetd.conf ]
then
    if ls -alL /etc/inetd.conf | egrep "rsh|rlogin|rexec" 
    then
        echo "[취약] r-command 가 활성화 되어있습니다." >> $report 2>&1
    else 
        echo "echo [양호] r-command 가 활성화 되어있습니다." >> $report 2>&1
    fi
else 
    echo "[기타]/etc/inetd.conf 파일이 존재하지 않습니다. " >> $report 2>&1
fi


if [ -d /etc/xinetd.d ]
then 
    for i in "${u_21_dir_arr[@]}"
    do
        if [ -f /etc/xinetd.d/$i ] && grep -iq "disable.*no" /etc/xinetd.d/$i   
        then
            echo "[취약] $i 설정이 활성화 되어있습니다." >> $report 2>&1
            u_21_vuln=1
        fi

    done
else
    echo "[기타]/etc/xinetd.d 디렉토리가 존재하지 않습니다." >> $report 2>&1
fi

if [ $u_21_vuln -eq 0 ]
then 
    echo "[양호]r-command 가 활성화 되어있지 않습니다." >> $report 2>&1
fi

# - Set owner and permissions for cron files: High U-22   here

echo " " >> $report 2>&1
echo "----Set owner and permissions for cron files: High U-22----" >> $report 2>&1

u_22_crontab_perm=$(ls -l /usr/bin/crontab | awk '{print $1}')



# - Disable services vulnerable to Dos attacks: High U-23

echo " " >> $report 2>&1
echo "----Disable services vulnerable to Dos attacks: High U-23----" >> $report 2>&1

u_23_file_arr=("echo" "discard" "daytime" "chargen")
u_23_vuln=0


if [ -d /etc/xinetd.d ]
then
    for i in "${u_23_file_arr[@]}"
    do
        if [ -f /etc/xinetd.d/$i ] && grep -iq "disable.*no" /etc/xinetd.d/$i 
        then
            echo "[취약] /etc/xinetd.d/$i 서비스가 활성화 되어있습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/xinetd.d/$i 에서 disable = yes 로 변경하고 서비스를 재시작하세요." >> $report 2>&1
            u_23_vuln=1
        fi
    done
else 
    echo "[기타] /etc/xinetd.d 디렉토리가 존재하지 않습니다" >> $report 2>&1
fi

if [ $u_23_vuln -eq 0 ]
then
    echo "[양호] xinetd 불필요한 서비스가 활성화 되어있지 않습니다." >> $report 2>&1
fi 

u_23_vuln=0

if [ -f /etc/inetd.conf ]
then
    for i in "${u_23_file_arr[@]}"
    do
        if grep -v '^#' | grep -q $i
        then 
            echo "[취약] /etc/inetd.conf파일에 $i 서비스가 활성화 되어있습니다." >> $report 2>&1
            echo "[[조치방법]] $i 부분을 주석처리한 후 서비스를 재시작하세요." >> $report 2>&1
            u_23_vuln=1
        fi
    done
fi

if [ $u_23_vuln -eq 0 ]
then
    echo "[양호] inetd RPC 서비스가 활성화 되어있지 않습니다." >> $report 2>&1
fi 
# - Disable NFS services: High U-24

echo " " >> $report 2>&1
echo "----Disable NFS services: High U-24----" >> $report 2>&1

if ps -ef | egrep "nfs|statd|lockd" | grep -vq grep 
then 
    echo "[취약] NFS 서비스가 활성화 되어있습니다. " >> $report 2>&1
    echo "[[조치방법]] kill 명령어를 사용하여 NFS 서비스를 중지시키세요" >> $report 2>&1
else    
    echo "[양호] NFS 서비스가 비활성화 되어있습니다." >> $report 2>&1
fi 

# - Control access to NFS: High U-25  here
#
#

echo " " >> $report 2>&1
echo "----Control access to NFS: High U-25----" >> $report 2>&1




# - Remove automountd: High U-26

echo " " >> $report 2>&1
echo "----Remove automountd: High U-26----" >> $report 2>&1

if ps -ef | grep -v grep | grep -q automountd
then 
    echo "[취약] automountd 가 활성화 되어있습니다. " >> $report 2>&1
    echo "[[조치방법]] kill 명령어를 사용하여 서비스를 비활성화하거나 스크립트의 이름을 변경하세요 "  >> $report 2>&1
else    
    echo "[양호] automountd가 비활성화 되어있습니다. " >> $report 2>&1
fi

# - Check RPC services: High U-27

echo " " >> $report 2>&1
echo "----Check RPC services: High U-27----" >> $report 2>&1

u_27_file_arr=("rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd")
u_27_vuln=0


if [ -d /etc/xinetd.d ]
then
    for i in "${u_27_file_arr[@]}"
    do
        if [ -f /etc/xinetd.d/$i ] && grep -iq "disable.*no" /etc/xinetd.d/$i 
        then
            echo "[취약] /etc/xinetd.d/$i 서비스가 활성화 되어있습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/xinetd.d/$i 에서 disable = yes 로 변경하고 서비스를 재시작하세요." >> $report 2>&1
            u_27_vuln=1
        fi
    done
else 
    echo "[기타] /etc/xinetd.d 디렉토리가 존재하지 않습니다" >> $report 2>&1
fi

if [ $u_27_vuln -eq 0 ]
then
    echo "[양호] xinetd RPC 서비스가 활성화 되어있지 않습니다." >> $report 2>&1
fi 
u_27_vuln=1

if [ -f /etc/inetd.conf ]
then
    for i in "${u_27_file_arr[@]}"
    do
        if grep -v '^#' | grep -q $i
        then 
            echo "[취약] /etc/inetd.conf파일에 $i 서비스가 활성화 되어있습니다." >> $report 2>&1
            echo "[[조치방법]] $i 부분을 주석처리한 후 서비스를 재시작하세요." >> $report 2>&1
            u_27_vuln=1       
        fi
    done
fi

if [ $u_27_vuln -eq 0 ]
then
    echo "[양호] inetd RPC 서비스가 활성화 되어있지 않습니다." >> $report 2>&1
fi 


# - Check NIS, NIS+: High U-28


echo " " >> $report 2>&1
echo "----Check NIS, NIS+: High U-28----" >> $report 2>&1

if ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -vq grep 
then
    echo "[취약] NIS 서비스가 활성화되어있습니다."  >> $report 2>&1
    echo "[[조치방법]] kill 명령어를 사용하여 NIS를 중지하거나 시동 스크립트의 이름을 변경하세요" >> $report 2>&1
else 
    echo "[양호] NIS 서비스가 비활성화 되어있습니다"  >> $report 2>&1
fi
 

# - Disable tftp, talk services: High U-29

echo " " >> $report 2>&1
echo "----Disable tftp, talk services: High U-29----" >> $report 2>&1



u_29_file_arr=("tftp" "talk" "ntalk")
u_29_vuln=0


if [ -d /etc/xinetd.d ]
then
    for i in "${u_29_file_arr[@]}"
    do
        if  [ -f /etc/xinetd.d/$i ] && grep -iq "disable.*no" /etc/xinetd.d/$i 
        then
            echo "[취약] /etc/xinetd.d/$i 서비스가 활성화 되어있습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/xinetd.d/$i 에서 disable = yes 로 변경하고 서비스를 재시작하세요." >> $report 2>&1
            u_29_vuln=1
        fi
    done
else 
    echo "[기타] /etc/xinetd.d 디렉토리가 존재하지 않습니다" >> $report 2>&1
fi

if [ $u_29_vuln -eq 0 ]
then
    echo "[양호] xinetd RPC 서비스가 활성화 되어있지 않습니다." >> $report 2>&1
fi 
u_29_vuln=1

if [ -f /etc/inetd.conf ]
then
    for i in "${u_29_file_arr[@]}"
    do
        if grep -v '^#' | grep -q $i
        then 
            echo "[취약] /etc/inetd.conf파일에 $i 서비스가 활성화 되어있습니다." >> $report 2>&1
            echo "[[조치방법]] $i 부분을 주석처리한 후 서비스를 재시작하세요." >> $report 2>&1
            u_29_vuln=1       
        fi
    done
fi

if [ $u_29_vuln -eq 0 ]
then
    echo "[양호] inetd RPC 서비스가 활성화 되어있지 않습니다." >> $report 2>&1
fi 



# - Check Sendmail version: High U-30

echo " " >> $report 2>&1
echo "----Check Sendmail version: High U-30----" >> $report 2>&1

if ps -ef | grep sendmail | grep -vq grep 
then 
        ## 버전 업데이트 필요  http://www.sendmail.org/ 
    if dpkg -s sendmail | grep -q "8.18."
    then 
        echo "[양호] sendmail 이 작동중이나 최신버전입니다. ">> $report 2>&1
    else 
        echo "[취약] sendmail 이 최신버전이 아닙니다.">> $report 2>&1
        echo "[[조치방법]] 최신버전으로 업데이트가 필요합니다.">> $report 2>&1
    fi
else
    echo "[기타] sendmail 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi


# - Limit spam mail relay: High U-31

echo " " >> $report 2>&1
echo "----Limit spam mail relay: High U-31----" >> $report 2>&1

if ps -ef | grep sendmail | grep -vq grep
then 
    if cat /etc/mail/sendmail.cf | grep -v "^#" | grep "R$\*" | grep -iq "Relaying denied"
    then
        echo "[양호] sendmail 의 릴레이 기능이 제한되어있습니다." >> $report 2>&1
    else 
        echo "[취약] sendmail 릴레이 기능이 활성화 되어있습니다." >> $report 2>&1
        echo "[[조치방법]]R$* $#error $@ 5.7.1 $: \"550 Relaying denied\"의 주석을 해제 하세요. 그 후 접근 가능한 목록을 따로 파일을 생성해 관리하세요." >> $report 2>&1
    fi
else
    echo "[기타] sendmail 이 활성화 되어있지 않습니다." >> $report 2>&1
fi


# - Prevent general users from executing Sendmail: High U-32

echo " " >> $report 2>&1
echo "----Prevent general users from executing Sendmail: High U-32---" >> $report 2>&1


if ps -ef | grep sendmail | grep -vq grep
then 
    if cat /etc/mail/sendmail.cf | grep -v "^#" | grep PrivacyOptions | grep -iq restrictqrun
    then
        echo "[양호] 일반사용자의 q 실행이 방지되어 있습니다." >> $report 2>&1
    else 
        echo "[취약] 일반사용자의 q 실행이 허용되어 있습니다." >> $report 2>&1
        echo "[[조치방법]] PrivacyOptions 에 restrictqrun을 삽입하세요." >> $report 2>&1
    fi
else
    echo "[기타] sendmail 이 활성화 되어있지 않습니다." >> $report 2>&1
fi

# - Patch DNS security version: High U-33

echo " " >> $report 2>&1
echo "----Patch DNS security version: High U-33----" >> $report 2>&1


if ps -ef | grep named | grep -vq grep
then 
        ## 버전 업데이트 필요  https://www.isc.org/download/
    if dpkg -s bind9 | grep -q "9.18."
    then 
        echo "[양호] bind가 작동중이나 최신버전입니다. ">> $report 2>&1
    else 
        echo "[취약] bind가 최신버전이 아닙니다.">> $report 2>&1
        echo "[[조치방법]] 최신버전으로 업데이트가 필요합니다.">> $report 2>&1
    fi
else
    echo "[기타] dns 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi



# - Configure DNS Zone Transfer settings: High U-34

echo " " >> $report 2>&1
echo "----Configure DNS Zone Transfer settings: High U-34----" >> $report 2>&1

if ps -ef | grep named | grep -vq grep
then
    if grep allow-transfer /etc/named.conf| grep -q any
    then 
        echo "[취약] Zone Transfer가 모든 사용자에게 허락되어있습니다. ">> $report 2>&1
        echo "[[조치방법]] /etc/named.conf 파일에 allow-transfer을 Secondary Name Server의 ip만으로 제한하세요.">> $report 2>&1
    else 
        echo "[양호] Zone Transfer가 특정 사용자로 제한되어있습니다.">> $report 2>&1
       
    fi
else
    echo "[기타] dns 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi



# - Remove directory listing from web services: High U-35

echo " " >> $report 2>&1
echo "----Remove directory listing from web services: High U-35----" >> $report 2>&1

if find / \( -name "apache2.conf" -o -name "httpd.conf" \) 2>/dev/null | xargs grep -i options |grep -i "indexes"| grep -v "^#" |grep -ivq "-indexes"
then 
    echo "[취약] apache의 디렉터리 검색기능이 활성화 되어있습니다" >> $report 2>&1
    echo "[[조치방법]] apache 구성파일에서 options 부분에 -Indexes를 추가하세요." >> $report 2>&1
else
    echo "[양호] apache의 디렉터리 검색기능이 활성화 되어있지 않습니다." >> $report 2>&1
fi

    

# - Limit web service process permissions: High U-36

echo " " >> $report 2>&1
echo "----Limit web service process permissions: High U-36----" >> $report 2>&1

if find / \( -name "apache2.conf" -o -name "httpd.conf" \) 2>/dev/null | xargs grep -i user |grep -iq root
then 
    echo "[취약] user-> apache 데몬 구동 권한이 루트로 설정되어있습니다. " >> $report 2>&1
    echo "[[조치방법]] apache 구성파일에서 User 부분을 루트 아닌 다른 계정으로 설정하세요. " >> $report 2>&1
else
    echo "[양호]  user-> apache 데몬 구동 권한이 루트가 아닌 다른 계정으로 설정설정한 후 apache 를 재시작하세요." >> $report 2>&1
fi

if find / \( -name "apache2.conf" -o -name "httpd.conf" \) 2>/dev/null | xargs grep -i group |grep -iq root
then 
    echo "[취약] group-> apache 데몬 구동 권한이 루트로 설정되어있습니다. " >> $report 2>&1
    echo "[[조치방법]] apache 구성파일에서 User 부분을 루트 아닌 다른 계정으로 설정한 후 apache 를 재시작하세요. " >> $report 2>&1
else
    echo "[양호] group-> apache 데몬 구동 권한이 루트가 아닌 다른 계정으로 설정되어있습니다." >> $report 2>&1
fi


# - Prohibit access to web service's upper directories: High U-37

echo " " >> $report 2>&1
echo "----Prohibit access to web service's upper directories: High U-37----" >> $report 2>&1


if find / \( -name "apache2.conf" -o -name "httpd.conf" \) 2>/dev/null | xargs grep -i AllowOverride |grep -i None | grep -vq "^#"
then 
    echo "[취약] apache 구성파일에 상위 디렉토리 접근이 허용되어있습니다. " >> $report 2>&1
    echo "[[조치방법]] apache 구성파일에서 AllowOverride 부분을 AuthConfig 로 수정한 후 사용자 인증을 설정할 디렉토리에 .htaccess 파일을 생성하여 설정하세요 " >> $report 2>&1
else
    echo "[양호] apache 구성파일에 상위 디렉토리 접근이 허용되어있지 않습니다." >> $report 2>&1
fi



# - Remove unnecessary files from web services: High U-38

echo " " >> $report 2>&1
echo "----Remove unnecessary files from web services: High U-38----" >> $report 2>&1

u_38_dir_path=$(dirname $(find / \( -name "apache2.conf" -o -name "httpd.conf" 2>/dev/null \) -print -quit))

if find $u_38_dir_path -name "manual" 2>/dev/null | grep -q .
then 
    echo "[취약] apache 에 불필요한 파일이나 디렉토리가 제거 되지 않았습니다." >> $report 2>&1
    echo "[[조치방법]] 다음과 같은 파일을 제거 하세요. $(find $u_38_dir_path -name "manual" 2>/dev/null ) " >> $report 2>&1
else
    echo "[양호] apache에 manual 관련 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Prohibit the use of links in web services: High U-39

echo " " >> $report 2>&1
echo "----Prohibit the use of links in web services: High U-39----" >> $report 2>&1

if find / \( -name "apache2.conf" -o -name "httpd.conf" \) 2>/dev/null | xargs grep -i options |grep -i FollowSymLinks| grep -v "^#"| grep -iqv "-FollowSymLinks"
then 
    echo "[취약] apache의 심볼릭 링크 설정이 활성화 되어있습니다" >> $report 2>&1
    echo "[[조치방법]] apache 구성파일에서 options 부분에 FollowSymLinks를 삭제하거나 - 를 앞에 추가하세요." >> $report 2>&1
else
    echo "[양호] apache의 심볼릭 링크 설정이 활성화 되어있지 않습니다." >> $report 2>&1
fi



# - Limit file upload and download in web services: High U-40

echo " " >> $report 2>&1
echo "----Limit file upload and download in web services: High U-40----" >> $report 2>&1



if find / \( -name "apache2.conf" -o -name "httpd.conf" \) 2>/dev/null | xargs grep -i LimitRequestBody| grep -v "^#"
then 
    echo "[취약] apache의 심볼릭 링크 설정이 활성화 되어있습니다" >> $report 2>&1
    echo "[[조치방법]] apache 구성파일에서 options 부분에 FollowSymLinks를 삭제하거나 - 를 앞에 추가하세요." >> $report 2>&1
else
    echo "[양호] apache의 심볼릭 링크 설정이 활성화 되어있지 않습니다." >> $report 2>&1
fi


# - Segregate web service areas: High U-41

echo " " >> $report 2>&1
echo "----Segregate web service areas: High U-41----" >> $report 2>&1

u_41_chk_arr=(
    "/usr/local/apache/htdocs"
    "/usr/local/apache2/htdocs"
    "/var/www/html"
)

u_41_documentroot=$(find / \( -name "apache2.conf" -o -name "htpd.conf" \) 2>/dev/null | xargs grep -i documentroot)
u_41_vuln=0

if [ -n $u_41_documentroot ]
then 
    echo "[취약] 아파치의 루트 디렉터리가 기본값으로 설정되어있습니다.">> $report 2>&1
    echo "[[조치방법]] apache 구성파일에서 DocumentRoot 부분에 /www 와 같이 별도의 디렉터리를 생성하여 설정하세요. ">> $report 2>&1
     u_41_vuln=1
else   
    for i in "${u_41_chk_arr[@]}"
    do  
        if grep -iq $i $u_41_documentroot 
        then 
            echo "[취약] 아파치의 루트 디렉터리가 기본값으로 설정되어있습니다.">> $report 2>&1
            echo "[[조치방법]] apache 구성파일에서 DocumentRoot 부분에 /www 와 같이 별도의 디렉터리를 생성하여 설정하세요. ">> $report 2>&1
            u_41_vuln=1
        fi
    done
fi

if [ $u_41_vuln == 0 ]
then 
    echo "[양호] 아파치의 루트 디렉터리가 별도의 디렉터리로 설정되어있습니다.">> $report 2>&1
fi

# - Apply the latest security patches and vendor recommendations: High U-42

echo " " >> $report 2>&1
echo "----Apply the latest security patches and vendor recommendations: High U-42----" >> $report 2>&1

echo "수동 점검이 필요한 부분입니다. 아래와 같은 항목을 확인하세요" >> $report 2>&1

echo " 1) 패치 적용 정책을 수립하여 주기적으로 패치관리를 하고 있는지 여부" >> $report 2>&1
echo " 2) 패치 관련 내용을 확인하고 적용했는지 여부">> $report 2>&1

# - Regularly review and report logs: High U-43

echo " " >> $report 2>&1
echo "----Regularly review and report logs: High U-43----" >> $report 2>&1

echo "수동 점검이 필요한 부분입니다. 아래와 같은 항목을 확인하세요" >> $report 2>&1

echo " 접속기록 등의 보안 로그, 응용 프로그램 및 시스템 로그 기록에 대해 정기 적으로 검토, 분석, 리포트 작성 및 보고 등의 조치 여부"  >> $report 2>&1


# - Prohibit UIDs of '0' other than root: Medium U-44

echo " " >> $report 2>&1
echo "----Prohibit UIDs of '0' other than root: Medium U-44----" >> $report 2>&1

if [ -f /etc/passwd ]
then
    if grep -v root /etc/passwd | awk -F: '$3 == 0 {exit 1}' 
    then
        echo "[취약] root 가 아닌 다른 유저의 uid 가 0 으로 설정되어있습니다." >> $report 2>&1
        echo "[[조치방안]] 0 으로 설정된 유저의 uid 를 다른 uid 로 변경하세요" >> $report 2>&1
    else
        echo "[양호] root 가 아닌 다른 유저의 uid 중 0 으로 설정된 것이 존재하지 않습니다." >> $report 2>&1
    fi
else
    echo "[기타] /etc/passwd 파일이 존재하지 않습니다."  >> $report 2>&1
fi        

#### - Restrict root account's use of su: Low U-45  here

echo " " >> $report 2>&1
echo "----Restrict root account's use of su: Low U-45----" >> $report 2>&1



# - Set minimum password length: Medium U-46

echo " " >> $report 2>&1
echo "----Set minimum password length: Medium U-46----" >> $report 2>&1

if [ -f /etc/login.defs ]
then
    u_46_output=$(grep -i pass_min_len /etc/login.defs | grep -v '^#'| awk '{print $2}')
    if  [ ! -z $u_46_output ]
    then 
        if [ $u_46_output -lt 8 ]
        then 
            echo "[취약] 비밀번호 글자수 설정이 8 미만으로 되어있습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/lgoin.defs 파일에서 비밀번호 글자수 설정을 8이상으로 설정하고 주석을 제거하세요." >> $report 2>&1

        else
            echo "[양호] 비밀번호 글자수 설정이 8 이상으로 되어있습니다." >> $report 2>&1
        fi
    else
        echo "[취약] 비밀번호 글자수 설정이 존재하지 않습니다." >> $report 2>&1
        echo "[[조치방법]] /etc/lgoin.defs 파일에서 비밀번호 글자수 설정을 8이상으로 설정하고 주석을 제거하세요." >> $report 2>&1


    fi
else 
    echo "[기타] /etc/login.defs 파일이 존재하지 않습니다."  >> $report 2>&1

fi

# - Set maximum password lifetime: Medium U-47

echo " " >> $report 2>&1
echo "----Set maximum password lifetime: Medium U-47----" >> $report 2>&1

if [ -f /etc/login.defs ]
then
    u_47_output=$(grep -i pass_max_days /etc/login.defs | grep -v '^#'| awk '{print $2}')
    if [ ! -z $u_47_output ]
    then
        if [ $u_47_output > 90 ]
        then 
            echo "[취약] 비밀번호 최대 사용기간이 91일 이상으로 설정 되어있습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/lgoin.defs 파일에서 PASS_MAX_DAYS 부분을 90으로 설정하고 주석을 제거하세요." >> $report 2>&1

        else
            echo "[양호] 비밀번호 최대 사용기간이 90일 이하로 설정 되어있습니다." >> $report 2>&1
        fi
    else
        echo "[취약] 비밀번호 최대 사용기간 설정이 존재하지 않습니다." >> $report 2>&1
        echo "[[조치방법]] /etc/lgoin.defs 파일에서 PASS_MAX_DAYS 부분을 90으로 설정하고 주석을 제거하세요." >> $report 2>&1

    fi
else 
    echo "[기타] /etc/login.defs 파일이 존재하지 않습니다."  >> $report 2>&1

fi

# - Set minimum password lifetime: Medium U-48


echo " " >> $report 2>&1
echo "----Set minimum password lifetime: Medium U-48----" >> $report 2>&1

if [ -f /etc/login.defs ]
then
    u_48_output=$(awk '/PASS_MIN_DAYS/ && !/^#/ {print $2}' /etc/login.defs)
    if [ ! -z $u_48_output ]
    then
        if [ $u_48_output -ge 1 ]
        then 
            echo "[양호] 비밀번호 최소 사용기간이 1일 이상으로 설정 되어있습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/lgoin.defs 파일에서 PASS_MIN_DAYS 부분을 1 이상으로 설정하고 주석을 제거하세요." >> $report 2>&1

        else
            echo "[취약] 비밀번호 최소 사용기간이 1일 미만으로 설정 되어있습니다." >> $report 2>&1
        fi
    else
         echo "[취약] 비밀번호 최소 사용기간이 설정되어있지 않습니다." >> $report 2>&1
         echo "[[조치방법]] /etc/lgoin.defs 파일에서 PASS_MIN_DAYS 부분을 1 이상으로 설정하고 주석을 제거하세요." >> $report 2>&1

    fi
else 
    echo "[기타] /etc/login.defs 파일이 존재하지 않습니다."  >> $report 2>&1

fi

# - Removal of unnecessary accounts: Low U-49

echo " " >> $report 2>&1
echo "----Removal of unnecessary accounts: Low U-49----" >> $report 2>&1

if [ -f /etc/passwd ]
then    
    echo "[중요] 로그인 가능한 계정은 다음과 같습니다. lp, uucp, nuucp와 같은 default 계정과 불필요한 계정은 제거하세요.  ">> $report 2>&1
    echo "$( grep -v '^#' /etc/passwd )">> $report 2>&1
else
    echo "[기타] /etc/passwd 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Include a minimal number of accounts in the admin group: Low U-50

echo " " >> $report 2>&1
echo "----Include a minimal number of accounts in the admin group: Low U-50----" >> $report 2>&1

if [ -f /etc/group ]
then
    if grep -v '^#' /etc/group | grep -i '^root' | awk -F: '{print $4}'
    then 
        echo "[중요] $( grep -v '^#' /etc/group | grep -i '^root' | awk -F: '{print $4}') 해당 그룹에 관리자가 아닌 유저가 있다면, 삭제하세요">> $report 2>&1
    else
        echo "[양호] 관리자 그룹에 불필요한 계정이 존재하지 않습니다.">> $report 2>&1
    fi
else
    echo "[기타] /etc/grpup 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Prohibit GIDs without accounts: Low U-51

echo " " >> $report 2>&1
echo "----Prohibit GIDs without accounts: Low U-51----" >> $report 2>&1

if [ -f /etc/group ]
then
    if [ $( grep -v '^#' /etc/group |  awk -F: '$3 >= 500 {print}' | wc -l ) -gt 0 ]    
    then 
        echo "[중요] group 에 gid 가 500 이상인 계정은 다음과 같습니다. 불필요한 계정은 제거하세요  ">> $report 2>&1
        echo "$( grep -v '^#' /etc/group |  awk -F: '$3 >= 500 {print}' )">> $report 2>&1
    else
        echo "[양호] 그룹에 불필요한 계정이 존재하지 않습니다.">> $report 2>&1
    fi
else
    echo "[기타] /etc/grpup 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Prohibit identical UIDs: Medium U-52

echo " " >> $report 2>&1
echo "----Prohibit identical UIDs: Medium U-52----" >> $report 2>&1

if [ -f /etc/passwd ]
then    
   if awk -F: '{print $3}' /etc/passwd | sort | uniq -d | grep -q .
   then 
        echo "[취약] 중복된 uid 를 사용하는 계정이 존재합니다. " >> $report 2>&1
    else 
        echo "[양호] 중복된 uid 를 사용하는 계정이 존재하지 않습니다. " >> $report 2>&1
    fi
else
    echo "[기타] /etc/passwd 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Check user shells: Low U-53

echo " " >> $report 2>&1
echo "----Check user shells: Low U-53----" >> $report 2>&1

if [ -f /etc/passwd ]
then
    if cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" | grep -v "admin" | grep -vq nologin
    then
        echo "[양호] 로그인이 불필요한 계정에 쉘이 부여되어있지 않습니다. " >> $report 2>&1
        else 
            echo "[취약] 로그인이 불필요한 계정에 쉘이 부여되어 있습니다.">> $report 2>&1
            echo "[[조치방법]] 아래의 계정에 /sbin/nologin로 변경하세요 " >> $report 2>&1
            echo "$(if cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" | grep -v "admin" | grep -v nologin)">> $report 2>&1
        fi
else
    echo "[기타] /etc/passwd 파일이 존재하지 않습니다." >> $report 2>&1
fi



# - Set Session Timeout: Low U-54

echo " " >> $report 2>&1
echo "----Set Session Timeout: Low U-54---" >> $report 2>&1

if [ -f /etc/profile ]
then 
    u_54_output=$(awk -F= '/TMOUT/ && !/^#/ {print $2}' /etc/profile)
    if [ ! -z $u_54_output ] && [ $u_54_output -ge 600 ]
    then 
        echo "[양호] session timeout 이 600 초 이상으로 설정되어있습니다." >> $report 2>&1
    else
        echo "[취약] /etc/profile 파일의 session timeout 이 600 초 이하로 설정되어있습니다." >> $report 2>&1
        echo "[[조치방법]] /etc/profile 파일의 TMOUT 설정을 600 이상으로 설정하세요." >> $report 2>&1
    fi
else
    echo "[기타] /etc/profile 파일이 존재하지 않습니다." >> $report 2>&1
fi


find / -name ".profile" -print0 | while IFS= read -r -d '' u_54_file
do
    u_54_output=$(awk -F= '/TMOUT/ && !/^#/ {print $2}' "$u_54_file")
    if [ ! -z $u_54_output ] && [ $u_54_output -ge 600 ]
    then
        echo "[양호] $u_54_file 파일의 session timeout 이 600 초 이상으로 설정되어있습니다." >> $report 2>&1
    else
        echo "[취약] $u_54_file 파일의 session timeout 이 600 초 이하로 설정되어있습니다." >> $report 2>&1
        echo "[[조치방법]] $u_54_file 파일의 TMOUT 설정을 600 이상으로 설정하세요." >> $report 2>&1
    fi
done

if [ -f /etc/csh.login ]
then 
    u_54_output=$(awk -F= '/autologout/ && !/^#/ {print $2}' /etc/csh.login)
    if [ ! -z $u_54_output ] && [ $u_54_output -lt 10 ]
    then 
        echo "[취약]/etc/csh.login의 session timeout 이 600 초 이하로 설정되어있습니다." >> $report 2>&1
        echo "[[조치방법]] /etc/csh.login에서 TMOUT 설정을 600 이상으로 설정하세요." >> $report 2>&1
    else
        echo "[양호]/etc/csh.login의 session timeout 이 600 초 이상으로 설정되어있습니다." >> $report 2>&1
    fi
else
    echo "[기타]/etc/csh.login 파일이 존재하지 않습니다." >> $report 2>&1
fi


if [ -f /etc/csh.cshrc ]
then 
    u_54_output=$(awk -F= '/autologout/ && !/^#/ {print $2}' /etc/csh.cshrc)
    if [ ! -z $u_54_output ] && [ $u_54_output -lt 10 ]
    then 
        echo "[취약]/etc/csh.cshrc의 session timeout 이 600 초 이하로 설정되어있습니다." >> $report 2>&1
        echo "[[조치방법]] /etc/csh.cshrc에서 TMOUT 설정을 600 이상으로 설정하세요." >> $report 2>&1
    else
        echo "[양호]/etc/csh.cshrc의 session timeout 이 600 초 이상으로 설정되어있습니다." >> $report 2>&1
    fi
else
    echo "[기타]/etc/csh.cshrc 파일이 존재하지 않습니다." >> $report 2>&1
fi

# - Set owner and permissions for hosts.lpd file: Low U-55

echo " " >> $report 2>&1
echo "----Set owner and permissions for hosts.lpd file: Low U-55---" >> $report 2>&1

u_55_vuln=0
if [ -f /etc/hosts.lpd ]
then
     if [ $(ls -l /etc/hosts.lpd | awk '{print $3}') != 'root' ]
        then 
            echo "[취약] /etc/hosts.lpd 파일의 소유주가 root 가 아닙니다.">> $report 2>&1
            echo "[[조치방법]] chown root /etc/hosts.lpd 명령어를 실행하세요">> $report 2>&1
            u_55_vuln=1
        fi

        if [ $(stat -c "%a" /etc/hosts.lpd) -gt 600 ]
        then 
            echo "[취약] /etc/hosts.lpd 파일의 권한이 600 이상입니다.">> $report 2>&1
            echo "[[조치방법]] chmod 600 /etc/hosts.lpd 명령어를 실행하세요">> $report 2>&1
            u_55_vuln=1
        fi
else
    echo "[양호] /etc/hosts.lpd 파일이 존재하지 않습니다.">> $report 2>&1
fi
 
if [ $u_55_vuln -eq 0 ]
then 
    echo "[양호] /etc/hosts.lpd 파일이 존재하지만 보안설정이 양호하게 적용되어있습니다.">> $report 2>&1
fi


# - Manage UMASK settings: Medium U-56

echo " " >> $report 2>&1
echo "----Manage UMASK settings: Medium U-56---" >> $report 2>&1

if [ -f /etc/profile ]
then 
    u_56_output=$(awk -F= '/UMASK/ && !/^#/ {print $2}' /etc/profile)
    if [ ! -z $u_56_output ] && [ $u_56_output -ge 022 ]
    then 
        echo "[양호] UMASK 가 022 이상으로 설정되어있습니다." >> $report 2>&1
    else
        echo "[취약] /etc/profile 파일의UMASK 가 022 미만으로 설정되어있습니다." >> $report 2>&1
        echo "[[조치방법]] /etc/profile 파일의 TUMASK 설정을 022 이상으로 설정하세요." >> $report 2>&1
    fi
else
    echo "[기타] /etc/profile 파일이 존재하지 않습니다." >> $report 2>&1
fi


# - Set owner and permissions for home directories: Medium U-57

echo " " >> $report 2>&1
echo "----Set owner and permissions for home directories: Medium U-57---" >> $report 2>&1


u_57_path="/home/*"
u_57_vuln=0

for p in $u_57_path
do
    u_57_perm=$(ls -l $p| awk '{print $1}')
    u_57_usr=$(ls -l $p | awk '{print $3}')

    if [ "$u_57_usr" != $(basename "$p") ]
    then
        echo "[취약] $p 의 소유자가 계정주가 아닙니다.">> $report 2>&1
        echo "[[조치방법]] 'chown {username} $p' 명령어를 통해 소유자를 변경하세요 .">> $report 2>&1
        u_57_vuln=1
    fi

    if [[ $u_57_perm =~ ^.....w  || $u_57_perm =~ ^.......w ]]
    then
        echo "[취약] $p 파일 소유자 외 쓰기가 허용되어있습니다.">> $report 2>&1
        echo "[[조치방법]] 'chmod o-w $p' 명려어를 통해 파일 쓰기권한을 제거하세요 .">> $report 2>&1
        u_57_vuln=1
    fi
done

if [ $u_57_vuln -eq 0 ] 
then
    echo "[양호] 모든 홈 디렉터리의 소유가 계정주로 되어있으며 소유주만 쓰기가 가능합니다.">> $report 2>&1
fi


# - Manage the existence of directories designated as home directories: Medium U-58

echo " " >> $report 2>&1
echo "----Manage the existence of directories designated as home directories: Medium U-58---" >> $report 2>&1

if [ -f /etc/passwd ]
then
    if [ $(awk -F: '($3 >= 1000 && $6 != "/")' /etc/passwd | wc -l ) -gt 0 ]
    then 
        echo "[취약] 홈 디렉터리가 설정되지 않은 계정이 존재합니다.">> $report 2>&1
        echo "[[조치방법]] /etc/passwd 파일을 수정해 홈 디렉터리가 설정되어 있지 않은 계정에 새로운 홈 디렉터리를 설정하세요.">> $report 2>&1

    else
        echo "[양호] 홈 디렉터리가 설정되지 않은 계정이 존재하지 않습니다.">> $report 2>&1  
    fi
else
    echo "[기타] /etc/passwd 파일이 존재하지 않습니다.">> $report 2>&1  
fi

# - Search for and remove hidden files and directories: Low U-59

echo " " >> $report 2>&1
echo "----Search for and remove hidden files and directories: Low U-59---" >> $report 2>&1

echo "[중요] 아래의 파일 중에 불필요한 파일이 있는지 점검하세요">> $report 2>&1  
echo "$(find / -type f -name '.*')">> $report 2>&1  
echo " " >> $report 2>&1  
echo "[중요] 아래의 디렉토리 중에 불필요한 디렉토리가 있는지 점검하세요">> $report 2>&1  
echo "$(find / -type d -name '.*')">> $report 2>&1  

# - Allow remote SSH access: Medium U-60

echo " " >> $report 2>&1
echo "----Allow remote SSH access: Medium U-60---" >> $report 2>&1

if ps aux | grep -v grep | grep -q sshd 
then
    if dpkg -l telnet | grep -q '^i'
    then    
        echo "[취약] telnet 이 설치되어있습니다. ">> $report 2>&1
        echo "[[조치방법]] sudo apt-get purge telnet 명령어를 사용하여 telnet 을 제거하세요. ">> $report 2>&1
    else 
        echo "[양호] telnet 이 설치되어있지 않습니다.">> $report 2>&1
    fi

    if dpkg -l ftp | grep -q '^i'
    then    
        echo "[취약] ftp 가 설치되어있습니다. ">> $report 2>&1
        echo "[[조치방법]] sudo apt-get purge ftp 명령어를 사용하여 ftp를 제거하세요. ">> $report 2>&1
    else 
        echo "[양호] ftp가 설치되어있지 않습니다.">> $report 2>&1
    fi
else 
    echo "[양호] ssh 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi

# - Check FTP service: Low U-61

echo " " >> $report 2>&1
echo "----Check FTP service: Low U-61---" >> $report 2>&1

if ps aux | grep -v grep | grep -q ftp 
then
    echo "[취약] ftp 가 활성화 되어있습니다. ">> $report 2>&1
    echo "[[조치방법]] kill 명령어를 사용하여 ftp를 비활성화하세요. ">> $report 2>&1

else 
    echo "[양호] ftp 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi

if ps aux | grep -v grep | grep -q ftp 
then
    echo "[취약] ftp 가 활성화 되어있습니다. ">> $report 2>&1
    echo "[[조치방법]] kill 명령어를 사용하여 ftp를 비활성화하세요. ">> $report 2>&1

else 
    echo "[양호] ftp 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi

if ps aux | grep -v grep | grep -q vsftpd
then
    echo "[취약] vsftpd 가 활성화 되어있습니다. ">> $report 2>&1
    echo "[[조치방법]] kill 명령어를 사용하여 vsftpd를 비활성화하세요. ">> $report 2>&1

else 
    echo "[양호] vsftpd 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi

if ps aux | grep -v grep | grep -q proftpd
then
    echo "[취약] proftpd 가 활성화 되어있습니다. ">> $report 2>&1
    echo "[[조치방법]] kill 명령어를 사용하여 proftpd를 비활성화하세요. ">> $report 2>&1

else 
    echo "[양호] proftpd 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi

# - Limit shell access for FTP accounts: Medium U-62

echo " " >> $report 2>&1
echo "----Limit shell access for FTP accounts: Medium U-62---" >> $report 2>&1

if [ -f /etc/passwd ]
then
    u_62_output=$(grep -i ftp /etc/passwd | awk -F: '{print $7}')
    if [ ! -z $u_62_output ] && [ $u_62_output != '/bin/false' ]  
    then
        echo "[취약] ftp 계정에 /bin/false 쉘이 설정되어있지 않습니다." >> $report 2>&1
        echo "[[조치방안]] /etc/passwd 파일에서 ftp 계정의 쉘을 /bin/false로 변경하세요." >> $report 2>&1
    else
        echo "[양호] ftp 계정에 /bin/false 쉘이 설정되어 있습니다." >> $report 2>&1
    fi
else
    echo "[기타] /etc/passwd 파일이 존재하지 않습니다."  >> $report 2>&1
fi      

# - Set owner and permissions for Ftpusers file: Low U-63

echo " " >> $report 2>&1
echo "----Set owner and permissions for Ftpusers file: Low U-63---" >> $report 2>&1

if ps aux | grep -v grep | grep -q ftp 

u_63_chk=0
u_63_file_arr=(
    "/etc/ftpusers" 
    "/etc/ftpd/ftpusers" 
    "/etc/vsftpd/ftpusers" 
    "/etc/vsftpd/user_list" 
    "/etc/vsftpd/user_list" 
    "/etc/vsftpd.ftpusers" 
    "/etc/vsftpd.ftpusers" 
    "/etc/vsftpd.user_list")

for i in "${u_13_file_arr[@]}"
do
    if [ -f $i ]
    then
        u_63_chk=2
        u_63_perm=$(ls -l $i| awk '{print $1}')
        u_63_usr=$(ls -l $i | awk '{print $3}')

        if [ "$u_63_usr" != 'root' ]
        then
            echo "[취약] $i 의 소유자가 root가 아닙니다.">> $report 2>&1
            echo "[[조치방법]] 'chown root $i' 명령어를 통해 소유자를 변경하세요 .">> $report 2>&1
            u_63_chk=1
        fi

        if [ $(stat -c "%a" $i) -lt 640 ]
        then
            echo "[취약] $i 파일의 권한이 640 보다 큽니다.">> $report 2>&1
            echo "[[조치방법]] 'chmod 640 $i' 명령어를 통해 권한을 설정하세요.">> $report 2>&1
            u_63_chk=1
        fi

        if [ u_63_chk -eq 2 ]
        then 
            echo "[양호] $i 파일의 권한이 640 이하고 소유주가 root로 설정되어있습니다 "  >> $report 2>&1
        fi
    fi
done

if [ u_63_chk -eq 0 ]
then 
    echo "[기타] 관련 파일이 존재하지 않습니다. "  >> $report 2>&1
fi

# - Configure Ftpusers file: Medium U-64     here
echo " " >> $report 2>&1
echo "----Configure Ftpusers file: Medium U-64---" >> $report 2>&1




# - Set owner and permissions for at files: Medium U-65    here
echo " " >> $report 2>&1
echo "----Set owner and permissions for at files: Medium U-65---" >> $report 2>&1


if [ -f /etc/at.allow ]
then 
    if grep -i "servertokens.*prod" /etc/at.allow | grep -vq '^#'
    then 
      ###########
    else
        echo "[취약] apache 설정파일에 ServerTokens 가 prod로 설정되어있지 않습니다." >> $report 2>&1
        echo "[[조치방법]] apache 구성파일에서 ServerTokens를 prod로 설정하고 ServerSignature 부분을 off로 설정하세요." >> $report 2>&1
    fi
else
    echo "[기타] apache 설정파일이 존재하지 않습니다." >> $report 2>&1
fi



# - Check for running SNMP services: Medium U-66

echo " " >> $report 2>&1
echo "----Check for running SNMP services: Medium U-66---" >> $report 2>&1

if ps aux | grep -v grep | grep -q snmp 
then
    echo "[취약] snmp 가 활성화 되어있습니다. ">> $report 2>&1
    echo "[[조치방법]] kill 명령어를 사용하여 snmp를 비활성화하세요. ">> $report 2>&1

else 
    echo "[양호] snmp 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi

if ps aux | grep -v grep | grep -q snmp 
then
    echo "[취약] snmp 가 활성화 되어있습니다. ">> $report 2>&1
    echo "[[조치방법]] snmp 서비스를 비활성화하세요. ">> $report 2>&1

else 
    echo "[양호] snmp 서비스가 비활성화 되어있습니다.">> $report 2>&1
fi



# - Set complexity for SNMP service community strings: Medium U-67
echo " " >> $report 2>&1
echo "----Set complexity for SNMP service community strings: Medium U-67---" >> $report 2>&1


if [ -f /etc/snmp/snmpd.conf ]
then 
    u_67_output=$(awk '/com2sec/ && /notConfigUser/ {print $4}' /etc/snmp/snmpd.conf)

    if [[ "$u_67_output" == "public" || "$u_67_output" == "private" ]]    
    then 
        echo "[취약] snmp community 의 이름이 public, private 로 설정되어있습니다.">> $report 2>&1
        echo "[[조치방법]] com2sec notConfigUser default 부분을 public, private 외에 다른 이름으로 대체하고 서비스를 재시작하세요.">> $report 2>&1

    else
        echo "[양호] snmp community 의 이름이 public, private 외에 다른 것으로 설정되어있습니다.">> $report 2>&1
    fi
else
    echo "[기타] /etc/snmp/snmpd.conf 파일이 존재하지 않습니다. ">> $report 2>&1
fi




# - Provide login warning message: Low U-68
echo " " >> $report 2>&1
echo "----Provide login warning message: Low U-68---" >> $report 2>&1

if [ -f /etc/motd ]
then
    if grep -v '^#' /etc/motd | grep -q .
    then 
        echo "[양호] /etc/motd 에 메세지가 설정되어있습니다.">> $report 2>&1
    else 
        echo "[취약] /etc/motd 에 메세지가 설정되어있지 않습니다.">> $report 2>&1
    fi 
else
    echo "[취약] /etc/motd 파일이 존재하지 않습니다.">> $report 2>&1
fi

if ps aux | grep -v grep | grep -q telnet
then
    if [ -f /etc/issue.net ]
    then
        if grep -v '^#' /etc/issue.net
        then 
            echo "[양호] /etc/issue.net 에 메세지가 설정되어있습니다.">> $report 2>&1
        else 
            echo "[취약] /etc/issue.net 에 메세지가 설정되어있지 않습니다.">> $report 2>&1
        fi 
    else
        echo "[취약] telnet이 실행중이지만 /etc/issue.net 파일이 존재하지 않습니다.">> $report 2>&1
    fi
fi

if ps aux | grep -v grep | grep -q ftp
then
    if [ -f /etc/vsftpd/vsftpd.conf ]
    then
        if grep -v '^#' /etc/vsftpd/vsftpd.conf  | grep -i ftpd_banner |awk -F= '{print $2}' | grep -q . 
        then 
            echo "[양호] /etc/vsftpd/vsftpd.conf 에 메세지가 설정되어있습니다.">> $report 2>&1
        else 
            echo "[취약] /etc/vsftpd/vsftpd.conf 에 메세지가 설정되어있지 않습니다.">> $report 2>&1
        fi 
    else
        echo "[취약] ftp가 실행중이지만  /etc/vsftpd/vsftpd.conf 파일이 존재하지 않습니다.">> $report 2>&1
    fi
    if [ -f /etc/proftpd/proftpd.conf ]
    then
        if grep -v '^#' /etc/proftpd/proftpd.conf | grep -i ServerIdent | awk -F= '{print $2}' | grep -q . 
        then 
            echo "[양호] /etc/proftpd/proftpd.conf 에 메세지가 설정되어있습니다.">> $report 2>&1
        else 
            echo "[취약] /etc/proftpd/proftpd.conf 에 메세지가 설정되어있지 않습니다.">> $report 2>&1
        fi 
    else
        echo "[취약] ftp가 실행중이지만  /etc/proftpd/proftpd.conf 파일이 존재하지 않습니다.">> $report 2>&1
    fi
fi

if ps aux | grep -v grep | grep -q smtp
then
    if [ -f /etc/mail/sendmail.cf ]
    then
        if grep -v '^#' /etc/mail/sendmail.cf | grep -i SmtpGreetingMessage |awk -F= '{print $2}' | grep -q . 
        then 
            echo "[양호] /etc/mail/sendmail.cf 에 메세지가 설정되어있습니다." >> $report 2>&1
        else 
            echo "[취약] /etc/mail/sendmail.cf 에 메세지가 설정되어있지 않습니다." >> $report 2>&1
        fi 
    else
        echo "[취약] smtp가 실행중이지만 /etc/mail/sendmail.cf 파일이 존재하지 않습니다." >> $report 2>&1
    fi
fi

if ps aux | grep -v grep | grep -q named
then
    if [ -f /etc/named.conf ]
    then
        if grep -v '^#' /etc/named.conf 
        then 
            echo "[양호] /etc/named.conf 에 메세지가 설정되어있습니다." >> $report 2>&1
        else 
            echo "[취약] /etc/named.conf 에 메세지가 설정되어있지 않습니다." >> $report 2>&1
        fi 
    else
        echo "[취약] smtp가 실행중이지만 /etc/named.conf 파일이 존재하지 않습니다." >> $report 2>&1
    fi
fi


# - Restrict access to NFS configuration files: Medium U-69
echo " " >> $report 2>&1
echo "----Restrict access to NFS configuration files: Medium U-69---" >> $report 2>&1

if [ -f /etc/exports ]
then
    u_68_perm=$(ls -l /etc/exports| awk '{print $1}')
    u_68_usr=$(ls -l /etc/exports | awk '{print $3}')

    if [ $u_68_usr != 'root' ]
    then
        echo "[취약] /etc/exports 의 소유자가 root가 아닙니다." >> $report 2>&1
        echo "[[조치방법]] 'chown root /etc/exports' 명령어를 통해 소유자를 변경하세요 ." >> $report 2>&1

    fi

    if [ $(stat -c "%a" /etc/exports) -lt 640 ]
    then
        echo "[취약] /etc/exports 파일의 권한이 640 보다 큽니다.">> $report 2>&1
        echo "[[조치방법]] 'chmod 640 /etc/exports' 명령어를 통해 권한을 설정하세요.">> $report 2>&1
   
    fi
else
    echo "[기타] 관련 파일이 존재하지 않습니다. "  >> $report 2>&1
   
fi


# - Limit expn, vrfy commands: Medium U-70
echo " " >> $report 2>&1
echo "----Limit expn, vrfy commands: Medium U-70---" >> $report 2>&1

if [ -f /etc/mail/sendmail.cf]
then 
    if grep -iq PrivacyOptions /etc/mail/sendmail.cf | grep -i noexpn | grep -i novrfy 
    then 
        echo "[양호] snmp community 의 이름이 public, private 외에 다른 것으로 설정되어있습니다."
    else
        echo "[취약] snmp community 의 이름이 public, private 로 설정되어있습니다."
        echo "[[조치방법]] com2sec notConfigUser default 부분을 public, private 외에 다른 이름으로 대체하고 서비스를 재시작하세요."

    fi
else
    echo "[기타] /etc/snmp/snmpd.conf 파일이 존재하지 않습니다. "
fi


# - Hide Apache web service information: Medium U-71
echo " " >> $report 2>&1
echo "----Hide Apache web service information: Medium U-71---" >> $report 2>&1


u_70_file_path=$(find / \( -name "apache2.conf" -o -name "httpd.conf" \) 2>/dev/null)

if [ -f u_70_file_path ]
then 
    if grep -iq "servertokens.*prod" $u_70_file_path | grep -v '^#'
    then 
        if grep -iq "serversigniture.*off" $u_70_file_path | grep -v '^#'
        then 
            echo "[양호] apache 설정파일에 ServerTokens Prod, ServerSignature Off가 설정되어있습니다. " >> $report 2>&1

        else
            echo "[취약] apache 설정파일에 ServerSignature Off가 설정되어있지 않습니다." >> $report 2>&1
            echo "[[조치방법]] apache 구성파일에서  apache 설정파일에 ServerSignature 부분을 off로 설정하세요." >> $report 2>&1
        fi
    else
        echo "[취약] apache 설정파일에 ServerTokens 가 prod로 설정되어있지 않습니다." >> $report 2>&1
        echo "[[조치방법]] apache 구성파일에서 ServerTokens를 prod로 설정하고 ServerSignature 부분을 off로 설정하세요." >> $report 2>&1
    fi
else
    echo "[기타] apache 설정파일이 존재하지 않습니다." >> $report 2>&1
fi



# - Set system logging according to policy: Low U-72 
echo " " >> $report 2>&1
echo "----Set system logging according to policy: Low U-72---" >> $report 2>&1

echo "수동 점검이 필요한 부분입니다. 아래와 같은 항목을 확인하세요" >> $report 2>&1

echo " 1) 로그 기록 정책이 정책에 따라 설정되어 수립되어 있는지 여부" >> $report 2>&1
echo " 2) 보안정책에 따라 로그를 남기고 있는지 여부">> $report 2>&1
