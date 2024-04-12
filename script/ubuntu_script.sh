# #!/bin/bash

report="report_$(date).txt"

# Account Management
# - Restrict remote access to root account: High U-01

echo "----Restrict remote access to root account: High U-01----" >> $report 2>&1

##Telnet 동작 확인 후 루트 권한 접속 제한 여부 확인
if ps aux | grep -v grep | grep telnet > /dev/null
then 
    if [ -f /etc/pam.d/login ]
    then
        if grep -v '^#' /etc/pam.d/login | grep 'auth[[:space:]]\+required[[:space:]]\+/lib/security/pam_securetty.so' >/dev/null
        then 
            echo "[양호] 텔넷이 활성화 되어있으나 루트 권한 접속이 제한되어있습니다." >> $report 2>&1
        else 
            echo "[취약] 텔넷이 활성화 되어있으며 루트 권한 접속 제한이 설정되어있지않습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/pam.d/login 파일에 'auth required /lib/security/pam_securetty.so' 를 삽입하세요" >> $report 2>&1
        fi
    
    else
        echo "[기타] /etc/pam.d/login 파일이 존재하지 않습니다." >> $report 2>&1
    fi
    if [ -f /etc/securetty ]
    then 
        if grep -v '^#' /etc/securetty | grep -q '^pts/[0-9]\+' >> /dev/null
        then 
            echo "[양호] 텔넷이 활성화 되어있으나 루트 권한 접속이 제한되어있습니다." >> $report 2>&1
        else 
            echo "[취약] 텔넷이 활성화 되어있으며 루트 권한 접속 제한이 설정되어있지않습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/securetty 파일에 pts/0 ~ pts/x 설정을 제거하세요 " >> $report 2>&1
        fi
    fi
    else
        echo "[기타] /etc/securetty 파일이 존재하지 않습니다." >> $report 2>&1

fi


##ssh 동작 확인 후 루트 권한 접속 제한 여부 확인

if ps aux | grep -v grep | grep telnet > /dev/null
then 
    if [ -f /etc/pam.d/login ]
    then
        if grep -v '^#' /etc/pam.d/login | grep 'auth[[:space:]]\+required[[:space:]]\+/lib/security/pam_securetty.so' >/dev/null
        then 
            echo "[양호] 텔넷이 활성화 되어있으나 루트 권한 접속이 제한되어있습니다." >> $report 2>&1
        else 
            echo "[취약] 텔넷이 활성화 되어있으며 루트 권한 접속 제한이 설정되어있지않습니다." >> $report 2>&1
            echo "[[조치방법]] /etc/pam.d/login 파일에 'auth required /lib/security/pam_securetty.so' 를 삽입하세요" >> $report 2>&1
        fi
    
    else
        echo "[기타] /etc/pam.d/login 파일이 존재하지 않습니다." >> $report 2>&1
    fi
fi

# - Password complexity settings: High U-02
# - Account lockout threshold settings: High U-03
# - Protection of password files: High U-04
# - Prohibit UIDs of '0' other than root: Medium U-44
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

# File and Directory Management
# - Set permissions and path for root home and path directories: High U-05
# - Set file and directory owner: High U-06
# - Set owner and permissions for /etc/passwd file: High U-07
# - Set owner and permissions for /etc/shadow file: High U-08
# - Set owner and permissions for /etc/hosts file: High U-09
# - Set owner and permissions for /etc/(x)inetd.conf file: High U-10
# - Set owner and permissions for /etc/syslog.conf file: High U-11
# - Set owner and permissions for /etc/services file: High U-12
# - Check files for SUID, SGID, Sticky bit settings: High U-13
# - Set owner and permissions for user, system startup, and environment files: High U-14
# - Check for world writable files: High U-15
# - Check for device files not in /dev: High U-16
# - Prohibit the use of $HOME/.rhosts, hosts.equiv: High U-17
# - Restrict login IP and port: High U-18
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
