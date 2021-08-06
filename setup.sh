#!/bin/bash
# Version 0.3

echo "Cthulhu 0.3"

if ping -c 1 -w 2 mirrors.ustc.edu.cn &>/dev/null; then
	echo "[+] ok"
else
	echo "[-] network error"
	exit
fi

python_requirements=`pip3 freeze`
str="termcolor"
if [[ $python_requirements =~ $str ]];then
    echo "[+] Python >= 3.x"
else
    which "pip3" &>/dev/null
    if [ $? -eq 0 ]
    then
       pip3 install -r requirements.txt
    fi
fi


m="mingw-w64"
SYSTEM=`cat /etc/issue.net | awk '{print $1}'`

case $SYSTEM in
    Debian) echo "[+] echo $SYSTEM, apt-get"
        min=`dpkg --list | grep mingw-w64`
        if [[ $min =~ $m ]];then
            python3 cthlhu.py
            exit
        else
            sudo apt-get install mingw-w64
            python3 cthlhu.py
            exit
        fi
        ;;
    Kali) echo "[+] echo $SYSTEM"
        min=`dpkg --list | grep mingw-w64`
        if [[ $min =~ $m ]];then
            exit
            python3 cthlhu.py
        else
            sudo apt-get install mingw-w64
            python3 cthlhu.py
            exit
        fi
        ;;
    *)
        ;;
esac 

