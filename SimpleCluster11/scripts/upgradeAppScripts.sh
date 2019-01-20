#! /bin/bash 
if [  -d "/data/customScripts/" ]
then 
  echo yes|cp /data/customScripts/*  /usr/lib/postgresql/scripts/
  chmod +x /usr/lib/postgresql/scripts/* 
  
  #因为该脚本是开机启动,在/etc/rc.local文件中调用,
  #因此$APPLOG/pgscripts.log目录还没有挂载好,日志放在临时日志文件中。
  echo "`date '+%Y-%m-%d %H:%M:%S'` - upgradeAppScripts.sh - Info - 开机启动的时候发现有/data目录下有自定义的customScripts目录,copy到image下的脚本目录下更新脚本。" >>/root/rclocal.log 
  exit 0
fi 
