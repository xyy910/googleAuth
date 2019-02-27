#!/bin/bash

token=`googleAuth`
user="你的用户名"
pass="你的密码"
host="要登录的机器"
server=$1

#echo $user@$host $token$pass

exec /usr/bin/expect <<-EOF

set timeout 10

spawn ssh $user@$host

expect "*password: " {send "$token$pass\r"}
expect "*~$" {send "ssh $server\r"}
#expect "*$"
interact

EOF

