#!/bin/bash
sudo su <<EOF
echo root:bodao | /usr/sbin/chpasswd
exit
EOF
exit
