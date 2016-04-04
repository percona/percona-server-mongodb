#!/bin/bash

killall saslauthd
dpkg -r sasl2-bin
dpkg -P sasl2-bin
/bin/rm -rf /etc/saslauthd.conf
/bin/rm -rf /etc/default/saslauthd
/bin/rm /etc/sasl2/mongodb.conf

