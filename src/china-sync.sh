#!/bin/sh

racket generate-china.sh > china-domains.txt
curl https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt > china-ips.txt