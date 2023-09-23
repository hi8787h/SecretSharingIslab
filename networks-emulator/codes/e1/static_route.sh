echo "Set route e1"
route add -net 10.1.1.0 netmask 255.255.255.0 gw 10.4.1.1
route add -net 10.2.1.0 netmask 255.255.255.0 gw 10.4.1.2
route add -net 10.3.1.0 netmask 255.255.255.0 gw 10.4.1.3
route del default
route add default gw 10.5.1.254 eth1

# service nginx start
service haproxy restart

bash