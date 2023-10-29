echo "Set route s2_1"
route add -net 10.4.1.0 netmask 255.255.255.0 gw 10.2.1.2
service haproxy restart
bash