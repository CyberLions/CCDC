sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
while [ $? -eq 0 ]; do
    sudo /sbin/iptables -D INPUT 1
done