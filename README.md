# Minimum example to run NFQUEUE

#Build
gcc main.c nf-queue.c -lmnl -lnetfilter_queue

# ADD iptable rules
sudo iptables -A INPUT -j NFQUEUE --queue-num 0

# Run program

# Delete iptable rule 
sudo iptables -L INPUT --line-numbers
sudo iptables -D INPUT <line-to-delete>

