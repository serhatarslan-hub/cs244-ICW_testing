sudo iptables -S | grep "OUTPUT -p tcp -m tcp --sport" | sed 's/-A/-D/g' | xargs -l sudo iptables