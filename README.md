# Network map utility

This repository implements NMAP utility in Python language

# Usage

```
$ sudo python3 nmap.py --src [address] --dst [address] --source-port [port] -- timeout [seconds] --destination-port [port]
```

# Example

```
$ sudo python3 nmap.py --src 192.168.2.68 --dst 192.168.0.192 --source-port 45000 --timeout 10 --destination-port 22
```

Ouput:
```
$ sudo python3 nmap.py --src 192.168.2.68 --dst 192.168.0.192 --source-port 45000 --timeout 10 --destination-port 22
$ Port is open 22
```
