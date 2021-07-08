# sniff

A little Python project to find in the network devices starting with some MACs inside a CSV wich contains the relationship between MAC and vendor

Scan TCP/IP protocol the seconds we select in the variable seconds<br>
Scan from ARP packets the seconds we select in the variable seconds<br>
Option to scan with ping (only Mask 255.255.255.0)<br>
Include all MAC's scanned to a dictionary "MAC":"IP"<br>
We're going to read MAC vendors from csv file to a dictionary<br>
We will create a csv with MAC;IP;VENDOR; hostname (if it has hostname) <br>
