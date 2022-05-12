import socket
import subprocess
import re
#list of most common ports in use
port_list = [
    ["FTP", 20],
    ["FTP", 21],
    ["SSH", 22],
    ["Telnet", 23],
    ["SMTP", 25],
    ["DNS", 53],
    ["HTTP", 80],
    ["POP3", 110],
    ["NNTP", 119],
    ["NTP", 123],
    ["IMAP", 143],
    ["SNMP", 161],
    ["IRC", 194],
    ["HTTPS", 443]
]


def scan_port(ipaddress, port):
    """
    This function recives the public ip and scans a selected port
    :param ipaddress: public ip address to scan
    :param port: selected port from our list
    :return: an answer to see if the selected port is opened or closed
    """
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ipaddress, port[1]))
        return str(port[0]) + " " + str(port[1]) + "Opened"
    except:
        return 'Closed Port ' + str(port[0]) + " " + str(port[1])


def get_public_ip():
    """
    This function gets the public ip of the selected network and destructs it from the stream read
    :return: public ip address
    """
    ip_addresses_list = subprocess.run(["nslookup", "myip.opendns.com", "resolver1.opendns.com"],
                                       capture_output=True).stdout.decode()
    selected_public_ip_address = (re.findall("Address: (.*)\r", ip_addresses_list))[0]
    return selected_public_ip_address


# 8
def iterate_all_ports():
    """
    This function recives our public ip address and iterate through our port list, scans it and return the result
    :return: list of results on each port scan
    """
    ip_address_to_scan = get_public_ip()
    final_scan_list = []
    for port in port_list:
        final_scan_list.append(scan_port(ip_address_to_scan, port))
    return final_scan_list


def main():
    final_scan_list = iterate_all_ports()
    export_scan_to_file(final_scan_list)


def export_scan_to_file(final_scan_list):
    """
    This function exports the result into a text file, according to the received scan list
    :param final_scan_list: a list of the port scan result
    :return: none
    """
    with open('scan-test.txt', 'w+') as fh:
        for x in range(0,len(final_scan_list)):
            fh.write(f"{x+1}){final_scan_list[x]}\n")


if __name__ == '__main__':
    main()
