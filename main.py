import nmap
def scan_host(analyzed_host, ports = None):
    nm = nmap.PortScanner()  # сканер
    info = nm.scan(analyzed_host, ports) # сканирует порты 22-443

    timestr = info['nmap']['scanstats']['timestr'] # время сканирования\
    print('Scan date:\n' + timestr)

    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol: ' + proto)
            ports = nm[host][proto].keys()
            for port in ports:
                print(f'Port: {port};\t'
                      f'State: {nm[host][proto][port]['state']};\t'
                      f'Product: {nm[host][proto][port]['product']}')





host = input('Host: ')
port = input('Порт(диапазон указать через дефис, если указать - 0, то сканирует все порты):\n')
if port == '0':
    ports = None

scan_host(host, ports)
