import requests

def send_firewall_rule(type,interface,ipprotocol,protocol, src,src_port, dst, dst_port, descr, log, top, apply,token):
    url = (f"https://pfsense.home.arpa/api/v1/firewall/rule?type={type}&interface={interface}&ipprotocol={ipprotocol}&protocol={protocol}&src={src}&srcport={src_port}&dst={dst}&dstport={dst_port}&descr={descr}&log={log}&top={top}&apply={apply}")
    payload = {
        
        'type': type,
        'interface': interface,
        'ipprotocol': 'inet',
        'protocol': protocol,
        'src': src,
        'src_port': src_port,
        'dst': dst,
        'dst_port': dst_port,
        'descr': descr,
        'log': log,
        'top': top,
        'apply':apply  
    }
    headers = {
        'Authorization': f'Bearer {token}'
    }

    response = requests.post(url,headers=headers,data=payload,verify=False)
    if response.status_code == 200:
        return "Rule created successfully."
    else:
        return "Failed to create rule. Please try again."



def get_firewall_info(token):
    url = "https://pfsense.home.arpa/api/v1/status/system"
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url, headers=headers,verify=False)
    
    if response.status_code == 200:
        response_json = response.json()
        data = response_json.get('data', {})
        device_name = data.get('system_platform')
        device_id = data.get('system_netgate_id')
        return device_name, device_id
    else:
        raise Exception('Failed to fetch firewall information')

def get_gateway_info(token):
    url = "https://pfsense.home.arpa/api/v1/status/gateway"
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url, headers=headers,verify=False)

    if response.status_code == 200:
        response_json = response.json()
        gateways = []
        data = response_json.get('data', [])
        for gateway_data in data:
            gateway_info = {
                'name': gateway_data.get('name', ''),
                'monitor_ip': gateway_data.get('monitorip', ''),
                'source_ip': gateway_data.get('srcip', ''),
                'delay': gateway_data.get('delay', 0),
                'loss': gateway_data.get('loss',0),
                'status': gateway_data.get('status', '')
            }
            gateways.append(gateway_info)
        return gateways
    else:
        raise Exception('Failed to get gateway details')


def get_interface_info(token):
    url="https://pfsense.home.arpa/api/v1/interface"
    headers={
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url,headers=headers,verify=False)

    if response.status_code == 200:
        response_json = response.json()
        interfaces = []
        data = response_json.get('data',[])
        for interface_name, interface_data in data.items():
            interface_info = {
                'name': interface_name,
                'descr': interface_data.get('descr', ''),
                'if': interface_data.get('if', ''),
                'ipaddr': interface_data.get('ipaddr', ''),
                'subnet': interface_data.get('subnet', ''),
                'ipaddrv6': interface_data.get('ipaddrv6', ''),
                'subnetv6': interface_data.get('subnetv6', ''),
            }
            interfaces.append(interface_info)

            
        names = [entry['name'] for entry in interfaces]

        print(names)

        return interfaces
    else:
        raise Exception('Failed to get Interface Details')

def get_services(token):
    url = "https://pfsense.home.arpa/api/v1/services"
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url,headers=headers,verify=False)

    if response.status_code == 200:
        response_json = response.json()
        services = []
        data = response_json.get('data',[])
        for services_data in data:
            service_info={
                'name': services_data.get('name',''),
                'description': services_data.get('description',''),
                'status': services_data.get('status',''),
            }
            services.append(service_info)

        return services
    else:
        raise Exception('Failed to get Services details')
    
def get_dhcp_lease(token):
    url= "https://pfsense.home.arpa/api/v1/services/dhcpd/lease"
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url,headers=headers,verify=False)

    if response.status_code == 200:
        response_json = response.json()
        dhcp_lease=[]
        data=response_json.get('data',[])
        for lease in data:
            dhcp_data={
                'type': lease.get('type',''),
                'ip': lease.get('ip',''),
                'mac': lease.get('mac',''),
                'online': lease.get('online',''),
                'hostname': lease.get('hostname',''),
               'starts': lease.get('starts',''),
               'ends': lease.get('ends',''),
               'state':lease.get('state',''),    

            }
            dhcp_lease.append(dhcp_data)
        return dhcp_lease
    else:
        raise Exception('Failed to get DHCP Lease Information')
    
def get_dhcp_util(token):
    url = "https://pfsense.home.arpa/api/v1/services/dhcpd"
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url,headers=headers,verify=False)

    if response.status_code == 200:
        response_json = response.json()
        dhcp_util = []
        data = response_json.get('data',[])
        for util in data:
            util_data = {
                'interface': util.get('interface',''),
                'from': util.get('range', {}).get('from', ''), 
                'to': util.get('range', {}).get('to', '')  
            }
            dhcp_util.append(util_data)
        for tool in util_data:
            from_last_octet = util_data['from'].split('.')[-1]
            to_last_octet = util_data['to'].split('.')[-1]
            print(from_last_octet,to_last_octet)
        return dhcp_util
    else:
        raise Exception('Failed to get DHCP Utilization')
    
def get_firewall_rules(token):
    url = "https://pfsense.home.arpa/api/v1/firewall/rule"
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url,headers=headers,verify=False)

    if response.status_code == 200:
        response_json = response.json()
        f_rules = []
        data = response_json.get('data','')
        for rule in data:
            rule = {
                'type': rule.get('type',''),
                'interface': rule.get('interface',''),
                'saddress': rule.get('source',{}).get('address',''),
                'daddress': rule.get('destination',{}).get('address',''),
                'descr': rule.get('descr','')
            }
            f_rules.append(rule)
        return f_rules
    else:
        raise Exception('Failed to get Firewall Rules')
            

