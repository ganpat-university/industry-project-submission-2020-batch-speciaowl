from flask import Flask, render_template, request, jsonify
from api_requests import send_firewall_rule,get_firewall_info,get_gateway_info,get_interface_info,get_services,get_dhcp_lease,get_dhcp_util,get_firewall_rules
from jwt_auth import generate_token

app = Flask(__name__)

@app.route('/')
def index():
    try:
        token = generate_token()
        device_name, device_id = get_firewall_info(token)
        gateways = get_gateway_info(token)
        interfaces = get_interface_info(token)
        services = get_services(token)
        dhcp_lease = get_dhcp_lease(token)
        dhcp_util = get_dhcp_util(token)
        return render_template('index.html',gateways=gateways, device_name=device_name, device_id=device_id,interfaces=interfaces,services=services,dhcp_lease=dhcp_lease,dhcp_util=dhcp_util)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api_call', methods=['POST'])
def api_call():
    try:

        token = generate_token()
        
        type = request.form['type']
        interface = request.form['interface']
        ipprotocol = 'inet'
        protocol = request.form['protocol']
        src = request.form['src']
        src_port = request.form['src_port']
        dst = request.form['dst']
        dst_port = request.form['dst_port']
        descr = request.form['descr']
        log = request.form['log']
        top = request.form['top']
        apply = request.form['apply']

        response = send_firewall_rule(type, interface, ipprotocol, protocol, src, src_port, dst, dst_port, descr, log, top, apply,token)

        return jsonify({'status': 'success', 'response': response})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/rule',methods=['GET'])
def rule():
    token= generate_token()

    device_name, device_id = get_firewall_info(token)
    f_rules = get_firewall_rules(token)
    interfaces = get_interface_info(token)
    names = [entry['name'] for entry in interfaces]
    return render_template('rule.html',device_id=device_id,device_name=device_name,f_rules=f_rules,interfaces=interfaces,names=names)

if __name__ == '__main__':
    app.run(debug=True)
