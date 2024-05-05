import requests
import time

token = None
token_creation_time = None

def generate_token():
    global token, token_creation_time
    
    # Check if the token is still valid (less than 24 hours old)
    if token_creation_time is not None:
        time_since_creation = time.time() - token_creation_time
        if time_since_creation < 24 * 60 * 60:
            return token

    url = "https://pfsense.home.arpa/api/v1/access_token"

    payload = {}
    headers = {
        'Authorization': 'Basic YWRtaW46UEBzc3cwcmQ='
        }

    response = requests.request("POST", url, headers=headers, data=payload,verify=False)

    print(response.text)
    if response.status_code == 200:
        response_json = response.json()
        if 'data' in response_json and 'token' in response_json['data']:
            token = response_json['data']['token']
            return token
        else:
            raise Exception('Token not found in the response data')
    else:
        raise Exception('Failed to generate JWT token')
