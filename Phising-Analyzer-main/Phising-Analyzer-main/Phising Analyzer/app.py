from flask import Flask, render_template, request, jsonify
import requests
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

# Replace 'YOUR_VIRUSTOTAL_API_KEY' with your actual VirusTotal API key
virustotal_api_key = '49127fa6f24f5004aa2b78f6cf65bba746ad482db76712879f1481506aa461fb'
abuseipdb_api_key = 'YOUR_ABUSEIPDB_API_KEY'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_ip', methods=['POST'])
def check_ip():
    try:
        ip = request.json.get('ip')

        if not ip:
            raise ValueError('IP address not provided in the request.')

        virustotal_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {'x-apikey': virustotal_api_key}

        response = requests.get(virustotal_url, headers=headers)
        response.raise_for_status()

        data = response.json()

        if 'data' in data and 'attributes' in data['data']:
            attributes = data['data']['attributes']
            
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)

            last_analysis_results = attributes.get('last_analysis_results', {})
            scan_date = last_analysis_results.get('scan_date', 'N/A')
            scan_results = last_analysis_results.get('result', 'N/A')

            country = attributes.get('country', 'N/A')
            
            return jsonify({
                'data': {
                    'abuseConfidenceScore': malicious_count,
                    'suspiciousConfidenceScore': suspicious_count,
                    'numReports': malicious_count + suspicious_count,
                    'scanDate': scan_date,
                    'scanResults': scan_results,
                    'country': country,
                }
            })
        else:
            return jsonify({'error': 'No information available for this IP on VirusTotal'})

    except requests.RequestException as e:
        return jsonify({'error': f'Error connecting to VirusTotal API: {str(e)}'})
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'})

if __name__ == '__main__':
    app.run(debug=True)