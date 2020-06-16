import json
from ast import literal_eval

import dateparser
import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS
from urllib.parse import quote
import hashlib
import requests
import json
import base64
import csv
import sys
import os
from time import sleep, time
from urllib.parse import quote
import logging
from requests.auth import HTTPBasicAuth
# import validators_collection
# import validators
# from validators_collection.errors import *


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
# param constants
DRIVE = demisto.params().get('drive', '')
VT_KEY = demisto.params().get('virustotal_apikey', '')
ABIP_KEY = demisto.params().get('abusedipdb_apikey', '')
IBM_KEY = demisto.params().get('ibm_key', '') + ":" + demisto.params().get('ibm_pass', '')
URLSCAN_KEY = demisto.params().get('urlscan_apikey', '')
GOOGLE_KEY = demisto.params().get('googleSafeBrowsing_apikey', '')
AUTH0_KEY = demisto.params().get('auth0_apikey', '')
PHISH_KEY = demisto.params().get('phishtank_apikey', '')
PHISH_USER = demisto.params().get('phishtank_user', '')
FG_KEY = demisto.params().get('fraudguard_apikey', '')

# String constants
IP_MODE = 'ip'
URL_MODE = 'url'
FILE_MODE = 'file'
HASH_MODE = 'hash'
REPUTATION = "Reputation"
BLOCK = "Block"
SAFE = "Safe"
NONE = "N/A"
UNKNOWN = "Not Found in Database"
SS_SAVED = "Screenshot saved"
SS_FAILED = "Failed to save screenshot"
EX_SERVER = ": {} is having problems. Please try again later."
EX_UNAUTH = ": Unauthorized. Please check API key"

# OSINT constants
# [VirusTotal] api / links
VT = 'VirusTotal'
VT_URL = 'https://www.virustotal.com/api/v3/urls'
VT_FILE = 'https://www.virustotal.com/api/v3/files'
VT_FILE_BIG = 'https://www.virustotal.com/api/v3/files/upload_url'
VT_IP = 'https://www.virustotal.com/api/v3/ip_addresses/{}'
VT_SS = 'https://www.virustotal.com/gui/{identifier}/{target}/detection'
# [AbuseIPDB] api / links
ABIP = 'AbusedIP'
ABIP_IP = 'https://api.abuseipdb.com/api/v2/check'
ABIP_SS = 'https://www.abuseipdb.com/check/{}'

# [IBM]
IBM = 'IBM'
IBM_IP = 'https://api.xforce.ibmcloud.com/ipr/{}'
IBM_URL = 'https://api.xforce.ibmcloud.com/url/{}'
IBM_SS = 'https://exchange.xforce.ibmcloud.com/search/{}'

# [Fraud Guard]
FG = 'FraudGuard'
name_API = 'api.'
name_FG = 'fraudguard'
FG_IP = 'https://' + name_API + name_FG + '.io/ip/{}'
FG_SS = 'https://' + name_FG + '.io/?ip={}'

# [URLScan]
URLSCAN = 'URLScan'
URLSCAN_URL = 'https://urlscan.io/api/v1/scan/'
URLSCAN_SS_ORIGIN = 'https://urlscan.io/screenshots/'
URLSCAN_SS = 'https://urlscan.io/result/{}'

# [Google Safe]
GOOGLE = 'GoogleSafeBrowsing'
GOOGLE_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key='
GOOGLE_SS = 'https://transparencyreport.google.com/safe-browsing/search?url={}&hl=en'

# [Auth0]
AUTH0 = 'Auth0'
name_auth0 = 'auth0'
name_signal = 'signals.'
AUTH0_IP = 'https://' + name_signal + name_API + name_auth0 + '.com/v2.0/ip/{}'
AUTH0_SS = 'https://auth0.com/signals/ip/{}-report'

# [PhishTank]
PHISH = 'PhishTank'
PHISH_URL = 'https://checkurl.phishtank.com/checkurl/'
PHISH_SS = 'https://www.phishtank.com/'

# [Cisco Talos]
CISCO = 'CiscoTalos'
CISCO_SS = 'https://talosintelligence.com/reputation_center/lookup?search='


# Initialisation of modes
mode = NONE
ss_mode = False
single_mode = False
vt_headers = {'Accept': 'application/json'}
ibm_headers = {"Content-Type": "application/json"}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def say_hello(self, name):
        return f'Hello {name}'

    def say_hello_http_request(self, name):
        """
        initiates a http request to a test url
        """
        data = self._http_request(
            method='GET',
            url_suffix='/hello/' + name
        )
        return data.get('result')

    def list_incidents(self):
        """
        returns dummy incident data, just for the example.
        """
        return [
            {
                'incident_id': 1,
                'description': 'Hello incident 1',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            },
            {
                'incident_id': 2,
                'description': 'Hello incident 2',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.say_hello('DBot')
    if 'Hello DBot' == result:
        return 'ok'
    else:
        return 'Test failed because ......'


def save_record_csv(data, filename, header):
    logging.info("Saving Record")
    # with open(filename, mode="a+", encoding="utf-8", newline="") as csv_file:
    #     writer = csv.DictWriter(csv_file, fieldnames=header)
    #     if os.stat(filename).st_size == 0:
    #         writer.writeheader()
    #     writer.writerow(data)
    # header = {
    #     "Accept-Encoding": "gzip, deflate",
    #     'Content-Type': 'multipart/form-data'
    # }
    # files = {"file": (filename, open(filename, "rb"), 'application-type')}
    # res = requests.request('POST', "https://192.168.43.199/entry/upload/62", files=files, headers=header)
    # print(res)


def vt_result(result):
    try:
        harmless = int(result.json()['data']['attributes']['last_analysis_stats']['harmless'])
        malicious = int(result.json()['data']['attributes']['last_analysis_stats']['malicious'])
        suspicious = int(result.json()['data']['attributes']['last_analysis_stats']['suspicious'])
        undetected = int(result.json()['data']['attributes']['last_analysis_stats']['undetected'])
        rate = str(malicious) + " // " + str(malicious + harmless + suspicious + undetected)
    except (KeyError, TypeError) as e:
        logging.error(VT + " - vt_result() - " + str(e))
        rate = NONE
    except Exception as e:
        logging.critical(VT + " - vt_result() - " + str(e))
        rate = NONE
    finally:
        return rate


def vt_exception(resp):
    # https://developers.virustotal.com/v3.0/reference#errors
    code = resp.status_code
    if not str(code).startswith('2'):
        try:
            msg = resp.json()['error']['message']
        except ValueError as e:
            msg = e
        if code == 401 or code == 503 or code == 429:
            print(VT + ": ERROR - " + str(msg))
        raise Exception(str(msg))


def virusTotalIP(ip):
    # vt_screenshot(ip)
    try:
        resp = requests.get(VT_IP.format(ip), headers={'Accept': 'application/json', 'x-apikey': VT_KEY})
        vt_exception(resp)
    except Exception as e:
        vt = NONE
        logging.exception(VT + " - " + str(e))
    else:
        # available status: harmless, malicious, suspicious, timeout, undetected
        vt = vt_result(resp)
    finally:
        return vt


def virusTotalURL(url):
    try:  # send url to scan
        headers = {'Accept': 'application/json', 'x-apikey': VT_KEY}
        resp = requests.post(VT_URL, headers=headers, data={'url': url})
        vt_exception(resp)
        req_id = resp.json()['data']['id'].split('-')[1]
    except Exception as e:
        logging.error(VT + " - " + str(e))
    try:
        # fetch scan results
        resp = requests.get(
            VT_URL + '/{}'.format(req_id),
            headers=headers)
        vt_exception(resp)
        # Check if the analysis is finished before returning the results
        while not resp.json()['data']['attributes']['last_analysis_results']:
            resp = requests.get(
                VT_URL + '/{}'.format(req_id),
                headers=headers)
            sleep(3)
        vt_exception(resp)
    except Exception as e:
        vt = NONE
        logging.exception(VT + " - " + str(e))
    else:
        # available status: harmless, malicious, suspicious, timeout, undetected
        vt = vt_result(resp)
    finally:
        # vt_screenshot(url)
        print(VT + ": " + vt)
        logging.info(VT + " - " + vt)
        return vt

# Get MD5 hash


def getmd5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def virusTotalFile(file):
    with open(file, 'rb') as f:
        data = {'file': f.read()}
    # upload file based on size
    file_size = os.path.getsize(file)
    try:
        if file_size <= 33554432:
            resp = requests.post(VT_FILE, headers=vt_headers, files=data)
        else:  # bigger than 32 mb - there may be performance issue as a file gets too big
            resp = requests.get(VT_FILE_BIG, headers=vt_headers)
            vt_exception(resp)
            upload_url = resp.json()['data']
            resp = requests.post(upload_url, headers=vt_headers, files=data)
        vt_exception(resp)
    except Exception as e:
        vt = NONE
        logging.exception(VT + " - " + str(e))
    else:
        vt = vt_result(resp)
        filehash = str(getmd5(file))
        # retrieve analysis
        vt = virusTotalHash([filehash, file])
        vt = [vt[4], filehash]
    finally:
        print(VT + ": " + str(vt))
        logging.info(VT + " - " + str(vt))
        return vt


def virusTotalHash(a_hash):
    # vt_screenshot(a_hash)
    if mode == FILE_MODE:
        a_hash = a_hash[0]
    try:
        resp = requests.get(VT_FILE + '/{}'.format(a_hash), headers={'Accept': 'application/json', 'x-apikey': VT_KEY})
        vt_exception(resp)
    except Exception as e:
        vt = NONE
        logging.exception(VT + " - " + str(e))
    else:
        # Status: confirmed-timeout, failure, harmless, malicious, suspicious, timeout, type-unsupported, undetected
        vt = vt_result(resp)
    finally:
        print(VT + ": " + str(vt))
        logging.info(VT + " - " + vt)

    try:
        md5 = resp.json()['data']['attributes']['md5']
        sha1 = resp.json()['data']['attributes']['sha1']
        sha256 = resp.json()['data']['attributes']['sha256']
        print("md5: " + md5 + ", SHA1: " + sha1 + ", SHA256: " + sha256)
    except (KeyError, TypeError) as e:
        logging.error(VT + " - virusTotalHash() - " + str(e))
        md5 = NONE
        sha256 = NONE
        sha1 = NONE
    finally:
        data = [a_hash, md5, sha1, sha256, vt]
        return data


def getScreenshotIBM(obj):
    rate = ''  # ss.IBM(obj)
    print(IBM + ": " + rate)
    logging.info(IBM + " - " + rate)
    return rate


def IBM_exceptionHandle(resp):
    logging.error(IBM + " - " + str(resp.json()))
    if resp.status_code == 402:
        print(IBM + ": Monthly quota exceeded")
    elif resp.status_code == 401:
        print(IBM + ": Not Authorized. Check API key and pass")
    elif str(resp.status_code).startswith('5'):
        print(IBM + EX_SERVER.format(IBM))


# call to this function when url mode on
def ibm_url(url):
    if ss_mode:
        return getScreenshotIBM(url)
    else:
        pass_data = IBM_KEY
        data = base64.b64encode(pass_data.encode())
        final = str(data.decode('utf-8'))
        ibm_headers = {"Content-Type": "application/json", "Authorization": "Basic " + final}
        resp = requests.get(IBM_URL.format(quote(url)), headers=ibm_headers)
        if str(resp.status_code).startswith('2'):
            try:
                rate = str(resp.json()['result']['score']) + " // 10"
            except:
                rate = UNKNOWN
        elif resp.status_code == 404:
            rate = UNKNOWN
            logging.info(IBM + " - Not found in database")
        else:
            rate = NONE
            IBM_exceptionHandle(resp)

        print(IBM + ": " + rate)
        logging.info(IBM + " - " + rate)
        return rate


# call to this function when ip mode on
def ibm_IP(ip):
    if ss_mode:
        return getScreenshotIBM(ip)
    else:
        pass_data = IBM_KEY
        data = base64.b64encode(pass_data.encode())
        final = str(data.decode('utf-8'))
        ibm_headers = {"Content-Type": "application/json", "Authorization": "Basic " + final}
        resp = requests.get(IBM_IP.format(ip), headers=ibm_headers)
        if str(resp.status_code).startswith('2'):
            try:
                rate = str(resp.json()['history'][-1]['score']) + " // 10"
            except:
                rate = UNKNOWN
        elif resp.status_code == 404:
            rate = UNKNOWN
            logging.warning(IBM + " - Not found in database")
        else:
            rate = NONE
            IBM_exceptionHandle(resp)

        print(IBM + ": " + rate)
        logging.info(IBM + " - " + rate)
        return rate

# only works for url, no ip support


def abusedIP(ip):
    # if ss_mode:
    #     if ss.abusedIP(ip):
    #         print(ABIP + ": " + SS_SAVED)
    #     else:
    #         print(ABIP + ": " + SS_FAILED)
    headers = {
        'Key': ABIP_KEY,
        'Accept': 'application/json',
    }
    params = {'ipAddress': ip}
    try:
        resp = json.loads(requests.get(ABIP_IP, headers=headers, params=params).text)
        rate = str(resp['data']["abuseConfidenceScore"]) + " // 100"
    except:
        rate = NONE
        error = resp['errors']
        if error[0]['status'] == 429 or error[0]['status'] == 401:
            print(ABIP + ": " + error[0]['detail'])
        elif str(error[0]['status']).startswith('5'):
            print(ABIP + EX_SERVER.format(ABIP))
        logging.error(ABIP + " - virusTotalHash() - " + str(error[0]['detail']))
    finally:
        print(ABIP + ": " + rate)
        logging.info(ABIP + " - " + rate)
        return rate


def fraudGuard(ip):
    # if ss_mode:
    #     if ss.fraudguard(ip):
    #         print(FG + ": " + SS_SAVED)
    #     else:
    #         print(FG + ": " + SS_FAILED)

    try:
        username = FG_KEY.strip().split(':')[0]
        password = FG_KEY.strip().split(':')[1]
    except IndexError:
        rate = NONE
        logging.error(FG + " - " + "No API keys provided")
        print(FG + ": API keys not provided in config.txt")
        print(FG + ": " + rate)
        logging.info(FG + " - " + rate)
        return rate
    resp = requests.get(FG_IP.format(ip), verify=True, auth=HTTPBasicAuth(username, password))
    try:
        rate = json.loads(resp.text)['risk_level'] + " // 5"
    except:
        rate = NONE
        logging.error(FG + " - " + str(resp.text))
        if resp.status_code == 401:
            print(FG + ": Invalid key - " + FG_KEY + " - Check credentials")
        elif str(resp.status_code).startswith('5'):
            print(FG + ": FraudGaurd is having problems. Please try again later")
        elif resp.status_code == 429:
            print(FG + ": API limit reached for FG key")
    finally:
        print(FG + ": " + rate)
        logging.info(FG + " - " + rate)
        return rate


def auth0(ip):
    # if ss_mode:
    #     if ss.auth0(ip):
    #         print(AUTH0 + ": " + SS_SAVED)
    #     else:
    #         print(AUTH0 + ": " + SS_FAILED)
    headers = {
        "Accept": "application/json",
        "X-Auth-Token": AUTH0_KEY
    }
    try:
        resp = requests.get(AUTH0_IP.format(ip), headers=headers).json()
        score = str(resp['fullip']['score']).strip()
    except:
        score = NONE
        logging.exception(AUTH0 + " - " + str(resp))
    finally:
        print(AUTH0 + ": " + score)
        logging.info(AUTH0 + " - " + score)
        return score


def googleSafe(url):
    # if ss_mode:
    #     if ss.googleSafe(url):
    #         print(GOOGLE + ": " + SS_SAVED)
    #     else:
    #         print(GOOGLE + ": " + SS_FAILED)
    data = {
        "client": {"clientId": "ProjectAuto", "clientVersion": "1.5.2"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["WINDOWS"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]}}
    resp = requests.post(GOOGLE_URL + GOOGLE_KEY, data=json.dumps(data))
    if resp.status_code == 200:
        if "matches" in resp.json().keys():
            gsb = resp.json()["matches"][0]["threatType"]
        else:
            gsb = "Safe"
    else:
        gsb = NONE
        if resp.status_code == 429:
            print(GOOGLE + ": Requests Exceeded!")
        elif str(resp.status_code).startswith('5'):
            print(GOOGLE + EX_SERVER.format(GOOGLE))
        logging.error(GOOGLE + " - " + str(resp.json()))
    print(GOOGLE + ": " + gsb)
    logging.info(GOOGLE + " - " + gsb)
    return gsb


def phishtank(url):
    # if ss_mode:
    #     if ss.phishtank(url):
    #         print(PHISH + ": " + SS_SAVED)
    #     else:
    #         print(PHISH + ": " + SS_FAILED)
    data = {
        "url": url,
        'format': "json",
        'app_key': PHISH_KEY
    }
    if not demisto.params().get('phishtank_user'):
        PHISH_USER = ""
    headers = {
        "User-Agent": "phishtank/" + PHISH_USER
    }
    resp = requests.post(PHISH_URL, headers=headers, data=data)

    if resp.status_code == 200:
        if resp.json()['results']['in_database']:  # if it exists in database
            if not resp.json()['results']['verified']:  # if pending verification return malicious
                result = "Questionable"
            elif resp.json()['results']['verified'] and resp.json()['results']['valid']:  # if phish return malicious
                result = "Phish"
            else:  # if verified as not a phish
                result = "Not a Phish"
        else:  # if result not found in database
            result = UNKNOWN
    else:
        result = NONE
        logging.error(PHISH + " - " + str(resp.json()))
        if resp.status_code == 509:
            print(PHISH + ": Requests Exceeded! Please wait at most 5 minutes to reset the number of requests.")
    print(PHISH + ": " + str(result))
    logging.info(PHISH + " - " + str(result))
    return result


def addScore(name, safescore, score, data, safe, block):
    data[name] = score
    if score != NONE:
        if score.startswith(safescore) or score == UNKNOWN:
            safe.append(name)
        else:
            block.append(name)
    return data, safe, block


def get_verdict(output):
    if len(output[BLOCK]) > 0:
        output["Verdict"] = BLOCK
    elif len(output[SAFE]) > 0:
        output["Verdict"] = SAFE
    return output


def ipmode(ip):
    output = {"ip": ip, "Verdict": NONE, SAFE: [], BLOCK: []}
    safe = []
    block = []
    vt = virusTotalIP(ip)
    output, safe, block = addScore(VT, "0", vt, output, safe, block)
    abip = abusedIP(ip)
    output, safe, block = addScore(ABIP, "0", abip, output, safe, block)
    fg = fraudGuard(ip)
    output, safe, block = addScore(FG, "1 ", fg, output, safe, block)
    ibm_rec = ibm_IP(ip)
    output, safe, block = addScore(IBM, "1 ", ibm_rec, output, safe, block)
    ath0 = auth0(ip)
    output, safe, block = addScore(AUTH0, "0", ath0, output, safe, block)
    # data = [ip, ibm_rec, vt, abip, fg, ath0]
    # if ss_mode:
    #     ct = ss.ciscoTalos(ip)
    #     data.append(ct)
    output[SAFE] = safe
    output[BLOCK] = block
    return get_verdict(output)


def urlmode(url):
    output = {"url": url, "Verdict": NONE, SAFE: [], BLOCK: []}
    safe = []
    block = []
    vt = virusTotalURL(url)
    output, safe, block = addScore(VT, "0", vt, output, safe, block)
    ibm_rec = ibm_url(url)
    output, safe, block = addScore(IBM, "1 ", ibm_rec, output, safe, block)
    gsb = googleSafe(url)
    output, safe, block = addScore(GOOGLE, "Safe", gsb, output, safe, block)
    pt = phishtank(url)
    output, safe, block = addScore(PHISH, "Not ", pt, output, safe, block)
    # data = [url, ibm_rec, vt, gsb, pt]
    # if ss_mode:
    #     usc = urlscan(url)
    #     uscuuid = usc[1]
    #     usc = usc[0]
    #     ct = ss.ciscoTalos(url)
    #     data.append(usc)
    #     data.append(uscuuid)
    #     data.append(ct)
    output[SAFE] = safe
    output[BLOCK] = block
    return get_verdict(output)


def hashmode(a_hash):
    output = {"hash": a_hash, "Verdict": NONE}
    vt = virusTotalHash(a_hash)
    output["MD5"] = vt[1]
    output["SHA1"] = vt[2]
    output["SHA256"] = vt[3]
    output[VT] = vt[4]
    if vt[4].startswith("0"):
        output["Verdict"] = SAFE
    elif vt[4] == NONE:
        pass
    else:
        output["Verdict"] = BLOCK
    return output


def filemode(a_file):
    output = {"file": a_file, "Verdict": NONE}
    vt = virusTotalFile(a_file)
    output[VT] = vt[0]
    output["File Hash"] = vt[1]
    if vt[0].startswith("0"):
        output["Verdict"] = SAFE
    elif vt[0] == NONE:
        pass
    else:
        output["Verdict"] = BLOCK
    return


def checker():
    # variables
    args = demisto.args()
    # if ss_mode:
    #     ss.makeFileName(file_to_read)
    output = NONE
    markdown = NONE
    output_key = NONE
    ec = {}  # type: dict

    if args.get('ip'):
        output = ipmode(args.get('ip'))
        markdown = '### Indicator: ' + args.get('ip') + '\n'
        markdown += tableToMarkdown('Results', output, headers=['ip', 'Verdict', SAFE, BLOCK, VT, ABIP, FG, IBM, AUTH0])
        output_key = 'ip'
        ec.update({
            outputPaths['ip']: {
                'Address': output['ip'],
                'Reputation': [
                    output[VT],
                    output[ABIP],
                    output[FG],
                    output[IBM],
                    output[AUTH0]
                ],
                'Verdict': output["Verdict"]
            }
        })
    elif args.get('url'):
        output = urlmode(args.get('url'))
        markdown = '### Indicator: ' + args.get('url') + '\n'
        markdown += tableToMarkdown('Results', output, headers=['url', 'Verdict', SAFE, BLOCK, VT, IBM, GOOGLE, PHISH])
        output_key = 'url'
        ec.update({
            outputPaths['url']: {
                'URL': output['url'],
                'Reputation': [
                    output[VT],
                    output[IBM],
                    output[GOOGLE],
                    output[PHISH]
                ],
                'Verdict': output["Verdict"]
            }
        })
    elif args.get('hash'):
        output = hashmode(args.get('hash'))
        markdown = '### Indicator: ' + args.get('hash') + '\n'
        markdown += tableToMarkdown('Results', output, headers=['hash', 'Verdict', "MD5", "SHA1", "SHA256", VT])
        output_key = 'hash'
        ec.update({
            'Hash': output['hash'],
            'Equivalent': [
                output["MD5"],
                output["SHA1"],
                output["SHA256"]
            ],
            'Reputation': output[VT],
            'Verdict': output["Verdict"]
        })
    elif args.get('file'):
        output = filemode(args.get('file'))
        markdown = '### Indicator: ' + args.get('file') + '\n'
        markdown += tableToMarkdown('Results', output, headers=['file', 'Verdict', VT])
        output_key = 'file'
        ec.update({
            outputPaths['file']: {
                'File': output['file'],
                'Reputation': output[VT],
                'Verdict': output["Verdict"]
            }
        })
    else:
        markdown = help()

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='Checker',
        outputs_key_field=output_key,
        outputs=output
    )
    return_results(results)


def checker_batch():
    # variables
    args = demisto.args()
    # if ss_mode:
    #     ss.makeFileName(file_to_read)
    markdown = ""
    output_key = ""
    ec = {}  # type: dict
    result = []
    if args.get('ips'):
        header = ['ip', 'Verdict', SAFE, BLOCK, VT, ABIP, FG, IBM, AUTH0]
        for address in args.get('ips'):
            ip = address["Address"]
            output = ipmode(ip)
            result.append(output)
            save_record_csv(output, "ip.csv", header)
            ec.update({
                outputPaths['ip']: {
                    'Address': output['ip'],
                    'Reputation': [
                        output[VT],
                        output[ABIP],
                        output[FG],
                        output[IBM],
                        output[AUTH0]
                    ],
                    'Verdict': output["Verdict"]
                }
            })

        markdown = '### IP Batch Reputation Check\n'
        markdown += tableToMarkdown('Results', result, headers=header)
        output_key = 'ip'

    elif args.get('urls'):
        header = ['url', 'Verdict', SAFE, BLOCK, VT, IBM, GOOGLE, PHISH]
        for link in args.get('urls'):
            url = link["Name"]
            output = urlmode(url)
            result.append(output)
            save_record_csv(output, "url.csv", header)
            ec.update({
                outputPaths['url']: {
                    'URL': output['url'],
                    'Reputation': [
                        output[VT],
                        output[IBM],
                        output[GOOGLE],
                        output[PHISH]
                    ],
                    'Verdict': output["Verdict"]
                }
            })

        markdown = '### URL Batch Reputation Check\n'
        markdown += tableToMarkdown('Results', result, headers=header)
        output_key = 'url'

    elif args.get('hashes'):
        header = ['hash', 'Verdict', "MD5", "SHA1", "SHA256", VT]
        for a_hash in args.get('hashes'):
            h = next(iter(a_hash.values()))
            output = hashmode(h)
            result.append(output)
            save_record_csv(output, "url.csv", header)
            ec.update({
                'Hash': output['hash'],
                'Equivalent': [
                    output["MD5"],
                    output["SHA1"],
                    output["SHA256"]
                ],
                'Reputation': output[VT],
                'Verdict': output["Verdict"]
            })

        markdown = '### Hash Batch Reputation Check\n'
        markdown += tableToMarkdown('Results', result, headers=header)
        output_key = 'hash'

    else:
        markdown = help()

    ec.update({
        outputPaths['file']: {
            'Output': result
        }
    })

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='Checker',
        outputs_key_field=output_key,
        outputs=result
    )
    return_results(results)


def help():
    markdown = '### Help text\n'
    markdown += 'For single IOC:\n'
    markdown += 'Command: !Checker ip=x.x.x.x\n'
    markdown += 'For batch IOC:\n'
    markdown += '1. Create new incident with playbook Checker_Batch_IP or URL or Hash\n'
    markdown += '2. Attach csv file containing indicators in column 0\n'
    return markdown


def say_hello_command(client, args):
    """
    Returns Hello {somename}

    Args:
        client (Client): HelloWorld client.
        args (dict): all command arguments.

    Returns:
        Hello {someone}

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs
                        for other tasks in the playbook
        raw_response (dict): Used for debugging/troubleshooting purposes -
                            will be shown only if the command executed with raw-response=true
    """
    name = args.get('name')

    result = client.say_hello(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def say_hello_over_http_command(client, args):
    name = args.get('name')

    result = client.say_hello_http_request(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = dateparser.parse(item['created_time'])
        incident = {
            'name': item['description'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1/suffix')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'hello':  # hello
            return_outputs(*say_hello_command(client, demisto.args()))

        # elif demisto.command() == 'check-file':
        #     demisto.results(check_file())
        elif demisto.command() == 'checker':
            demisto.results(checker())
        elif demisto.command() == 'checker-batch':
            demisto.results(checker_batch())

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
