import ipaddress

import dateparser
from selenium.webdriver.chrome.options import Options

import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS
import hashlib
import requests
import json
import csv
import os
from time import sleep, time
from requests.auth import HTTPBasicAuth
from selenium import webdriver
from selenium.common.exceptions import *
from selenium.webdriver.common.by import By
# from bs4 import BeautifulSoup
from urllib.parse import quote
import base64
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from datetime import datetime
from zipfile import ZipFile

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CHROME_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36'  # noqa
# param constants
VT_KEY = demisto.params().get('virustotal_apikey', '')
ABIP_KEY = demisto.params().get('abusedipdb_apikey', '')
IBM_KEY = demisto.params().get('ibm_key', '') + ":" + demisto.params().get('ibm_pass', '')
URLSCAN_KEY = demisto.params().get('urlscan_apikey', '')
GOOGLE_KEY = demisto.params().get('googleSafeBrowsing_apikey', '')
AUTH0_KEY = demisto.params().get('auth0_apikey', '')
PHISH_KEY = demisto.params().get('phishtank_apikey', '')
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
ABIP = 'AbuseIP'
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

timeout = 20
imageName = "checker"


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

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


def init_driver():
    demisto.debug(f'Creating chrome driver.')
    try:
        options = webdriver.ChromeOptions()
        options.add_argument('--no-sandbox')
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument("--window-size=1680x1050")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument(f'--user-agent={CHROME_USER_AGENT}')
        # options.add_experimental_option("excludeSwitches", ["enable-automation", 'enable-logging'])
        # options.add_experimental_option('useAutomationExtension', False)

        driver = webdriver.Chrome(options=options)
        # if offline_mode:
        #     driver.set_network_conditions(offline=True, latency=5, throughput=500 * 1024)
    except Exception as ex:
        demisto.info(f'Unexpected exception: {ex}\nTrace:{traceback.format_exc()}')

    demisto.debug('Creating chrome driver - COMPLETED')
    return driver


def save_record_csv(data, filename, header):
    demisto.info("Saving Record")
    with open(filename, mode="a+", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=header)
        if os.stat(filename).st_size == 0:
            writer.writeheader()
        writer.writerow(data)


def vt_result(result):
    try:
        harmless = int(result.json()['data']['attributes']['last_analysis_stats']['harmless'])
        malicious = int(result.json()['data']['attributes']['last_analysis_stats']['malicious'])
        suspicious = int(result.json()['data']['attributes']['last_analysis_stats']['suspicious'])
        undetected = int(result.json()['data']['attributes']['last_analysis_stats']['undetected'])
        rate = str(malicious) + " // " + str(malicious + harmless + suspicious + undetected)
        if malicious > 0:
            dbot = Common.DBotScore.BAD
        elif suspicious > 0:
            dbot = Common.DBotScore.SUSPICIOUS
        else:
            dbot = Common.DBotScore.GOOD
    except (KeyError, TypeError) as e:
        demisto.info(VT + " - vt_result() - " + str(e))
        rate = NONE
        dbot = Common.DBotScore.NONE
    except Exception as e:
        demisto.info(VT + " - vt_result() - " + str(e))
        rate = NONE
        dbot = Common.DBotScore.NONE
    finally:
        return rate, dbot


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


def vt_screenshot(obj):
    if ss_mode:
        if not screenshot_virusTotal(obj):
            print(VT + ": " + SS_FAILED)


def virusTotalIP(ip):
    vt_screenshot(ip)
    try:
        resp = requests.get(VT_IP.format(ip), headers={'Accept': 'application/json', 'x-apikey': VT_KEY})
        vt_exception(resp)
    except Exception as e:
        vt = NONE
        demisto.info(VT + " - " + str(e))
    else:
        # available status: harmless, malicious, suspicious, timeout, undetected
        vt, dbot = vt_result(resp)
    finally:
        # print(VT + ": " + vt)
        return vt, dbot


def virusTotalURL(url):
    headers = {'Accept': 'application/json', 'x-apikey': VT_KEY}
    try:  # send url to scan
        resp = requests.post(VT_URL, headers=headers, data={'url': url})
        vt_exception(resp)
        req_id = resp.json()['data']['id'].split('-')[1]
    except Exception as e:
        demisto.info(VT + " - " + str(e))
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
        dbot = Common.DBotScore.NONE
        demisto.info(VT + " - " + str(e))
    else:
        # available status: harmless, malicious, suspicious, timeout, undetected
        vt, dbot = vt_result(resp)
    finally:
        vt_screenshot(url)
        # print(VT + ": " + vt)
        demisto.info(VT + " - " + vt)
        return vt, dbot


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
            resp = requests.post(VT_FILE, headers={'Accept': 'application/json', 'x-apikey': VT_KEY}, files=data)
        else:  # bigger than 32 mb - there may be performance issue as a file gets too big
            resp = requests.get(VT_FILE_BIG, headers={'Accept': 'application/json', 'x-apikey': VT_KEY})
            vt_exception(resp)
            upload_url = resp.json()['data']
            resp = requests.post(upload_url, headers={'Accept': 'application/json', 'x-apikey': VT_KEY}, files=data)
        vt_exception(resp)
    except Exception as e:
        vt = NONE
        dbot = Common.DBotScore.NONE
        demisto.info(VT + " - " + str(e))
    else:
        vt, dbot = vt_result(resp)
        filehash = str(getmd5(file))
        # retrieve analysis
        vt, dbot = virusTotalHash([filehash, file])
        # vt = [vt[4], filehash]
    finally:
        # print(VT + ": " + str(vt))
        demisto.info(VT + " - " + str(vt))
        return vt, dbot


def virusTotalHash(a_hash):
    vt_screenshot(a_hash)
    if mode == FILE_MODE:
        a_hash = a_hash[0]
    try:
        resp = requests.get(VT_FILE + '/{}'.format(a_hash), headers={'Accept': 'application/json', 'x-apikey': VT_KEY})
        vt_exception(resp)
    except Exception as e:
        vt = NONE
        dbot = Common.DBotScore.NONE
        print(str(e))
        demisto.info(VT + " - " + str(e))
    else:
        # Status: confirmed-timeout, failure, harmless, malicious, suspicious, timeout, type-unsupported, undetected
        vt, dbot = vt_result(resp)
    finally:
        # print(VT + ": " + str(vt))
        demisto.info(VT + " - " + vt)

    try:
        md5 = resp.json()['data']['attributes']['md5']
        sha1 = resp.json()['data']['attributes']['sha1']
        sha256 = resp.json()['data']['attributes']['sha256']
        # print("md5: " + md5 + ", SHA1: " + sha1 + ", SHA256: " + sha256)
    except (KeyError, TypeError) as e:
        demisto.info(VT + " - virusTotalHash() - " + str(e))
        md5 = NONE
        sha256 = NONE
        sha1 = NONE
    finally:
        data = [a_hash, md5, sha1, sha256, vt]
        return data, dbot


def getScreenshotIBM(obj):
    if ss_mode:
        if not screenshot_IBM(obj):
            print(IBM + ": " + SS_FAILED)


def IBM_exceptionHandle(resp):
    demisto.info(IBM + " - " + str(resp.json()))
    if resp.status_code == 402:
        print(IBM + ": Monthly quota exceeded")
    elif resp.status_code == 401:
        print(IBM + ": Not Authorized. Check API key and pass")
    elif str(resp.status_code).startswith('5'):
        print(IBM + EX_SERVER.format(IBM))


# call to this function when url mode on
def ibm_url(url):
    getScreenshotIBM(url)
    pass_data = IBM_KEY
    data = base64.b64encode(pass_data.encode())
    final = str(data.decode('utf-8'))
    ibm_headers = {"Content-Type": "application/json", "Authorization": "Basic " + final}
    resp = requests.get(IBM_URL.format(quote(url)), headers=ibm_headers)
    if str(resp.status_code).startswith('2'):
        try:
            rate = str(resp.json()['result']['score']) + " // 10"
            if rate.startswith("1 "):
                dbot = Common.DBotScore.GOOD
            else:
                dbot = Common.DBotScore.BAD
        except:
            rate = UNKNOWN
            dbot = Common.DBotScore.NONE
    elif resp.status_code == 404:
        rate = UNKNOWN
        dbot = Common.DBotScore.NONE
        demisto.info(IBM + " - Not found in database")
    else:
        dbot = Common.DBotScore.NONE
        rate = NONE
        IBM_exceptionHandle(resp)

    # print(IBM + ": " + rate)
    demisto.info(IBM + " - " + rate)
    return rate, dbot


# call to this function when ip mode on
def ibm_IP(ip):
    getScreenshotIBM(ip)
    pass_data = IBM_KEY
    data = base64.b64encode(pass_data.encode())
    final = str(data.decode('utf-8'))
    ibm_headers = {"Content-Type": "application/json", "Authorization": "Basic " + final}
    resp = requests.get(IBM_IP.format(ip), headers=ibm_headers)
    if str(resp.status_code).startswith('2'):
        try:
            rate = str(resp.json()['history'][-1]['score']) + " // 10"
            if rate.startswith("1 "):
                dbot = Common.DBotScore.GOOD
            else:
                dbot = Common.DBotScore.BAD
        except:
            rate = UNKNOWN
            dbot = Common.DBotScore.NONE
    elif resp.status_code == 404:
        rate = UNKNOWN
        dbot = Common.DBotScore.NONE
        demisto.info(IBM + " - Not found in database")
    else:
        rate = NONE
        dbot = Common.DBotScore.NONE
        IBM_exceptionHandle(resp)

    # print(IBM + ": " + rate)
    demisto.info(IBM + " - " + rate)
    return rate, dbot


# only works for url, no ip support
def abusedIP(ip):
    if ss_mode:
        if not screenshot_abusedIP(ip):
            print(ABIP + ": " + SS_FAILED)
    headers = {
        'Key': ABIP_KEY,
        'Accept': 'application/json',
    }
    params = {'ipAddress': ip}
    try:
        resp = json.loads(requests.get(ABIP_IP, headers=headers, params=params).text)
        rate = str(resp['data']["abuseConfidenceScore"]) + " // 100"
        if rate.startswith("0"):
            dbot = Common.DBotScore.GOOD
        else:
            dbot = Common.DBotScore.BAD
    except:
        rate = NONE
        dbot = Common.DBotScore.NONE
        error = resp['errors']
        if error[0]['status'] == 429 or error[0]['status'] == 401:
            print(ABIP + ": " + error[0]['detail'])
        elif str(error[0]['status']).startswith('5'):
            print(ABIP + EX_SERVER.format(ABIP))
        demisto.info(ABIP + " - virusTotalHash() - " + str(error[0]['detail']))
    finally:
        # print(ABIP + ": " + rate)
        demisto.info(ABIP + " - " + rate)
        return rate, dbot


def fraudGuard(ip):
    if ss_mode:
        if not screenshot_fraudguard(ip):
            print(FG + ": " + SS_FAILED)

    try:
        username = FG_KEY.strip().split(':')[0]
        password = FG_KEY.strip().split(':')[1]
    except IndexError:
        rate = NONE
        dbot = Common.DBotScore.NONE
        demisto.info(FG + " - " + "No API keys provided")
        print(FG + ": API keys not provided in config.txt")
        print(FG + ": " + rate)
        demisto.info(FG + " - " + rate)
        return rate, dbot
    resp = requests.get(FG_IP.format(ip), verify=True, auth=HTTPBasicAuth(username, password))
    try:
        rate = json.loads(resp.text)['risk_level'] + " // 5"
        # 1: No Risk
        # 2: Spam/ website abuse
        # 3: Open public proxy
        # 4: Tor Node
        # 5: Honeypot, malware, botnet, ddos
        if rate.startswith("1"):
            dbot = Common.DBotScore.GOOD
        else:
            dbot = Common.DBotScore.BAD
    except:
        rate = NONE
        dbot = Common.DBotScore.NONE
        demisto.info(FG + " - " + str(resp.text))
        if resp.status_code == 401:
            print(FG + ": Invalid key - " + FG_KEY + " - Check credentials")
        elif str(resp.status_code).startswith('5'):
            print(FG + ": FraudGaurd is having problems. Please try again later")
        elif resp.status_code == 429:
            print(FG + ": API limit reached for FG key")
    finally:
        # print(FG + ": " + rate)
        demisto.info(FG + " - " + rate)
        return rate, dbot


def auth0(ip):
    if ss_mode:
        if not screenshot_auth0(ip):
            print(AUTH0 + ": " + SS_FAILED)
    headers = {
        "Accept": "application/json",
        "X-Auth-Token": AUTH0_KEY
    }
    try:
        resp = requests.get(AUTH0_IP.format(ip), headers=headers).json()
        score = str(resp['fullip']['score']).strip()
        if score.startswith("0"):
            dbot = Common.DBotScore.GOOD
        else:
            dbot = Common.DBotScore.BAD
    except:
        score = NONE
        dbot = Common.DBotScore.NONE
        demisto.info(AUTH0 + " - " + str(resp))
    finally:
        # print(AUTH0 + ": " + score)
        demisto.info(AUTH0 + " - " + score)
        return score, dbot


def googleSafe(url):
    if ss_mode:
        if not screenshot_googleSafe(url):
            print(GOOGLE + ": " + SS_FAILED)
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
            dbot = Common.DBotScore.BAD
        else:
            gsb = "Safe"
            dbot = Common.DBotScore.GOOD
    else:
        gsb = NONE
        dbot = Common.DBotScore.NONE
        if resp.status_code == 429:
            print(GOOGLE + ": Requests Exceeded!")
        elif str(resp.status_code).startswith('5'):
            print(GOOGLE + EX_SERVER.format(GOOGLE))
        demisto.info(GOOGLE + " - " + str(resp.json()))
    # print(GOOGLE + ": " + gsb)
    demisto.info(GOOGLE + " - " + gsb)
    return gsb, dbot


def phishtank(url):
    if ss_mode:
        if not screenshot_phishtank(url):
            print(PHISH + ": " + SS_FAILED)
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
                dbot = Common.DBotScore.SUSPICIOUS
            elif resp.json()['results']['verified'] and resp.json()['results']['valid']:  # if phish return malicious
                result = "Phish"
                dbot = Common.DBotScore.BAD
            else:  # if verified as not a phish
                result = "Not a Phish"
                dbot = Common.DBotScore.GOOD
        else:  # if result not found in database
            result = UNKNOWN
            dbot = Common.DBotScore.NONE
    else:
        result = NONE
        dbot = Common.DBotScore.NONE
        demisto.info(PHISH + " - " + str(resp.json()))
        if resp.status_code == 509:
            print(PHISH + ": Requests Exceeded! Please wait at most 5 minutes to reset the number of requests.")
    # print(PHISH + ": " + str(result))
    demisto.info(PHISH + " - " + str(result))
    return result, dbot


def urlscan(url):
    headers = {"API-Key": URLSCAN_KEY}
    data = {"url": url}
    try:
        # send scan request
        resp = requests.post(URLSCAN_URL, data=data, headers=headers)
        uuid = resp.json()['uuid']
        nextpage = resp.json()['api']
    except:
        score = NONE
        uuid = NONE
        logging.exceptionURLSCAN + " - " + str(resp.json())
        if resp.status_code == 401:
            print(URLSCAN + EX_UNAUTH)
    else:
        begin = time()
        time_elapsed = 0
        result = requests.get(nextpage)
        # repeat until url has finished scanning. Max time is 65seconds
        while result.status_code == 404 and time_elapsed < 65:
            sleep(5)
            result = requests.get(nextpage)
            time_elapsed = time() - begin
        try:
            score = str(result.json()['verdicts']['overall']['score']) + " out of 100"
            if score.startswith("0 "):
                dbot = Common.DBotScore.GOOD
            else:
                dbot = Common.DBotScore.BAD
        except:
            score = NONE
            dbot = Common.DBotScore.NONE
            logging.exception(URLSCAN + " - " + str(result.json()))
        finally:
            with open(imageName.format(""), "wb+") as img_sc:
                try:
                    img_sc.write(requests.get(URLSCAN_SS_ORIGIN + uuid + ".png").content)
                    # print(URLSCAN + ": Screenshot of target URL saved")
                except:
                    print(URLSCAN + ": Failed to save screenshot of target URL")
            res = fileResult(filename=imageName.format(""), data=open(imageName.format(""), "rb").read())
            res['Type'] = entryTypes['image']
            return_results(res)
            with ZipFile(mode + '.zip', 'a') as zipObj:
                zipObj.write(imageName.format(""))
            if not screenshot_urlscan(uuid):
                print(URLSCAN + ": " + SS_FAILED)
    finally:
        # print(URLSCAN + ": " + score)
        logging.info(URLSCAN + " - " + score)
        return [str(score), uuid], dbot


# Screenshot mode
def screenshot_phishtank(url):
    driver = init_driver()
    driver.get(PHISH_SS)
    try:
        element_present = EC.presence_of_element_located((By.ID, 'main'))
        WebDriverWait(driver, timeout).until(element_present)
        input = driver.find_element_by_xpath("//input[@type='text' and @name='isaphishurl' and @value='http://']")
        input.clear()
        input.send_keys(url)
        driver.find_element_by_xpath("//input[@type='submit' and @class='submitbutton']").click()
        image = driver.get_screenshot_as_png()
        save_image(image, PHISH)
        saved = True
        demisto.info(PHISH + " - Screenshot saved at " + imageName.format(PHISH))
    except WebDriverException as e:
        demisto.info(PHISH + " - Screenshot - " + str(e))
        saved = False
    finally:
        driver.quit()
        return saved


def screenshot_auth0(ip):
    driver = init_driver()
    driver.get(AUTH0_SS.format(ip))
    try:
        element_present = EC.presence_of_element_located((By.XPATH, '//section[@data-results-register="true"]'))
        WebDriverWait(driver, timeout).until(element_present)
        driver.execute_script("window.scrollTo(0, 200)")
        image = driver.get_screenshot_as_png()
        save_image(image, AUTH0)
        saved = True
        demisto.info(AUTH0 + " - Screenshot saved at " + imageName.format(AUTH0))
    except WebDriverException as e:
        demisto.info(AUTH0 + " - Screenshot - " + str(e))
        saved = False
    finally:
        driver.quit()
        return saved


def screenshot_googleSafe(url):
    driver = init_driver()
    driver.get(GOOGLE_SS.format(url))
    try:
        element_present = EC.presence_of_element_located((By.TAG_NAME, 'data-tile'))
        WebDriverWait(driver, timeout).until(element_present)
        image = driver.get_screenshot_as_png()
        save_image(image, GOOGLE)
        saved = True
        demisto.info(GOOGLE + " - Screenshot saved at " + imageName.format(GOOGLE))
    except WebDriverException as e:
        demisto.info(GOOGLE + " - Screenshot - " + str(e))
        saved = False
    finally:
        driver.quit()
        return saved


def screenshot_fraudguard(ip):
    driver = init_driver()
    driver.get(FG_SS.format(ip))
    try:
        element_present = EC.presence_of_element_located((By.CLASS_NAME, 'col-md-6'))
        WebDriverWait(driver, timeout).until(element_present)
        driver.execute_script("window.scrollTo(0, 500)")
        image = driver.get_screenshot_as_png()
        save_image(image, FG)
        saved = True
        demisto.info(FG + " - Screenshot saved at " + imageName.format(FG))
    except WebDriverException as e:
        demisto.info(FG + " - Screenshot - " + str(e))
        saved = False
    finally:
        driver.quit()
        return saved


def screenshot_abusedIP(ip):
    driver = init_driver()
    driver.get(ABIP_SS.format(ip))
    try:
        element_present = EC.presence_of_element_located((By.CLASS_NAME, 'well'))
        WebDriverWait(driver, timeout).until(element_present)
        image = driver.get_screenshot_as_png()
        save_image(image, ABIP)
        saved = True
        demisto.info(ABIP + " - Screenshot saved at " + imageName.format(ABIP))
    except WebDriverException as e:
        demisto.info(ABIP + " - Screenshot - " + str(e))
        saved = False
    finally:
        driver.quit()
        return saved

# for url and ip


def screenshot_IBM(obj):
    driver = init_driver()
    driver.implicitly_wait(5)
    driver.get(IBM_SS.format(quote(obj)))
    element_present = EC.presence_of_element_located((By.CLASS_NAME, 'modal-dialog'))
    WebDriverWait(driver, timeout).until(element_present)
    # terms and condition + guest login
    driver.find_element_by_xpath("//input[@ng-model='termsCheckbox']").click()
    driver.find_element_by_xpath("//a[@ng-click='guest()']").click()
    try:  # Close help pop up if there is
        element = driver.find_element_by_xpath("//button[@ng-click='$ctrl.actionButtonHandler()']")
        driver.execute_script("arguments[0].click();", element)
    except WebDriverException as e:
        # demisto.info(IBM + " - Screenshot - " + str(e))
        pass
    # Make sure score element is there for screenshot
    element_present = EC.presence_of_element_located((By.ID, 'report'))
    WebDriverWait(driver, timeout).until(element_present)
    # To print score
    # try:
    # element_present = EC.presence_of_element_located((By.ID, 'report'))
    # WebDriverWait(driver, timeout).until(element_present)
    # riskLevel = str(driver.find_element_by_class_name('scorebackgroundfilter numtitle').text).split()[0]
    # soup = BeautifulSoup(driver.page_source, 'html.parser')
    # riskLevel = soup.find('div', attrs={'class': 'scorebackgroundfilter numtitle'}).text.split()[0]
    # if riskLevel != "Unknown":
    #     riskLevel = str(riskLevel) + " out of 10"
    # except:
    #     riskLevel = NONE
    #     demisto.info(IBM + " - Screenshot")
    try:
        image = driver.get_screenshot_as_png()
        save_image(image, IBM)
        saved = True
        demisto.info(IBM + " - Screenshot saved at " + imageName.format(IBM))
    except WebDriverException as e:
        demisto.info(IBM + " - Screenshot - " + str(e))
        print(IBM + ": " + SS_FAILED)
        saved = False
    finally:
        driver.quit()
        return saved


def screenshot_urlscan(uuid):
    driver = init_driver()
    driver.get(URLSCAN_SS.format(uuid))
    try:
        element_present = EC.presence_of_element_located((By.CLASS_NAME, 'container'))
        WebDriverWait(driver, timeout).until(element_present)
        image = driver.get_screenshot_as_png()
        save_image(image, URLSCAN)
        saved = True
        demisto.info(URLSCAN + " - Screenshot saved at " + imageName.format(URLSCAN))
    except WebDriverException as e:
        demisto.info(URLSCAN + " - Screenshot - " + str(e))
        saved = False
    finally:
        driver.quit()
        return saved


def screenshot_virusTotal(obj):
    driver = init_driver()
    driver.implicitly_wait(3)
    driver.set_page_load_timeout(60)
    target = obj
    identifier = mode
    if mode == URL_MODE:
        encoded_url = base64.b64encode(obj.encode())
        target = encoded_url.decode().replace('=', '')
    elif mode == IP_MODE:
        identifier = 'ip-address'
    elif mode == HASH_MODE:
        identifier = 'file'
    elif mode == FILE_MODE:
        target = obj[0]
        makeFileName(obj)
    driver.get(VT_SS.format(identifier=identifier, target=target))
    try:
        element_present = EC.presence_of_element_located((By.TAG_NAME, 'vt-virustotal-app'))
        WebDriverWait(driver, timeout).until(element_present)
        # To check scores are same with the VT API
        root = str(driver.find_element_by_tag_name('vt-virustotal-app').text)
        res = root.find("Community\nScore")
        while res is -1:
            sleep(1)
            root = str(driver.find_element_by_tag_name('vt-virustotal-app').text)
            res = root.find("Community\nScore")

        # positives = int(''.join(list(filter(str.isdigit, substr.split("/")[0]))))
        # total = int(''.join(list(filter(str.isdigit, substr.split("/")[1]))))
        # rate = str(positives) + " out of " + str(total)
        # print(rate)
        image = driver.get_screenshot_as_png()
        save_image(image, VT)
        saved = True
        demisto.info(VT + " - Screenshot saved as " + imageName.format(VT))
    except Exception as e:
        saved = False
        demisto.info(VT + " - Screenshot - " + str(e))
    finally:
        driver.quit()
        return saved


# works for both ip or url
def screenshot_ciscoTalos(iporurl):
    driver = init_driver()
    driver.get(CISCO_SS + quote(iporurl))
    try:
        element_present = EC.presence_of_element_located((By.CLASS_NAME, 'new-legacy-label'))
        WebDriverWait(driver, timeout).until(element_present)
        web_reputation = str(driver.find_element_by_class_name('new-legacy-label').text).split()[0]
        if web_reputation == "Neutral" or web_reputation == "Favorable" or web_reputation == "Trusted":
            dbot = Common.DBotScore.GOOD
        elif web_reputation == "Unknown":
            dbot = Common.DBotScore.NONE
        else:
            dbot = Common.DBotScore.BAD
        if ss_mode:
            image = driver.get_screenshot_as_png()
            save_image(image, CISCO)
            # print(CISCO + ": " + SS_SAVED)
            demisto.info(CISCO + " - Screenshot saved at " + imageName.format(CISCO))
        # results: Trusted, Favorable, Neutral, Questionable, Untrusted, Unknown
    except WebDriverException as e:
        web_reputation = NONE
        dbot = Common.DBotScore.NONE
        demisto.info(CISCO + " - Screenshot - " + str(e))
        print(CISCO + ": " + SS_FAILED)
        try:
            element_present = EC.presence_of_element_located((By.ID, 'cf-wrapper'))
            WebDriverWait(driver, timeout).until(element_present)
            print(CISCO + ": Please go to {} to check if captcha is required and complete it once"
                  .format(CISCO_SS + quote(iporurl)))
            demisto.info(CISCO + " - Recaptcha is required")
        except:
            pass
    finally:
        driver.quit()
        # print(CISCO + ": " + web_reputation)
        demisto.info(CISCO_SS + " - " + web_reputation)
        return web_reputation, dbot


def save_image(image, name):
    res = fileResult(filename=imageName.format(name), data=image)
    res['Type'] = entryTypes['image']
    return_results(res)
    add_to_zip(image, name)


def add_to_zip(image, name):
    with open(imageName.format(name), 'wb') as f:
        f.write(image)
    with ZipFile(mode + '.zip', 'a') as zipObj:
        zipObj.write(imageName.format(name))


# For url and ip
def makeFileName(obj):
    name = obj
    if mode == URL_MODE:
        name = obj.split("://")
        if len(name) >= 2:
            name = name[1].split("/")[0]
        else:
            name = name[0].split("/")[0]
    elif mode == FILE_MODE:
        name = obj[1].split("/")[-1].split(".")[0]
    return f'' + name + "_{}.png"


def addScore(name, dbot, score, data, safe, block):
    data[name] = score
    if dbot == Common.DBotScore.NONE or dbot == Common.DBotScore.GOOD:
        safe.append(name)
    else:
        block.append(name)
    return data, safe, block


# def addScore_cisco(name, score, data, safe, block):
#     data[name] = score
#     if score != NONE:
#         if score == "Neutral" or score == "Favorable" or score == "Trusted" or score == "Unknown":
#             safe.append(name)
#         else:
#             block.append(name)
#     return data, safe, block


def get_verdict(output):
    if len(output[BLOCK]) > 0:
        output["Verdict"] = BLOCK
    elif len(output[SAFE]) > 0:
        output["Verdict"] = SAFE
    return output


def ipmode(ip):
    global imageName, mode
    mode = IP_MODE
    output = {"ip": ip, "Verdict": NONE, SAFE: [], BLOCK: []}
    if ss_mode:
        imageName = makeFileName(ip)
    safe = []
    block = []
    vt, dbot = virusTotalIP(ip)
    output_ip(ip, VT, vt, dbot)
    output, safe, block = addScore(VT, dbot, vt, output, safe, block)
    abip, dbot = abusedIP(ip)
    output_ip(ip, ABIP, abip, dbot)
    output, safe, block = addScore(ABIP, dbot, abip, output, safe, block)
    fg, dbot = fraudGuard(ip)
    output_ip(ip, FG, fg, dbot)
    output, safe, block = addScore(FG, dbot, fg, output, safe, block)
    ibm_rec, dbot = ibm_IP(ip)
    output_ip(ip, IBM, ibm_rec, dbot)
    output, safe, block = addScore(IBM, dbot, ibm_rec, output, safe, block)
    ath0, dbot = auth0(ip)
    output_ip(ip, AUTH0, ath0, dbot)
    output, safe, block = addScore(AUTH0, dbot, ath0, output, safe, block)
    if ss_mode:
        ct, dbot = screenshot_ciscoTalos(ip)
        output_ip(ip, CISCO, ct, dbot)
        output, safe, block = addScore(CISCO, dbot, ct, output, safe, block)
    output[SAFE] = safe
    output[BLOCK] = block
    return get_verdict(output)


def urlmode(url):
    global imageName, mode
    mode = URL_MODE
    output = {"url": url, "Verdict": NONE, SAFE: [], BLOCK: []}
    if ss_mode:
        imageName = makeFileName(url)
    safe = []
    block = []
    vt, dbot = virusTotalURL(url)
    output_url(url, VT, vt, dbot)
    output, safe, block = addScore(VT, dbot, vt, output, safe, block)
    ibm_rec, dbot = ibm_url(url)
    output_url(url, IBM, ibm_rec, dbot)
    output, safe, block = addScore(IBM, dbot, ibm_rec, output, safe, block)
    gsb, dbot = googleSafe(url)
    output_url(url, GOOGLE, gsb, dbot)
    output, safe, block = addScore(GOOGLE, dbot, gsb, output, safe, block)
    pt, dbot = phishtank(url)
    output_url(url, PHISH, pt, dbot)
    output, safe, block = addScore(PHISH, dbot, pt, output, safe, block)
    if ss_mode:
        usc, dbot = urlscan(url)
        uscuuid = usc[1]
        usc = usc[0]
        output_url(url, URLSCAN, usc, dbot)
        output, safe, block = addScore(URLSCAN, dbot, usc, output, safe, block)
        ct, dbot = screenshot_ciscoTalos(url)
        output_url(url, CISCO, ct, dbot)
        output, safe, block = addScore(CISCO, dbot, ct, output, safe, block)
    output[SAFE] = safe
    output[BLOCK] = block
    return get_verdict(output)


def hashmode(a_hash):
    global imageName, mode
    mode = HASH_MODE
    output = {"hash": a_hash, "Verdict": NONE}
    if ss_mode:
        imageName = makeFileName(a_hash)
    vt, dbot = virusTotalHash(a_hash)
    output_hash(a_hash, VT, vt, dbot)
    output["MD5"] = vt[1]
    output["SHA1"] = vt[2]
    output["SHA256"] = vt[3]
    output[VT] = vt[4]
    if vt[4].startswith("0"):
        output["Verdict"] = SAFE
        output[SAFE] = [VT]
    elif vt[4] == NONE:
        pass
    else:
        output[BLOCK] = [VT]
        output["Verdict"] = BLOCK
    return output


def filemode(a_file, name):
    global imageName, mode
    mode = FILE_MODE
    output = {"file": name, "Verdict": NONE}
    if ss_mode:
        imageName = makeFileName(name)
    vt, dbot = virusTotalFile(a_file)
    output_hash(name, VT, vt, dbot)
    output[VT] = vt[4]
    output["MD5"] = vt[1]
    output["SHA1"] = vt[2]
    output["SHA256"] = vt[3]
    if vt[4].startswith("0"):
        output["Verdict"] = SAFE
    elif vt[4] == NONE:
        pass
    else:
        output["Verdict"] = BLOCK
    return output


def get_header(m):
    if m == IP_MODE:
        header = ['ip', 'Verdict', SAFE, BLOCK, VT, ABIP, FG, IBM, AUTH0]
        if ss_mode:
            header.append(CISCO)
        return header

    elif m == URL_MODE:
        header = ['url', 'Verdict', SAFE, BLOCK, VT, IBM, GOOGLE, PHISH]
        if ss_mode:
            header.append(URLSCAN)
            header.append(CISCO)
        return header

    elif m == HASH_MODE:
        return ['hash', 'Verdict', "MD5", "SHA1", "SHA256", VT, SAFE, BLOCK]

    elif m == FILE_MODE:
        return ['file', 'Verdict', "MD5", "SHA1", "SHA256", VT]


def get_reputation(data):
    if mode == IP_MODE:
        rep = [
            data[VT],
            data[ABIP],
            data[FG],
            data[IBM],
            data[AUTH0]
        ]
        if ss_mode:
            rep.append(data[CISCO])
        return rep

    elif mode == URL_MODE:
        rep = [
            data[VT],
            data[IBM],
            data[GOOGLE],
            data[PHISH]
        ]
        if ss_mode:
            rep.append(data[URLSCAN])
            rep.append(data[CISCO])
        return rep

    elif mode == HASH_MODE:
        return data[VT]

    elif mode == FILE_MODE:
        return data[VT]


def checker():
    args = demisto.args()
    global ss_mode
    ss_mode = False
    if args.get('screenshot') == "true":
        ss_mode = True
    output = NONE
    markdown = ""
    output_key = NONE

    if args.get('ip'):
        output = ipmode(args.get('ip'))
        header = get_header(IP_MODE)
        markdown += '### Indicator: ' + args.get('ip') + '\n'
        markdown += tableToMarkdown('Results', output, headers=header)
        output_key = 'IP'

    elif args.get('url'):
        output = urlmode(args.get('url'))
        header = get_header(URL_MODE)
        markdown += '### Indicator: ' + args.get('url') + '\n'
        markdown += tableToMarkdown('Results', output, headers=header)
        output_key = 'URL'

    elif args.get('hash'):
        output = hashmode(args.get('hash'))
        header = get_header(HASH_MODE)
        markdown += '### Indicator: ' + args.get('hash') + '\n'
        markdown += tableToMarkdown('Results', output, headers=header)
        output_key = 'Hash'

    elif args.get('file'):
        entry_id = args.get('file')
        res = demisto.getFilePath(entry_id)
        if not res:
            return_error("Entry {} not found".format(entry_id))
        file_path = res['path']
        file_name = res['name']
        if file_name == "file.zip":
            return
        output = filemode(file_path, file_name)
        header = get_header(FILE_MODE)
        markdown += '### Indicator: ' + args.get('file') + '\n'
        markdown += tableToMarkdown('Results', output, headers=header)
        output_key = 'File'

    else:
        markdown += help()
    if ss_mode:
        # Return ZIP
        res = fileResult(filename=mode + '.zip', data=open(mode + '.zip', "rb").read())
        return_results(res)
    # return reputation
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='Checker',
        outputs_key_field=output_key,
        outputs=output
    )
    return_results(results)


def checker_batch():
    args = demisto.args()
    global ss_mode
    ss_mode = False
    if args.get('screenshot') == "true":
        ss_mode = True
    if args.get('ips'):
        arr = []
        for ip in args.get('ips').split(","):
            arr.append(ip.strip())
        check_batch_process(arr, IP_MODE)
    if args.get('urls'):
        arr = []
        for url in args.get('urls').split(","):
            arr.append(url.strip())
        check_batch_process(args.get('urls'), URL_MODE)
    if args.get('hashes'):
        arr = []
        for h in args.get('hashes').split(","):
            arr.append(h.strip())
        check_batch_process(args.get('hashes'), HASH_MODE)
    if args.get('entryID'):
        entry_id = args.get('entryID')
        arr = extract_single(entry_id)
        if arr:
            check_batch_process(arr, args.get('mode'))


def check_batch_process(indicators, mode):
    markdown = ""
    output_key = ""
    result = []
    filename = ""
    if mode == IP_MODE:
        filename = "ip_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))
        header = get_header(IP_MODE)
        for ip in indicators:
            output = ipmode(ip)
            result.append(output)
            output_key = 'ip'
            save_record_csv(output, filename, header)
        markdown += '### IP Batch Reputation Check\n'
        markdown += tableToMarkdown('Results', result, headers=header)

    elif mode == URL_MODE:
        filename = "url_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))
        header = get_header(URL_MODE)
        f = None
        for url in indicators:
            output = urlmode(url)
            result.append(output)
            output_key = 'url'
            save_record_csv(output, filename, header)
        markdown += '### URL Batch Reputation Check\n'
        markdown += tableToMarkdown('Results', result, headers=header)

    elif mode == HASH_MODE:
        filename = "hash_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))
        header = get_header(HASH_MODE)
        for h in indicators:
            output = hashmode(h)
            result.append(output)
            output_key = 'hash'
            save_record_csv(output, filename, header)
        markdown += '### Hash Batch Reputation Check\n'
        markdown += tableToMarkdown('Results', result, headers=header)
    else:
        markdown += help()

    if ss_mode:
        # Return ZIP
        with ZipFile(mode + '.zip', 'a') as zipObj:
            zipObj.write(filename)
        zip = fileResult(filename=mode + '.zip', data=open(mode + '.zip', "rb").read())
        zip['Type'] = entryTypes['file']
        return_results(zip)

    # return csv
    res = fileResult(filename=filename, data=open(filename, "rb").read())
    return_results(res)
    # return reputation
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='Checker',
        outputs_key_field=output_key,
        outputs=result
    )
    return_results(results)


def find_ip(s):
    return re.findall(
        r'(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?'
        r'[1-9]\d|0?0?\d)', s)


def find_url(s):
    # Currently matches https or http or www.example.com or just domain like exmaple.com
    # To remove not matching with any url without http / https, remove "|\b(?:[a-z]+\.)" portion
    return re.findall(r"""(?:(?:https?|ftp):\/\/|\b(?:[a-z]+\.))(?:(?:[^\s()<>]+|\((?:[
                        ^\s()<>]+|(?:\([^\s()<>]+\)))?\))+(?:\((?:[^\s()<>]+|(?:\(?:[^\s()<>]+\)))?\)|[^\s`!()\[\]{
                        };:'".,<>?`]))?""", s)


def find_hash(s):
    return re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32,}(?![a-z0-9])', s)


def checker_extract():
    args = demisto.args()
    global ss_mode
    ss_mode = False
    if args.get('screenshot') == "true":
        ss_mode = True

    entry_id = args.get('entryID')
    ips, urls, hashes = extract_all(entry_id)

    if ips:
        check_batch_process(ips, IP_MODE)
    if urls:
        check_batch_process(urls, URL_MODE)
    if hashes:
        check_batch_process(hashes, HASH_MODE)


def help():
    markdown = '### Help text\n'
    markdown += 'For single IOC:\n'
    markdown += 'Command: !Checker ip=x.x.x.x\n'
    markdown += 'For batch IOC:\n'
    markdown += '1. Create new incident with playbook Checker_Batch_IP or URL or Hash\n'
    markdown += '2. Attach csv file containing indicators in column 0\n'
    return markdown


def extract_all(entry_id):
    res = demisto.getFilePath(entry_id)
    if not res:
        return_error("Entry {} not found".format(entry_id))
    file_path = res['path']
    file_name = res['name']
    ips = []
    urls = []
    hashes = []
    if file_name.lower().endswith('.csv'):
        # csv file
        try:
            with open(file_path, newline='', encoding="ISO-8859-1") as f:
                r = csv.reader(f)
                for row in r:
                    newrow = ' '.join(row).strip()
                    if not newrow:
                        continue
                    else:
                        ips.extend(find_ip(newrow))
                        urls.extend(find_url(newrow))
                        hashes.extend(find_hash(newrow))

        except Exception as e:
            return_error(str(e))

    elif file_name.lower().endswith('.txt'):
        # txt file
        try:
            with open(file_path, newline='', encoding="ISO-8859-1") as f:
                content = f.read()
                ips.extend(find_ip(content))
                urls.extend(find_url(content))
                hashes.extend(find_hash(content))
        except Exception as e:
            return_error(str(e))
    if ips:
        ips = list(set(ips))
        results = CommandResults(
            readable_output=tableToMarkdown('### {} IP addresses found\n'.format(len(ips)), ips,
                                            headers=['IP Address']),
            outputs_prefix='Checker',
            outputs_key_field='IP Address',
            outputs=ips
        )
        return_results(results)
    if urls:
        urls = list(set(urls))
        results = CommandResults(
            readable_output=tableToMarkdown('### {} URLs found\n'.format(len(urls)), urls, headers=['URL']),
            outputs_prefix='Checker',
            outputs_key_field='URL',
            outputs=urls
        )
        return_results(results)
    if hashes:
        hashes = list(set(hashes))
        results = CommandResults(
            readable_output=tableToMarkdown('### {} Hashes found\n'.format(len(hashes)), hashes, headers=['Hash']),
            outputs_prefix='Checker',
            outputs_key_field='Hash',
            outputs=hashes
        )
        return_results(results)

    return ips, urls, hashes


def checkerindi_extract_all():
    args = demisto.args()
    entry_id = args.get('entryID')
    ips, urls, hashes = extract_all(entry_id)
    context = {}  # type: dict
    if ips:
        for ip in ips:
            context["IP"].append({"Address": ip})

    if urls:
        for url in urls:
            context["URL"].append({"Data": url})

    if hashes:
        for hash_string in hashes:
            if len(hash_string) == 32:
                context["File"].append({"MD5": hash_string})
            if len(hash_string) == 64:
                context["File"].append({"SHA256": hash_string})
            if len(hash_string) == 40:
                context["File"].append({"SHA1": hash_string})

    return_results({"EntryContext": context})


def extract_single(entry_id):
    res = demisto.getFilePath(entry_id)
    if not res:
        return_error("Entry {} not found".format(entry_id))
    file_path = res['path']
    file_name = res['name']
    if file_name.lower().endswith('.txt') or file_name.lower().endswith('.csv'):
        arr = []
        with open(file_path) as f:
            for line in f:
                newline = line.replace("\n", "")
                if newline != "":
                    arr.append(newline)
        return arr
    else:
        return_error("Not correct file format")


def checkerindi_extract_single():
    args = demisto.args()
    entry_id = args.get('entryID')
    mode = args.get('mode')
    arr = extract_single(entry_id)
    context = {}
    output = []
    if arr:
        if mode == IP_MODE:
            for ip in arr:
                output.append({'Address': ip})
            output_prefix = 'IP'
            output_key = 'Address'
        elif mode == URL_MODE:
            for url in arr:
                output.append({'Data': url})
            output_prefix = 'URL'
            output_key = 'Data'
        elif mode == HASH_MODE:
            output_prefix = 'Hash'
            for hash_string in arr:
                if len(hash_string) == 32:
                    output.append({'MD5': hash_string})
                    output_key = 'MD5'
                elif len(hash_string) == 64:
                    output.append({'SHA256': hash_string})
                    output_key = 'SHA256'
                elif len(hash_string) == 40:
                    output.append({'SHA1': hash_string})
                    output_key = 'SHA1'
    results = CommandResults(
        outputs_prefix=output_prefix,
        outputs_key_field=output_key,
        outputs=output
    )
    return_results(results)


def common(args):
    global ss_mode, imageName
    indicator = args.get('indicator')
    ss_mode = False
    if args.get('screenshot') == "true":
        ss_mode = True
    ec = {}
    if mode == IP_MODE:
        try:
            ip = indicator["Address"]
        except:
            ip = indicator
        if ss_mode:
            imageName = makeFileName(ip)
        return ip

    elif mode == URL_MODE:
        try:
            url = indicator["Data"]
        except:
            url = indicator
        if ss_mode:
            imageName = makeFileName(url)
        return url
    elif mode == HASH_MODE:
        try:
            if indicator["SHA256"]:
                h = indicator["SHA256"]
            elif indicator["SHA1"]:
                h = indicator["SHA1"]
            elif indicator["MD5"]:
                h = indicator["MD5"]
        except:
            # print("Exception")
            if isinstance(indicator, list):
                h = indicator
        if ss_mode:
            imageName = makeFileName(h)
        return h
    elif mode == FILE_MODE:
        entry_id = indicator
        res = demisto.getFilePath(entry_id)
        if not res:
            return_error("Entry {} not found".format(entry_id))
        if ss_mode:
            imageName = makeFileName(res['name'])
        return res


def checkerindi_virustotal():
    global mode
    args = demisto.args()
    mode = args.get('mode')
    indicator = common(args)
    if mode == IP_MODE:
        vt, dbot = virusTotalIP(indicator)
        output_ip(indicator, VT, vt, dbot)
    elif mode == URL_MODE:
        vt, dbot = virusTotalURL(indicator)
        output_url(indicator, VT, vt, dbot)
    elif mode == HASH_MODE:
        vt, dbot = virusTotalHash(indicator)
        output_hash(indicator, VT, vt, dbot)
    elif mode == FILE_MODE:
        file_path = indicator['path']
        file_name = indicator['name']
        vt, dbot = virusTotalFile(file_path)
        output_hash(file_name, VT, vt, dbot)
    else:
        vt = NONE


def checkerindi_ibm():
    global mode
    args = demisto.args()
    mode = args.get('mode')
    indicator = common(args)
    if mode == IP_MODE:
        ibm, dbot = ibm_IP(indicator)
        output_ip(indicator, IBM, ibm, dbot)

    elif mode == URL_MODE:
        ibm, dbot = ibm_url(indicator)
        output_url(indicator, IBM, ibm, dbot)


def checkerindi_abusedIP():
    global mode
    mode = IP_MODE
    args = demisto.args()
    indicator = common(args)
    abip, dbot = abusedIP(indicator)
    output_ip(indicator, ABIP, abip, dbot)


def checkerindi_fraudguard():
    global mode
    mode = IP_MODE
    args = demisto.args()
    indicator = common(args)
    fg, dbot = fraudGuard(indicator)
    output_ip(indicator, FG, fg, dbot)


def checkerindi_auth0():
    global mode
    mode = IP_MODE
    args = demisto.args()
    indicator = common(args)
    ath0, dbot = auth0(indicator)
    output_ip(indicator, AUTH0, ath0, dbot)


def checkerindi_google():
    global mode
    mode = URL_MODE
    args = demisto.args()
    indicator = common(args)
    gsb, dbot = googleSafe(indicator)
    output_url(indicator, GOOGLE, gsb, dbot)


def checkerindi_phish():
    global mode
    mode = URL_MODE
    args = demisto.args()
    indicator = common(args)
    pt, dbot = phishtank(indicator)
    output_url(indicator, PHISH, pt, dbot)


def checkerindi_urlscan():
    global mode
    mode = URL_MODE
    args = demisto.args()
    indicator = common(args)
    us, dbot = urlscan(indicator)
    output_url(indicator, URLSCAN, us[0], dbot)


def checkerindi_cisco():
    global mode
    args = demisto.args()
    mode = args.get('mode')
    indicator = common(args)
    ct, dbot = screenshot_ciscoTalos(indicator)
    if mode == IP_MODE:
        output_ip(indicator, CISCO, ct, dbot)
    elif mode == URL_MODE:
        output_url(indicator, CISCO, ct, dbot)


def output_ip(indicator, name, score, dbot):
    # ec = {}
    # ec.update({
    #     outputPaths['ip']: {'Address': indicator}
    # })
    dbot_score = Common.DBotScore(
        indicator=indicator,
        integration_name='Checker',
        indicator_type=DBotScoreType.IP,
        score=dbot
    )
    ip = Common.IP(
        ip=indicator,
        dbot_score=dbot_score
    )
    malic = True
    if dbot == Common.DBotScore.GOOD or dbot == Common.DBotScore.NONE:
        malic = False
    return_results(CommandResults(
        outputs_prefix='Checker.IP',
        outputs_key_field='Indicator',
        outputs=[{
            'Indicator': indicator,
            name: {
                'score': score,
                'malicious': malic
            }}],
        indicators=[ip]))
    # ec.update({
    #     outputPaths['dbotscore']: {'Indicator': indicator, 'Type': mode, 'Vendor': name, 'Score': score}
    # })
    # return_results({"EntryContext": ec})


def output_url(indicator, name, score, dbot):
    # ec = {}
    # ec.update({
    #     outputPaths['url']: {'Data': indicator}
    # })
    dbot_score = Common.DBotScore(
        indicator=indicator,
        integration_name='Checker',
        indicator_type=DBotScoreType.URL,
        score=dbot
    )
    url = Common.URL(
        url=indicator,
        dbot_score=dbot_score
    )
    malic = True
    if dbot == Common.DBotScore.GOOD or dbot == Common.DBotScore.NONE:
        malic = False
    return_results(CommandResults(
        outputs_prefix='Checker.URL',
        outputs_key_field='Indicator',
        outputs=[{
            'Indicator': indicator,
            name: {
                'score': score,
                'malicious': malic
            }}],
        indicators=[url]))
    # ec.update({
    #     outputPaths['dbotscore']: {'Indicator': indicator, 'Type': mode, 'Vendor': name, 'Score': score}
    # })
    # return_results({"EntryContext": ec})


def output_hash(indicator, name, score, dbot):
    # ec = {}
    # ec.update({
    #     outputPaths['file']: {
    #         'MD5': score[1],
    #         'SHA1': score[2],
    #         'SHA256': score[3],
    #     }
    # })
    dbot_score = Common.DBotScore(
        indicator=indicator,
        integration_name='Checker',
        indicator_type=DBotScoreType.FILE,
        score=dbot
    )
    f = Common.File(
        dbot_score=dbot_score,
        md5=score[1],
        sha1=score[2],
        sha256=score[3]
    )
    malic = True
    if dbot == Common.DBotScore.GOOD or dbot == Common.DBotScore.NONE:
        malic = False
    return_results(CommandResults(
        outputs_prefix='Checker.File',
        outputs_key_field='Indicator',
        outputs=[{
            'Indicator': indicator,
            'MD5': score[1],
            'SHA1': score[2],
            'SHA256': score[3],
            name: {
                'score': score[4],
                'malicious': malic,
            }}],
        indicators=[f]))
    # ec.update({
    #     outputPaths['dbotscore']: {'Indicator': indicator, 'Type': mode, 'Vendor': name, 'Score': score}
    # })
    # return_results({"EntryContext": ec})


def checkerindi_print():
    global mode, ss_mode
    args = demisto.args()
    ctx = demisto.context()
    mode = args.get('mode')
    ss_mode = False
    if args.get('screenshot') == "true":
        ss_mode = True

    if mode == IP_MODE:
        ip = ctx['Checker']['IP']
        output = {"ip": ip["Indicator"], "Verdict": NONE, SAFE: [], BLOCK: []}
        output = append_result(ip, output)
        output_key = 'IP'
        markdown = '### IP Reputation Check\n'
        markdown += tableToMarkdown('Results', output, headers=get_header(IP_MODE))

    elif mode == URL_MODE:
        url = ctx["Checker"]["URL"]
        output = {"url": url["Indicator"], "Verdict": NONE, SAFE: [], BLOCK: []}
        output = append_result(url, output)
        output_key = 'URL'
        markdown = '### URL Reputation Check\n'
        markdown += tableToMarkdown('Results', output, headers=get_header(URL_MODE))

    elif mode == HASH_MODE:
        h = ctx["Checker"]["File"]
        output = {"hash": h["Indicator"], "Verdict": NONE, "MD5": h["MD5"], "SHA1": h["SHA1"],
                  "SHA256": h["SHA256"]}
        output = append_result(h, output)
        output_key = 'File'
        markdown = '### Hash Reputation Check\n'
        markdown += tableToMarkdown('Results', output, headers=get_header(HASH_MODE))

    elif mode == FILE_MODE:
        h = ctx["Checker"]["File"]
        if isinstance(h, list):
            for f in h:
                try:
                    output = {"file": f["Indicator"], "Verdict": NONE, "MD5": f["MD5"], "SHA1": f["SHA1"],
                              "SHA256": f["SHA256"]}
                    output = append_result(f, output)
                except:
                    pass
        else:
            output = {"file": h["Indicator"], "Verdict": NONE, "MD5": h["MD5"], "SHA1": h["SHA1"],
                      "SHA256": h["SHA256"]}
            output = append_result(h, output)
        output.pop(SAFE)
        output.pop(BLOCK)
        output_key = 'File'
        markdown = '### File Reputation Check\n'
        markdown += tableToMarkdown('Results', output, headers=get_header(FILE_MODE))

    if ss_mode:
        # Return ZIP
        with ZipFile(mode + '.zip', 'a') as zipObj:
            if isinstance(ctx['InfoFile'], list):
                for pic in ctx['InfoFile']:
                    f = demisto.getFilePath(pic['EntryID'])
                    path = f['path']
                    name = f['name']
                    with open(path, 'rb') as f, open(name, 'wb') as image:
                        data = f.read()
                        image.write(data)
                    zipObj.write(name)
            else:
                f = demisto.getFilePath(ctx['InfoFile']['EntryID'])
                path = f['path']
                name = f['name']
                with open(path, 'rb') as f, open(name, 'wb') as image:
                    data = f.read()
                    image.write(data)
                zipObj.write(name)
        zip = fileResult(filename=mode + '.zip', data=open(mode + '.zip', "rb").read())
        return_results(zip)

    # return reputation
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='Checker',
        outputs_key_field=output_key,
        outputs=output
    )
    return_results(results)


def append_result(indicator, output):
    safe = []
    block = []
    for k in indicator.keys():
        if k != "Indicator" and k != "Verdict" and k != "MD5" and k != "SHA1" and k != "SHA256":
            output[k] = indicator[k]['score']
            if indicator[k]['malicious']:
                block.append(k)
            else:
                safe.append(k)
    output[SAFE] = safe
    output[BLOCK] = block
    output = get_verdict(output)
    return output


def checkerindi_results():
    global mode, ss_mode
    args = demisto.args()
    ctx = demisto.context()
    result = []
    filename = ""
    mode = args.get('mode')
    if args.get('filename'):
        filename = args.get('filename')
    ss_mode = False
    if args.get('screenshot') == "true":
        ss_mode = True

    if mode == IP_MODE:
        if not filename:
            filename = "ip_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))
        header = get_header(IP_MODE)
        for ip in ctx["Checker"]["IP"]:
            output = {"ip": ip["Indicator"], "Verdict": NONE, SAFE: [], BLOCK: []}
            output = append_result(ip, output)
            result.append(output)
            save_record_csv(output, filename, header)
        markdown = '### IP Batch Reputation Check\n'
        output_key = 'IP'

    elif mode == URL_MODE:
        if not filename:
            filename = "url_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))
        header = get_header(URL_MODE)
        for url in ctx["Checker"]["URL"]:
            output = {"url": url["Indicator"], "Verdict": NONE, SAFE: [], BLOCK: []}
            output = append_result(url, output)
            result.append(output)
            save_record_csv(output, filename, header)
        output_key = 'URL'
        markdown = '### URL Batch Reputation Check\n'

    elif mode == HASH_MODE:
        if not filename:
            filename = "hash_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))
        header = get_header(HASH_MODE)
        for h in ctx["Checker"]["File"]:
            try:
                output = {"hash": h["Indicator"], "Verdict": NONE, "MD5": h["MD5"], "SHA1": h["SHA1"], "SHA256": h["SHA256"]}
                output = append_result(h, output)
                result.append(output)
                save_record_csv(output, filename, header)
            except:
                pass
        output_key = 'File'
        markdown = '### Hash Batch Reputation Check\n'

    if ss_mode:
        # Return ZIP
        with ZipFile(mode + '.zip', 'a') as zipObj:
            zipObj.write(filename)
            for pic in ctx['InfoFile']:
                f = demisto.getFilePath(pic['EntryID'])
                path = f['path']
                name = f['name']
                with open(path, 'rb') as f, open(name, 'wb') as image:
                    data = f.read()
                    image.write(data)
                zipObj.write(name)
        zip = fileResult(filename=mode + '.zip', data=open(mode + '.zip', "rb").read())
        return_results(zip)
    # return csv
    res = fileResult(filename=filename, data=open(filename, "rb").read())
    return_results(res)
    # return reputation
    markdown += tableToMarkdown('Results', result, headers=header)
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='Checker',
        outputs_key_field=output_key,
        outputs=result
    )
    return_results(results)


def test_module():
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    # # result = client.say_hello('DBot')
    # if 'Hello DBot' == result:
    #     return 'ok'
    # else:
    #     return 'Test failed because ......'


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
    # if demisto.params()['url']
    # base_url = urljoin(demisto.params()['url'], '/api/v1/suffix')

    # verify_certificate = not demisto.params().get('insecure', False)
    #
    # # How much time before the first fetch to retrieve incidents
    # first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()
    #
    # proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        # client = Client(
        #     base_url=base_url,
        #     verify=verify_certificate,
        #     proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module()
            demisto.results(result)

        elif demisto.command() == 'checker':
            checker()
        elif demisto.command() == 'checker-batch':
            checker_batch()
        elif demisto.command() == 'checker-extract':
            checker_extract()
        elif demisto.command() == 'checkerindi-extract-all':
            checkerindi_extract_all()
        elif demisto.command() == 'checkerindi-extract-single':
            checkerindi_extract_single()
        elif demisto.command() == 'checkerindi-results':
            checkerindi_results()
        elif demisto.command() == 'checkerindi-print':
            checkerindi_print()
        elif demisto.command() == 'checkerindi-virustotal':
            checkerindi_virustotal()
        elif demisto.command() == 'checkerindi-ibm':
            checkerindi_ibm()
        elif demisto.command() == 'checkerindi-abuseip':
            checkerindi_abusedIP()
        elif demisto.command() == 'checkerindi-fraudguard':
            checkerindi_fraudguard()
        elif demisto.command() == 'checkerindi-auth0':
            checkerindi_auth0()
        elif demisto.command() == 'checkerindi-google':
            checkerindi_google()
        elif demisto.command() == 'checkerindi-phish':
            checkerindi_phish()
        elif demisto.command() == 'checkerindi-cisco':
            checkerindi_cisco()
        elif demisto.command() == 'checkerindi-urlscan':
            checkerindi_urlscan()
    # Log exceptions
    except Exception as e:
        demisto.info(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
