import dateparser
from selenium.webdriver.chrome.options import Options

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
# DRIVE = demisto.params().get('drive', '')
VT_KEY = demisto.params().get('virustotal_apikey', '')
ABIP_KEY = demisto.params().get('abusedipdb_apikey', '')
IBM_KEY = demisto.params().get('ibm_key', '') + ":" + demisto.params().get('ibm_pass', '')
URLSCAN_KEY = demisto.params().get('urlscan_apikey', '')
GOOGLE_KEY = demisto.params().get('googleSafeBrowsing_apikey', '')
AUTH0_KEY = demisto.params().get('auth0_apikey', '')
PHISH_KEY = demisto.params().get('phishtank_apikey', '')
# PHISH_USER = demisto.params().get('phishtank_user', '')
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

timeout = 20
imageName = ""


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
    except (KeyError, TypeError) as e:
        demisto.info(VT + " - vt_result() - " + str(e))
        rate = NONE
    except Exception as e:
        demisto.info(VT + " - vt_result() - " + str(e))
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
        vt = vt_result(resp)
    finally:
        print(VT + ": " + vt)
        return vt


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
        demisto.info(VT + " - " + str(e))
    else:
        # available status: harmless, malicious, suspicious, timeout, undetected
        vt = vt_result(resp)
    finally:
        vt_screenshot(url)
        print(VT + ": " + vt)
        demisto.info(VT + " - " + vt)
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
        demisto.info(VT + " - " + str(e))
    else:
        vt = vt_result(resp)
        filehash = str(getmd5(file))
        # retrieve analysis
        vt = virusTotalHash([filehash, file])
        vt = [vt[4], filehash]
    finally:
        print(VT + ": " + str(vt))
        demisto.info(VT + " - " + str(vt))
        return vt


def virusTotalHash(a_hash):
    vt_screenshot(a_hash)
    if mode == FILE_MODE:
        a_hash = a_hash[0]
    try:
        resp = requests.get(VT_FILE + '/{}'.format(a_hash), headers={'Accept': 'application/json', 'x-apikey': VT_KEY})
        vt_exception(resp)
    except Exception as e:
        vt = NONE
        demisto.info(VT + " - " + str(e))
    else:
        # Status: confirmed-timeout, failure, harmless, malicious, suspicious, timeout, type-unsupported, undetected
        vt = vt_result(resp)
    finally:
        print(VT + ": " + str(vt))
        demisto.info(VT + " - " + vt)

    try:
        md5 = resp.json()['data']['attributes']['md5']
        sha1 = resp.json()['data']['attributes']['sha1']
        sha256 = resp.json()['data']['attributes']['sha256']
        print("md5: " + md5 + ", SHA1: " + sha1 + ", SHA256: " + sha256)
    except (KeyError, TypeError) as e:
        demisto.info(VT + " - virusTotalHash() - " + str(e))
        md5 = NONE
        sha256 = NONE
        sha1 = NONE
    finally:
        data = [a_hash, md5, sha1, sha256, vt]
        return data


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
        except:
            rate = UNKNOWN
    elif resp.status_code == 404:
        rate = UNKNOWN
        demisto.info(IBM + " - Not found in database")
    else:
        rate = NONE
        IBM_exceptionHandle(resp)

    print(IBM + ": " + rate)
    demisto.info(IBM + " - " + rate)
    return rate


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
        except:
            rate = UNKNOWN
    elif resp.status_code == 404:
        rate = UNKNOWN
        demisto.info(IBM + " - Not found in database")
    else:
        rate = NONE
        IBM_exceptionHandle(resp)

    print(IBM + ": " + rate)
    demisto.info(IBM + " - " + rate)
    return rate

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
    except:
        rate = NONE
        error = resp['errors']
        if error[0]['status'] == 429 or error[0]['status'] == 401:
            print(ABIP + ": " + error[0]['detail'])
        elif str(error[0]['status']).startswith('5'):
            print(ABIP + EX_SERVER.format(ABIP))
        demisto.info(ABIP + " - virusTotalHash() - " + str(error[0]['detail']))
    finally:
        print(ABIP + ": " + rate)
        demisto.info(ABIP + " - " + rate)
        return rate


def fraudGuard(ip):
    if ss_mode:
        if not screenshot_fraudguard(ip):
            print(FG + ": " + SS_FAILED)

    try:
        username = FG_KEY.strip().split(':')[0]
        password = FG_KEY.strip().split(':')[1]
    except IndexError:
        rate = NONE
        demisto.info(FG + " - " + "No API keys provided")
        print(FG + ": API keys not provided in config.txt")
        print(FG + ": " + rate)
        demisto.info(FG + " - " + rate)
        return rate
    resp = requests.get(FG_IP.format(ip), verify=True, auth=HTTPBasicAuth(username, password))
    try:
        rate = json.loads(resp.text)['risk_level'] + " // 5"
    except:
        rate = NONE
        demisto.info(FG + " - " + str(resp.text))
        if resp.status_code == 401:
            print(FG + ": Invalid key - " + FG_KEY + " - Check credentials")
        elif str(resp.status_code).startswith('5'):
            print(FG + ": FraudGaurd is having problems. Please try again later")
        elif resp.status_code == 429:
            print(FG + ": API limit reached for FG key")
    finally:
        print(FG + ": " + rate)
        demisto.info(FG + " - " + rate)
        return rate


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
    except:
        score = NONE
        demisto.info(AUTH0 + " - " + str(resp))
    finally:
        print(AUTH0 + ": " + score)
        demisto.info(AUTH0 + " - " + score)
        return score


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
        else:
            gsb = "Safe"
    else:
        gsb = NONE
        if resp.status_code == 429:
            print(GOOGLE + ": Requests Exceeded!")
        elif str(resp.status_code).startswith('5'):
            print(GOOGLE + EX_SERVER.format(GOOGLE))
        demisto.info(GOOGLE + " - " + str(resp.json()))
    print(GOOGLE + ": " + gsb)
    demisto.info(GOOGLE + " - " + gsb)
    return gsb


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
            elif resp.json()['results']['verified'] and resp.json()['results']['valid']:  # if phish return malicious
                result = "Phish"
            else:  # if verified as not a phish
                result = "Not a Phish"
        else:  # if result not found in database
            result = UNKNOWN
    else:
        result = NONE
        demisto.info(PHISH + " - " + str(resp.json()))
        if resp.status_code == 509:
            print(PHISH + ": Requests Exceeded! Please wait at most 5 minutes to reset the number of requests.")
    print(PHISH + ": " + str(result))
    demisto.info(PHISH + " - " + str(result))
    return result


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
        except:
            score = NONE
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
        print(URLSCAN + ": " + score)
        logging.info(URLSCAN + " - " + score)
        return [str(score), uuid]


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
    # driver.implicitly_wait(5)
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
        image = driver.get_screenshot_as_png()
        save_image(image, CISCO)
        # print(CISCO + ": " + SS_SAVED)
        demisto.info(CISCO + " - Screenshot saved at " + imageName.format(CISCO))
        # results: Trusted, Favorable, Neutral, Questionable, Untrusted, Unknown
    except WebDriverException as e:
        web_reputation = NONE
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
        print(CISCO + ": " + web_reputation)
        demisto.info(CISCO_SS + " - " + web_reputation)
        return web_reputation


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


def addScore(name, safescore, score, data, safe, block):
    data[name] = score
    if score != NONE:
        if score.startswith(safescore) or score == UNKNOWN:
            safe.append(name)
        else:
            block.append(name)
    return data, safe, block


def addScore_cisco(name, score, data, safe, block):
    data[name] = score
    if score != NONE:
        if score == "Neutral" or score == "Favorable" or score == "Trusted" or score == "Unknown":
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
    global imageName, mode
    mode = IP_MODE
    output = {"ip": ip, "Verdict": NONE, SAFE: [], BLOCK: []}
    if ss_mode:
        imageName = makeFileName(ip)
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
    if ss_mode:
        ct = screenshot_ciscoTalos(ip)
        output, safe, block = addScore_cisco(CISCO, ct, output, safe, block)
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
    vt = virusTotalURL(url)
    output, safe, block = addScore(VT, "0", vt, output, safe, block)
    ibm_rec = ibm_url(url)
    output, safe, block = addScore(IBM, "1 ", ibm_rec, output, safe, block)
    gsb = googleSafe(url)
    output, safe, block = addScore(GOOGLE, "Safe", gsb, output, safe, block)
    pt = phishtank(url)
    output, safe, block = addScore(PHISH, "Not ", pt, output, safe, block)
    if ss_mode:
        usc = urlscan(url)
        uscuuid = usc[1]
        usc = usc[0]
        output, safe, block = addScore(URLSCAN, "0 ", usc, output, safe, block)
        ct = screenshot_ciscoTalos(url)
        output, safe, block = addScore_cisco(CISCO, ct, output, safe, block)
    output[SAFE] = safe
    output[BLOCK] = block
    return get_verdict(output)


def hashmode(a_hash):
    global imageName, mode
    mode = HASH_MODE
    output = {"hash": a_hash, "Verdict": NONE}
    if ss_mode:
        imageName = makeFileName(a_hash)
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
    global imageName, mode
    mode = FILE_MODE
    output = {"file": a_file, "Verdict": NONE}
    if ss_mode:
        imageName = makeFileName(a_file)
    vt = virusTotalFile(a_file)
    output[VT] = vt[0]
    output["File Hash"] = vt[1]
    if vt[0].startswith("0"):
        output["Verdict"] = SAFE
    elif vt[0] == NONE:
        pass
    else:
        output["Verdict"] = BLOCK
    return output


def checker():
    args = demisto.args()
    global ss_mode
    ss_mode = False
    if args.get('screenshot') == "true":
        ss_mode = True
    output = NONE
    markdown = ""
    output_key = NONE
    ec = {}  # type: dict

    if args.get('ip'):
        output = ipmode(args.get('ip'))
        header = ['ip', 'Verdict', SAFE, BLOCK, VT, ABIP, FG, IBM, AUTH0]
        rep = [
            output[VT],
            output[ABIP],
            output[FG],
            output[IBM],
            output[AUTH0]
        ]
        if ss_mode:
            header.append(CISCO)
            rep.append(output[CISCO])
        markdown += '### Indicator: ' + args.get('ip') + '\n'
        markdown += tableToMarkdown('Results', output, headers=['ip', 'Verdict', SAFE, BLOCK, VT])
        output_key = 'ip'
        ec.update({
            outputPaths['ip']: {
                'Address': output['ip'],
                'Reputation': rep,
                'Verdict': output["Verdict"]
            }
        })
    elif args.get('url'):
        output = urlmode(args.get('url'))
        header = ['url', 'Verdict', SAFE, BLOCK, VT, IBM, GOOGLE, PHISH]
        rep = [
            output[VT],
            output[IBM],
            output[GOOGLE],
            output[PHISH]
        ]
        if ss_mode:
            header.append(URLSCAN)
            header.append(CISCO)
            rep.append(output[URLSCAN])
            rep.append(output[CISCO])
        markdown += '### Indicator: ' + args.get('url') + '\n'
        markdown += tableToMarkdown('Results', output, headers=header)
        output_key = 'url'
        ec.update({
            outputPaths['url']: {
                'URL': output['url'],
                'Reputation': rep,
                'Verdict': output["Verdict"]
            }
        })
    elif args.get('hash'):
        output = hashmode(args.get('hash'))
        markdown += '### Indicator: ' + args.get('hash') + '\n'
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
        markdown += '### Indicator: ' + args.get('file') + '\n'
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
        markdown += help()

    ## Return ZIP
    res = fileResult(filename=mode+'.zip', data=open(mode+'.zip', "rb").read())
    return_results(res)
    ## return reputation
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
    markdown = ""
    output_key = ""
    ec = {}  # type: dict
    result = []
    filename = ""

    if args.get('ips'):
        header = ['ip', 'Verdict', SAFE, BLOCK, VT, ABIP, FG, IBM, AUTH0]
        filename = "ip_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))
        if ss_mode:
            header.append(CISCO)
        for address in args.get('ips'):
            ip = address["Address"]
            output = ipmode(ip)
            result.append(output)
            rep = [
                output[VT],
                output[ABIP],
                output[FG],
                output[IBM],
                output[AUTH0]
            ]
            if ss_mode:
                rep.append(output[CISCO])
            output_key = 'ip'
            save_record_csv(output, filename, header)
            ec.update({
                outputPaths['ip']: {
                    'Address': output['ip'],
                    'Reputation': rep,
                    'Verdict': output["Verdict"]
                }
            })
        markdown += '### IP Batch Reputation Check\n'
        markdown += tableToMarkdown('Results', result, headers=header)

    elif args.get('urls'):
        header = ['url', 'Verdict', SAFE, BLOCK, VT, IBM, GOOGLE, PHISH]
        filename = "url_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))
        if ss_mode:
            header.append(URLSCAN)
            header.append(CISCO)
        f = None
        for link in args.get('urls'):
            url = link["Name"]
            output = urlmode(url)
            result.append(output)
            rep = [
                output[VT],
                output[IBM],
                output[GOOGLE],
                output[PHISH]
            ]
            if ss_mode:
                rep.append(output[URLSCAN])
                rep.append(output[CISCO])
            output_key = 'url'
            save_record_csv(output, filename, header)
            ec.update({
                outputPaths['url']: {
                    'URL': output['url'],
                    'Reputation': rep,
                    'Verdict': output["Verdict"]
                }
            })
        markdown += '### URL Batch Reputation Check\n'
        markdown += tableToMarkdown('Results', result, headers=header)

    elif args.get('hashes'):
        header = ['hash', 'Verdict', "MD5", "SHA1", "SHA256", VT]
        filename = "hash_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))
        for a_hash in args.get('hashes'):
            h = next(iter(a_hash.values()))
            output = hashmode(h)
            result.append(output)
            output_key = 'hash'
            save_record_csv(output, filename, header)
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

        markdown += '### Hash Batch Reputation Check\n'
        markdown += tableToMarkdown('Results', result, headers=header)

    else:
        markdown += help()

    ec.update({
        outputPaths['file']: {
            'Output': result
        }
    })
    ## Return ZIP
    with ZipFile(mode + '.zip', 'a') as zipObj:
        zipObj.write(filename)
    zip = fileResult(filename=mode + '.zip', data=open(mode + '.zip', "rb").read())
    zip['Type'] = entryTypes['file']
    return_results(zip)
    ## return reputation
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='Checker',
        outputs_key_field=output_key,
        outputs=result
    )
    return_results(results)
    ## return csv
    res = fileResult(filename=filename, data=open(filename, "rb").read())
    return_results(res)


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
        demisto.info(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
