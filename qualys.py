import functools
import requests
import getpass
import xmltodict

from requests.models import Response


# Set globals
baseURL = 'https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/'
headers = {
    'X-Requested-With': 'python'
}


# Show a menu
def menu(sess):
    # Put in a try to handle logout when complete or on script error
    try:
        while True:
            print('1. List host vulnerabilities')
            print('2. Ignore or restore vulnerability')
            print('q: quit')
            choice = input('Action: ')

            match choice:
                case '1':
                    getHostVulns(sess)
                case '2':
                    ignoreRestoreVuln(sess)
                case 'q':
                    break
    finally:
        closeSession(sess)
 

# Establish a session to Qualys
def connect():
    # Get a user and pass
    user = input("Username: ")
    password = getpass.getpass("Password: ")

    params = {
        'action': 'login',
        'username': user,
        'password': password
    }
 
    # Setup session with a timeout
    sess = requests.Session()
    response = sess.post(baseURL + 'session/', params, headers=headers)
    for method in ('get', 'post'):
        setattr(sess, method, functools.partial(getattr(sess, method), timeout=15))

    # Quit if not successful
    if response.status_code != 200:
        print('Error: ' + response.text)
        quit()

    return sess


def closeSession(sess):
    params = {
        'action': 'logout'
    }
 
    response = sess.post(baseURL + 'session/', params, headers=headers)

    sess.close()
 

def getHostByIP(sess, ipAddr):
    params = {
        'action': 'list',
        'ips': ipAddr
    }

    hostReq = sess.post(baseURL + 'asset/host/', params, headers=headers)
    host = xmltodict.parse(hostReq.text)['HOST_LIST_OUTPUT']['RESPONSE']['HOST_LIST']['HOST']

    print(host['ID'] + '\t' + host['DNS_DATA']['HOSTNAME'])
 

def getHostVulns(sess):
    ipAddr = input('IP address: ')

    params = {
        'action': 'list',
        'ips': ipAddr,
        'include_ignored': '1'
    }

    hostVulnsReq = sess.post(baseURL + 'asset/host/vm/detection/', params, headers=headers)
    hostVulns = xmltodict.parse(hostVulnsReq.text)['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['HOST_LIST']['HOST']

    # Handle when multiple assets exist for IP
    if 'ID' not in hostVulns:
        print("Multiple hosts matching, please select:")

        # Print the list of returned assets and ask which to display
        i = 1
        for host in hostVulns:
            print(str(i) + '. ' + host['ID'] + '\t' + host['IP'] + '\t' + host['TRACKING_METHOD'] + '\t' + host['DNS_DATA']['HOSTNAME'])
            i += 1

        # Verify specified asset is valid
        tgtHost = -1
        while tgtHost < 0 or tgtHost > (i - 1):
            tgtHost = int(input("Selection: ")) - 1

        hostVulns = hostVulns[tgtHost]['DETECTION_LIST']['DETECTION']
    else:
        hostVulns = hostVulns['DETECTION_LIST']['DETECTION']

    for vuln in hostVulns:
        dataStr = vuln['QID'] + '\t' + vuln['TYPE'] + '\t'
        if vuln['IS_IGNORED'] == '1':
            dataStr += 'IGNORED' + '\t'
        else:
            dataStr += vuln['STATUS'] + '\t'
        dataStr += vuln['RESULTS'][:60]
        print(dataStr)


def ignoreRestoreVuln(sess):
    qid = input('QID: ')

    # Get a valid action input, i or r
    while True:
        action = input('I\u0332gnore or R\u0332estore: ')
        if action.lower() in ('i', 'r'):
            break
 
    ipAddr = input('IP target: ')
    comment = input('Comment: ')

    # If ignoring, set reopen date
    if action.lower() == 'i':
        reopenDate = input('Reopen date: ')

    if action.lower() == 'i':
        ignoreVulnReq(sess, qid, ipAddr, comment, reopenDate)
    else:
        restoreVulnReq(sess, qid, ipAddr, comment)

def ignoreVulnReq(sess, qid, ipAddr, comment, reopenDate):
    params = {
        'action': 'ignore',
        'qids': qid,
        'ips': ipAddr,
        'comments': comment,
        'reopen_ignored_date': reopenDate
    }

    ignoreResponse = sess.post(baseURL + 'ignore_vuln/index.php', params, headers=headers)
    ignored = xmltodict.parse(ignoreResponse.text)['IGNORE_VULN_OUTPUT']['RESPONSE']

    if ignored['@status'] == 'SUCCESS':
        print(ignored['@status'] + ' ignored ' + ignored['@number'])
    else:
        print("Error " + ignored['MESSAGE'])
        

def restoreVulnReq(sess, qid, ipAddr, comment):
    params = {
        'action': 'restore',
        'qids': qid,
        'ips': ipAddr,
        'comments': comment
    }

    restoreResponse = sess.post(baseURL + 'ignore_vuln/index.php', params, headers=headers)

    print(restoreResponse.text)

 

if __name__ == '__main__':
    sess = connect()
    menu(sess)
