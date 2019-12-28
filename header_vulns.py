import requests

URL = input("enter url")
def headers():
    print("Checking Headers....")
    urls = open("websites.txt", "r")
    for url in urls:
        url = url.strip()
        req = requests.get(url)
        print(url, 'report:')

        try:
            protection_xss = req.headers['X-XSS-Protection']
            if protection_xss == '1; mode = block':
                pass
        except:
            print('X-XSS-Protection not set, it may be possible')

        try:
            options_content_type = req.headers['X-Content-Type-Options']
            if options_content_type == 'nosniff':
                pass
        except:
            print('X-Content-Type-Options not set')

        try:
            transport_security = req.headers['Strict-Transport-Security']
        except:
            print('HSTS header not set properly, Man in the middle attacks is possible')

        try:
            content_security = req.headers['Content-Security-Policy']
            print('Content-Security-Policy set:', content_security)
        except:
            print('Content-Security-Policy missing')
    print("------------------------------------------------------------------------")

def clickjack():
    print("checking for Clickjacking...")
    req = requests.get(URL)
    try:
        xframe = req.headers['x-frame-options']
        print('X-FRAME-OPTIONS:', xframe, 'present, clickjacking not likely possible')
    except:
        print('X-FRAME-OPTIONS missing')
    print("------------------------------------------------------------------------")

def http_methods():
    print("Testing HTTP methods")
    verbs = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE',
             'TEST']
    for verb in verbs:
        req = requests.request(verb, URL)
        print(verb, req.status_code, req.reason)
        if verb == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
            print('Possible Cross Site Tracing vulnerability found')
    print("------------------------------------------------------------------------")

def server_fingerprinting():
    print("Performing Server fingerprinting")
    req = requests.get(URL)
    header = 'Server'
    try:
        result = req.headers[header]
        print('%s: %s' % (header, result))
        print("\x1b[31mServer Version Disclosure found\x1b[39;49m")
    except Exception:
        print('%s: Not found' % header)
    print("------------------------------------------------------------------------")

def cookie_flags():
    print("checking cookie Flags")
    import requests
    req = requests.get(URL)
    for cookie in req.cookies:
        print('Name:', cookie.name)
        print('Value:', cookie.value)
        if not cookie.secure:
            cookie.secure = '\x1b[31mFalse\x1b[39;49m'
        print('Secure:', cookie.secure)
        if 'httponly' in cookie._rest.keys():
            cookie.httponly = 'True'
        else:
            cookie.httponly = '\x1b[31mFalse\x1b[39;49m'
        print('HTTPOnly:', cookie.httponly)
        if cookie.domain_initial_dot:
            cookie.domain_initial_dot = '\x1b[31mTrue\x1b[39;49m'
        print('Loosly defined domain:', cookie.domain_initial_dot)
        if cookie.path == '/':
            print("\x1b[31mcookie path set to root\x1b[39;49m")

headers()
clickjack()
http_methods()
server_fingerprinting()
cookie_flags()