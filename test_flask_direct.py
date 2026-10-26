import http.client
conn = http.client.HTTPConnection('127.0.0.1', 5000, timeout=3)
conn.request('GET', '/api/data')
resp = conn.getresponse()
print(resp.status, resp.read().decode())
