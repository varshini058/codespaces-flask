from flask import Flask, render_template
import requests
import json
import pandas as pd

app = Flask(__name__)

@app.route("/")
def hello_world():
    return render_template("index.html", title="Hello")

@app.route("/returncviapi")
def returncviapi(): 
 url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2024-05-08T13:00:00.000%2B01:00&lastModEndDate=2024-05-10T13:36:00.000%2B01:00"

 payload = {}
 headers= {}

 response = requests.request("GET", url, headers=headers, data = payload)

 nested_json = response.json()

 # Function to filter nested JSON
 def filter_nested_json(nested_json):
     filtered_data = nested_json ['vulnerabilities']
     print(type(filtered_data))
     return filtered_data
    
# Filter the nested JSON
 filtered_json = filter_nested_json(nested_json)

 # Print or do whatever you need with the filtered JSON
 jsonlist =json.dumps(filtered_json, indent=4)
 dictlist =json.loads(jsonlist)
 #print(dictlist)

 idlist=[]
 df = pd.DataFrame(columns=["id", "sourceIdentifier","published","published","lastModified","vulnStatus"])
 for item in dictlist:
     #print(item)
    #print(item['cve'] ['id'])
     iddict = {"id":item['cve'] ['id'],"sourceIdentifier":item['cve'] ['sourceIdentifier'],"published": item['cve']['published'],"lastModified": item['cve']['lastModified'],"vulnStatus":item['cve']['vulnStatus']}
     idlist.append(iddict)
 return json.dumps(idlist)

@app.route("/cves/list")
def prepare_cveslist():
    return render_template("cvelist.html", title="cveslist")

