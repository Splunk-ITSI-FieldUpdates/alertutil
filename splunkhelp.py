import subprocess
import ConfigParser
import requests 
import uuid
import sys
import json
import random, string
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
HOST = "localhost"
PORT = 8089
USERNAME = "admin2"
PASSWORD = "changeme"
def getConfig():
        print "Step=1,Action=Reading Config File"
        config = ConfigParser.RawConfigParser()
        config.read('remedy_itsi.cfg')
        SplunkUser = config.get('remedy_itsi', 'splunkuser')
        SplunkPassword = config.get('remedy_itsi', 'splunkpassword')
        SplunkPassword = codecs.decode(SplunkPassword,'rot_13')
        SplunkServer = config.get('remedy_itsi', 'splunkserver')
        SplunkPort = config.get('remedy_itsi', 'splunkport')
	return SplunkUser,SplunkPassword,SplunkServer,SplunkPort

def executesearch (HOST,PORT,USERNAME,PASSWORD,search):
        import splunklib.results as results
        import splunklib.client as client
        arr = []
        # Create a Service instance and log in
        service = client.connect(
    host=HOST,
    port=int(PORT),
    username=USERNAME,
    password=PASSWORD)
        kwargs_oneshot = {}
        searchquery_oneshot = "search "+search
        print (searchquery_oneshot)
        oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
        # Get the results and display them using the ResultsReader
        reader = results.ResultsReader(oneshotsearch_results)
        #print "Found individual events:"+str(len(reader))
        for item in reader:
                row = item.values()
		print row
                arr.append(row)
	return arr
