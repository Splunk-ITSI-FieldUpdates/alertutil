import subprocess
import uuid
import sys
import splunkhelp
import urllib2
import json
import random, string
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
returnv=""
correlatorids=[]

AuthToken = "BA8141BF-ABAC-4449-A898-9A4D72ADFBE8"
HOST = "localhost"
PORT = 8089
USERNAME = "admin"
PASSWORD = "changeme"


def breakgroup(groupeventId):
	policyIDs = getPolicyforEventGroup(groupeventId)
	for policy in policyIDs:
		urlstring = "https://"+HOST+":8089/servicesNS/nobody/SA-ITOA/event_management_interface/vLatest/notable_event_group/?break_group_policy_id="+policy
		print "Breaking the Event Group"
		payload = {"status":"5","_key":groupeventId}
		r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
	return

def checkKVStore (groupeventId):
	print ("Checking KV Store for:"+groupeventId)
	urlstring = "https://"+HOST+":8089/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group/"+groupeventId
	#print urlstring
	output = (requests.get(urlstring, verify=False, auth=(USERNAME, PASSWORD)))
	if "null" in output.text:
		return "Empty"
	if "_key" in output.text:
		return "Preset"

def updateKVStoreStatus (inputstring,groupeventId,returnval,suser,spass,sserver,sport):
	print ("About to update event:"+groupeventId+" for "+returnval)
	if returnval=="Preset":
		urlstring = "https://"+sserver+":"+sport+"/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group/"+groupeventId+"/?is_partial_data=1"
		payload = {"group_id": groupeventId,"status": inputstring}
		print payload
		r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
		print r,r.text
		return r.text
	if returnval=="Empty":
		print "empty KV store for this groupid:"+groupeventId+" going to check initial index"
		myarray=myresultarray=splunkhelp.executesearch(sserver,sport,suser,spass,"index=itsi_grouped_alerts itsi_group_id="+groupeventId)
		#print "result:",myarray[0]
		jsoninput = myarray[0]
		json2=json.loads(jsoninput[3])
		status=inputstring
		severity=json2['severity']
		owner=json2['owner']
		payload = {"group_id": groupeventId,"status": status,"severity":severity,"owner":owner}
		urlstring = "https://"+sserver+":"+sport+"/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group"
		r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
                print r,r.text
                return r.text
def updateKVStoreOwner (inputstring,groupeventId,returnval,suser,spass,sserver,sport):
        print ("About to update event:"+groupeventId+" for "+returnval)
        if returnval=="Preset":
                urlstring = "https://"+sserver+":"+sport+"/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group/"+groupeventId+"/?is_partial_data=1"
                payload = {"group_id": groupeventId,"owner": inputstring}
                print payload
                r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
                print r,r.text
                return r.text
        if returnval=="Empty":
                print "empty KV store for this groupid:"+groupeventId+" going to check initial index"
                myarray=myresultarray=splunkhelp.executesearch(sserver,sport,suser,spass,"index=itsi_grouped_alerts itsi_group_id="+groupeventId)
                #print "result:",myarray[0]
                jsoninput = myarray[0]
                json2=json.loads(jsoninput[3])
                owner=inputstring
                severity=json2['severity']
                status=json2['status']
                payload = {"group_id": groupeventId,"status": status,"severity":severity,"owner":owner}
                urlstring = "https://"+sserver+":"+sport+"/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group"
                r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
                print r,r.text
                return r.text		
def updateKVStoreSeverity (inputstring,groupeventId,returnval,suser,spass,sserver,sport):
	print ("About to update event:"+groupeventId+" for "+returnval)
	if returnval=="Preset":
		urlstring = "https://"+sserver+":"+sport+"/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group/"+groupeventId+"/?is_partial_data=1"
		payload = {"group_id": groupeventId,"severity": inputstring}
		print payload
		r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
		print r,r.text
		return r.text
	if returnval=="Empty":
		print "empty KV store for this groupid:"+groupeventId+" going to check initial index"
		myarray=myresultarray=splunkhelp.executesearch(sserver,sport,suser,spass,"index=itsi_grouped_alerts itsi_group_id="+groupeventId)
		#print "result:",myarray[0]
		jsoninput = myarray[0]
		json2=json.loads(jsoninput[3])
		severity=inputstring
		status=json2['status']
		owner=json2['owner']
		payload = {"group_id": groupeventId,"status": status,"severity":severity,"owner":owner}
		urlstring = "https://"+sserver+":"+sport+"/servicesNS/nobody/SA-ITOA/event_management_interface/notable_event_group"
		r = requests.post(urlstring, data=json.dumps(payload), auth=(USERNAME, PASSWORD), verify=False)
                print r,r.text
                return r.text

def setGroupStatus(groupeventId,statusvalue,suser,spass,sserver,sport):	
	print ("Setting event:"+groupeventId+" to:"+statusvalue)
	returnval = checkKVStore(groupeventId)
	print returnval, "Response from Initial checkKVStore:"+groupeventId
	returnval = updateKVStoreStatus (statusvalue,groupeventId,returnval,suser,spass,sserver,sport)
	sys.exit(0)
def setGroupOwner(groupeventId,ownervalue,suser,spass,sserver,sport):
        print ("Setting event:"+groupeventId+" to:"+ownervalue)
        returnval = checkKVStore(groupeventId)
        print returnval, "Response from Initial checkKVStore:"+groupeventId
        returnval = updateKVStoreOwner (ownervalue,groupeventId,returnval,suser,spass,sserver,sport)
        sys.exit(0)

def setGroupSeverity(groupeventId,severityvalue,suser,spass,sserver,sport):	
	print ("Setting event:"+groupeventId+" to:"+severityvalue)
	returnval = checkKVStore(groupeventId)
	print returnval, "Response from Initial checkKVStore:"+groupeventId
	returnval = updateKVStoreSeverity (severityvalue,groupeventId,returnval,suser,spass,sserver,sport)
	sys.exit(0)

if len(sys.argv) != 3 and len(sys.argv) != 4:
	print "usage: python alertutil.py setstatus \"<eventid>\" statusvalue"
	print "usage: python alertutil.py setseverity \"<eventid>\" severityvalue"
	print "usage: python alertutil.py setowner \"<eventid>\" ownername"
	sys.exit(0)

if ((len(sys.argv)==4) and ("setseverity" in sys.argv[1])):
        groupeventId = sys.argv[2]
        severityvalue = sys.argv[3]
        print ("Setting event:"+groupeventId+" to severity:"+severityvalue)
        suser=USERNAME
        spass=PASSWORD
        sserver=HOST
        sport=str(PORT)
        setGroupSeverity(groupeventId,severityvalue,suser,spass,sserver,sport)
        sys.exit(0)

if ((len(sys.argv)==4) and ("setstatus" in sys.argv[1])):
	groupeventId = sys.argv[2]
	statusvalue = sys.argv[3]
	print ("Setting event:"+groupeventId+" to status:"+statusvalue)
	suser=USERNAME
	spass=PASSWORD
	sserver=HOST
	sport=str(PORT)
	setGroupStatus(groupeventId,statusvalue,suser,spass,sserver,sport)
	sys.exit(0)
if ((len(sys.argv)==4) and ("setowner" in sys.argv[1])):
        groupeventId = sys.argv[2]
        ownervalue = sys.argv[3]
        print ("Setting event:"+groupeventId+" to owner:"+ownervalue)
        suser=USERNAME
        spass=PASSWORD
        sserver=HOST
        sport=str(PORT)
        setGroupOwner(groupeventId,ownervalue,suser,spass,sserver,sport)
        sys.exit(0)



