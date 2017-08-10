#!/usr/bin/python
#
# Takes a Tenable.io Container Security JSON report and generates a CSV report.
# The output file is called tiocs-report.csv
#
# Example usage with environment variables:
# TIOACCESSKEY="********************"; export TIOACCESSKEY
# TIOSECRETKEY="********************"; export TIOSECRETKEY
# TIOREPOSITORY="reponame"; export TIOREPOSITORY
# ./tiocs-csv-report.py 
#



import json
import os
import csv
import sys
from tenable_io.api.models import Folder
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from tenable_io.api.models import AssetList, AssetInfo, VulnerabilityList, VulnerabilityOutputList

def GenerateReport(accesskey,secretkey,repo):
	DEBUG=False

	client = TenableIOClient(access_key=accesskey, secret_key=secretkey)

	#Gather the list of repositories
	resp=client.get("container-security/api/v1/container/list")
	respdata=json.loads(resp.text)
	if DEBUG:
		print "Response",respdata
		print "\n\n"
	for i in respdata:
		if DEBUG:
			print "Repo info:",i
		if i['name'] == repo:
			if DEBUG:
				print "Found repo ID:",i['id']
			containerid=i['id']

	#Gather the report for the specified repository
	resp=client.get("container-security/api/v1/reports/show?container_id="+str(containerid))
	respdata=json.loads(resp.text)
	if DEBUG:
		print "Response",respdata
		print "\n\n"

	with open("tiocs-report.csv","w") as csvfile:
        	fieldnames=['cve','severity','vuln publication date','affected packages','remediation','description']
        	writer=csv.DictWriter(csvfile,fieldnames=fieldnames)
       		writer.writeheader()
		DEBUG=True
		for i in respdata['findings']:
			packages=""
			for j in i['packages']:
				if packages != "":
					packages+="\n"
				if DEBUG:
					print "Software packages affected",j['name'],j['version']
				packages=packages+' '+j['name'].encode('utf-8').strip()+' '+j['version'].encode('utf-8').strip()
			if DEBUG:
				print i
				print "\n\n"
				print "Package",i['packages']
				print "NVD Finding",i['nvdFinding']
				print "CVE",i['nvdFinding']['cve']
				print "Severity",i['nvdFinding']['cvss_score']
				print "Remediation",i['nvdFinding']['remediation']
				print "Description",i['nvdFinding']['description']
				print "Vulnerability publication date",i['nvdFinding']['published_date']
	
       		         	rowdict={'cve':i['nvdFinding']['cve'], 'severity': i['nvdFinding']['cvss_score'], 'vuln publication date': i['nvdFinding']['published_date'],'remediation': i['nvdFinding']['remediation'].encode('utf-8').strip(), 'description': i['nvdFinding']['description'].encode('utf-8').strip(), 'affected packages': packages}
                		writer.writerow(rowdict)

	csvfile.close()
		

	return

################################################################
# Start of program 
################################################################
#Set debugging on or off
DEBUG=True

#Pull as much information from the environment variables
# as possible, and where missing then initialize the variables.
if os.getenv('TIOACCESSKEY') is None:
        accesskey=""
else:
        accesskey=os.getenv('TIOACCESSKEY')

if os.getenv('TIOSECRETKEY') is None:
        secretkey=""
else:
        secretkey=os.getenv('TIOSECRETKEY')

if os.getenv('TIOREPOSITORY') is None:
        repo=""
else:
        repo=os.getenv('TIOREPOSITORY')

if DEBUG:
        print "Connecting to cloud.tenable.com with access key",accesskey,"to report on repository",repo

#Pull information from command line.  If nothing there,
# and there was nothing in the environment variables, then ask user.
if len(sys.argv) > 1:
        accesskey=sys.argv[1]
else:
        if accesskey == "":
                accesskey=raw_input("Access key:")

if len(sys.argv) > 2:
        repo=sys.argv[2]
else:
        if repo == "":
                repo=raw_input("Repository:")

if len(sys.argv) > 3:
	secretkey=sys.argv[3]
else:
	if secretkey == "":
        	secretkey=raw_input("Secret key:")

GenerateReport(accesskey,secretkey,repo)


