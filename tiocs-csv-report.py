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
import argparse
from tenable.io import TenableIO


def GenerateReport(DEBUG, accesskey, secretkey,repo, image, tag):

	client = TenableIO(accesskey, secretkey)

	# Gather the list of repositories
	resp = client.get("container-security/api/v2/reports/"+repo+"/"+image+"/"+tag)
	respdata = json.loads(resp.text)
	if DEBUG:
		print("Response", respdata)
		print("\n\n")


	with open("tiocs-report.csv","w") as csvfile:
			fieldnames=['cve', 'severity', 'vuln publication date', 'affected packages', 'remediation', 'description']
			writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
			writer.writeheader()
			for i in respdata['findings']:
				packages=""
				for j in i['packages']:
					if packages != "":
						packages+="\n"
					if DEBUG:
						print("Software packages affected",j['name'],j['version'])
					packages=packages+' '+str(j['name'])+' '+str(j['version'])
					if DEBUG:
						print(i)
						print("\n\n")
						print("Package",i['packages'])
						print("NVD Finding",i['nvdFinding'])
						print("CVE",i['nvdFinding']['cve'])
						print("Severity",i['nvdFinding']['cvss_score'])
						print("Remediation",i['nvdFinding']['remediation'])
						print("Description",i['nvdFinding']['description'])
						print("Vulnerability publication date",i['nvdFinding']['published_date'])

					rowdict={'cve': i['nvdFinding']['cve'], 'severity': i['nvdFinding']['cvss_score'], 'vuln publication date': i['nvdFinding']['published_date'],'remediation': str(i['nvdFinding']['remediation']), 'description': str(i['nvdFinding']['description']), 'affected packages': packages}
					writer.writerow(rowdict)
	csvfile.close()
	return

################################################################
# Start of program 
################################################################
parser = argparse.ArgumentParser(description="Pulls a JSON report from Tenable.io CS for a given repository, image name, and tag")
parser.add_argument('--debug',help="Display a **LOT** of information",action="store_true")
parser.add_argument('--accesskey',help="The Tenable.io access key",nargs=1,action="store",default=[None])
parser.add_argument('--secretkey',help="The Tenable.io secret key",nargs=1,action="store",default=[None])
parser.add_argument('--repo',help="The Tenable.io CS repository",nargs=1,action="store",default=[None])
parser.add_argument('--image',help="The Tenable.io CS image",nargs=1,action="store",default=[None])
parser.add_argument('--tag',help="The Tenable.io CS tag",nargs=1,action="store",default=["latest"])
args = parser.parse_args()

DEBUG=False
#Set debugging on or off

if args.debug:
	DEBUG = True

accesskey = None
secretkey = None
repo = None

# Pull as much information from the environment variables
# as possible, and where missing then initialize the variables.
if args.accesskey[0] is None:
		accesskey=os.getenv('TIOACCESSKEY')
else:
		accesskey=args.accesskey[0]

if args.secretkey[0] is None:
		secretkey=os.getenv('TIOSECRETKEY')
else:
		secretkey=args.secretkey[0]

if args.repo[0] is not None:
	repo=args.repo[0]

if DEBUG:
	print("Connecting to cloud.tenable.com with access key", accesskey, "to report on repository", repo)


GenerateReport(DEBUG, accesskey, secretkey, repo, args.image[0], args.tag[0])


