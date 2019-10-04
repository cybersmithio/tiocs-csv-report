# Summary
Takes a Tenable.io Container Security report in JSON format and creates a CSV.

# Requirements
This script needs the pyTenable module from https://github.com/tenable/pyTenable

# Usage Example With Environment Variables
export TIOACCESSKEY="******************"

export TIOSECRETKEY="******************"

python3 tiocs-csv-report.py --repo=myproject --image=java --tag=latest

This will produce a file called tiocs-report.csv
