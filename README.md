# Summary
Takes a Tenable.io Container Security report in JSON format and creates a CSV.

# Requirements
This script needs the Tenable.io SDK, which can be found at https://github.com/tenable/Tenable.io-SDK-for-Python/tree/master/tenable_io

# Usage Example With Environment Variables
TIOACCESSKEY="******************"; export TIOACCESSKEY

TIOSECRETKEY="******************"; export TIOSECRETKEY

TIOREPOSITORY="reponamegoeshere"; export TIOREPOSITORY

./tiocs-csv-report.py 

This will produce a file called tiocs-report.csv
