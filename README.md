# Summary
Takes a Tenable.io Container Security report in JSON format and creates a CSV.

# Usage Example With Environment Variables
TIOACCESSKEY="******************"; export TIOACCESSKEY

TIOSECRETKEY="******************"; export TIOSECRETKEY

TIOREPOSITORY="reponamegoeshere"; export TIOREPOSITORY

./tiocs-csv-report.py 

This will produce a file called tiocs-report.csv
