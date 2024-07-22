#!/bin/bash
# To run this script you will need to install trivy and jq
#redhat 
#sudo yum -y update
# sudo yum -y install trivy
# sudo yum -y install jq
#ubuntu
#sudo apt-get -y update
# sudo apt-get -y install trivy
# sudo apt-get -y install jq

#MacOS
# brew install trivy
# brew install jq

#windows
#install cholatey
# choco install trivy
# choco install jq

# Set variables
TERRAFORM_CODE_DIR="./"
TRIVY_OUTPUT_FILE="trivy_output.json"

# Run Trivy scan
trivy fs --scanners vuln,misconfig --severity HIGH,CRITICAL $TERRAFORM_CODE_DIR > $TRIVY_OUTPUT_FILE 

# Check if the Trivy scan succeeded
if [ $? -ne 0 ]; then
  echo "Trivy scan command failed."
  exit 1
fi

# Check if Trivy found any issues
critical_issues=$(grep -o 'CRITICAL' $TRIVY_OUTPUT_FILE | wc -l)
high_issues=$(grep -o 'HIGH' $TRIVY_OUTPUT_FILE | wc -l)

if [ $critical_issues -gt 0 ] || [ $high_issues -gt 0 ]; then

    # Send the output to Slack
   curl -X POST -H 'Content-type: application/json' \
    --data "$(jq -Rs --arg text "Trivy Scan Report" '{text: "\($text)\n\(. | tostring)"}' < ./trivy_output.json)" https://hooks.slack.com/services/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

    
    echo "Trivy scan found critical/high issues. Aborting the provisioning."
    exit 1
else
    echo "Trivy scan did not find any critical/high issues."
    exit 0
fi




