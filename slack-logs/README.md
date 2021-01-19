# slack-logs

Lambda function to pull logs from slack and publish them to a SQS queue
for ingest.

Much to do here ... 
* Need to implement state tracking so duplicate logs are not sent
* setup parameter store to hold api token, and pull from there.
