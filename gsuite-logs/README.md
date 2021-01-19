# gsuite-logs

Utility for collecting gsuite logs and publishing to a SQS queue for
ingest into logging system.

TODO:

* create utility for getting OAuth Token
* write lambda that pulls token from parameter store, fetches logs, and publishes to a queue.