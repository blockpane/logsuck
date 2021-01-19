# CloudFlare

This works, but desperately needs documentation. It expects configuration to be stored in SSM, and will also use
SSM to store the last time logs were pulled to prevent duplicates. More info to come ....

Each of these should env vars should point to a SSM parameter.
```
	ssmEmail := os.Getenv("SSM_EMAIL")
	ssmKey := os.Getenv("SSM_KEY")
	ssmZone := os.Getenv("SSM_ZONE")
	ssmTime := os.Getenv("SSM_TIMESTAMP")
```

The .conf file in this directory adds a few useful transforms for a logstash pipeline.
