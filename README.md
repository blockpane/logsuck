# logsuck

Because, logs suck.

AWS Lambda + Cloudwatch logs + ELK

This is a handful of lambda functions that pull logs from various cloud services. They log to STDOUT, which
means to use them it's necessary to ingest the AWS lambda logs into cloudwatch log streams. My preferred method
to ingest is via the https://github.com/lukewaite/logstash-input-cloudwatch-logs logstash plugin.

The lambda functions are configured via SSM, S3, or env vars. It's not very consistent because these weren't
necessarily written at the same time, or even for the same organization.

Right now, this is in an unorganized and undocumented state. But I felt it more important to get these saved
for future use than not publishing at all. If a person has a need for these and it isn't clear how to use it,
please open an issue and ask for help and I will make it a higher priority.

Even worse is I need to track down all the associated logstash filters ... like I said, give me a nudge if these
seem like they may be useful.

I have a lot more of these and will hopefully add them when planetary alignments suggests it's a good idea.
