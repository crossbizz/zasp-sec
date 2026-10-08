# API identity metadata probe successor

Run37730244369/job113157484912 on21723a12 failed before nine subcases with SQLSTATE42501. The added direct api_ready() fixture probe was not granted to the API principal. This failure and the missed source-review condition remain preserved.

The successor uses the existing granted metadata() consumer, which checks private api_ready() internally, and validates both session/webhook API principal bindings. It adds no grants and changes no authentication, catalog, original test, timeout or resource policy. Independent source review permits another hosted original-nine run only; native/production acceptance remains unestablished.
