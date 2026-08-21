-- AU-6.1: who touched the evidence vault, and what did they do?
-- The one bucket where "who read this" is itself an audit question.
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress, errorCode
FROM cloudtrail_logs
WHERE dt >= date_format(current_date - interval '7' day, '%Y/%m/%d')
  AND eventSource = 's3.amazonaws.com'
  AND element_at(resources, 1).ARN LIKE '%evidence-vault%'
ORDER BY eventTime DESC;
