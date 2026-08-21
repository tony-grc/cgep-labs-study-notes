-- AU-6.3: denied actions clustered by principal. The signal that someone is
-- probing the edges of their permissions.
SELECT userIdentity.arn, eventName, count(*) AS attempts
FROM cloudtrail_logs
WHERE dt >= date_format(current_date - interval '7' day, '%Y/%m/%d')
  AND errorCode IN ('AccessDenied', 'UnauthorizedOperation')
GROUP BY userIdentity.arn, eventName
HAVING count(*) > 5
ORDER BY attempts DESC;
