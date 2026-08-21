-- AU-6.2: console sign-ins without MFA. AC-2 / IA-2 evidence.
SELECT eventTime, userIdentity.arn, sourceIPAddress
FROM cloudtrail_logs
WHERE dt >= date_format(current_date - interval '30' day, '%Y/%m/%d')
  AND eventName = 'ConsoleLogin'
  AND userIdentity.sessionContext.attributes.mfaAuthenticated = 'false'
ORDER BY eventTime DESC;
