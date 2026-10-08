# Alexa forwarder (AWS Lambda)

Alexa's Smart Home skill only accepts a Lambda endpoint, so this function forwards each directive to
`https://relay.mdtronix.online/v1/voice/alexa` and returns the relay's answer. It holds no secrets: the
relay checks the account token. Tests: `npm test` (runs `index.test.mjs`).

## Deploy (not done yet; needs AWS sign-in)

Run from `alexa-forwarder/` with the `mdtronix-dev` profile, region `eu-west-1`. Node.js 22 runtime.

```
Compress-Archive -Path index.mjs -DestinationPath function.zip -Force
aws lambda create-function --function-name mdtronix-alexa-forwarder --runtime nodejs22.x `
  --handler index.handler --role <role-arn> --zip-file fileb://function.zip `
  --region eu-west-1 --profile mdtronix-dev
```

The role is `mdtronix-alexa-forwarder-role`, with the AWS-managed `AWSLambdaBasicExecutionRole` policy. Create
it with `mdtronix-dev` (it may only manage roles named `mdtronix-*`). Alexa must be allowed to invoke the
function: `aws lambda add-permission --function-name mdtronix-alexa-forwarder --statement-id alexa-skill
--action lambda:InvokeFunction --principal alexa-appkit.amazon.com --region eu-west-1 --profile mdtronix-dev`,
with the skill ID as `--event-source-token`.
