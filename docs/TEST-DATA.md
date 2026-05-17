# Test Data

Fake secrets and PII for testing bleep proxy detection + replacement.

## Secrets

```
AKIAIOSFODNN7EXAMPLE
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123
gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123
sk_live_ABCDEFGHIJKLMNOPQRSTuvwx
rk_test_ABCDEFGHIJKLMNOPQRSTuvwx
xoxb-123456789012-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx
SG.abcdefghijklmnopqrstuv.wxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01
npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123
pypi-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890123456789ABCDEFGHIJKLMNOP-QRSTUVWXYZ01
```

## PII

```
123-45-6789
4111111111111111
5500000000000004
378282246310005
john.doe@company.com
(555) 123-4567
192.168.1.100
```

## Curl test

```bash
# start proxy first: task run:release -- --port 9190

curl -x http://localhost:9190 \
  --cacert src/cert.pem \
  -H "Content-Type: application/json" \
  -d '{
    "message": "my aws key is AKIAIOSFODNN7EXAMPLE and card 4111111111111111",
    "email": "john.doe@company.com",
    "token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"
  }' \
  https://httpbin.org/post
```

## JSON body for direct testing

```json
{
  "prompt": "explain this code, my AWS key is AKIAIOSFODNN7EXAMPLE",
  "context": "SSN: 123-45-6789, email: john.doe@company.com",
  "api_key": "sk_live_ABCDEFGHIJKLMNOPQRSTuvwx",
  "github_token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"
}
```
