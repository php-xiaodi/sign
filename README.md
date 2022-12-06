##bff-sign
bff-sign为bff框架提供了开箱即用的sign功能,用于bff的签名。

### API
- `signObject(obj)`: object转param string
- `signArray(myArr)`: array转param string
- `enc(apiKey, apiSecret, params)`: 生成签名
- `loose(apiKey, apiSecret, params)`: 仅仅校验签名算法，不做timestamp检查
- `verify(apiKey, apiSecret, params)`: 签名强校验，检查timestamp有效性（60s以内）




















