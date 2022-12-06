
/**
 * Mediator、APIM签名算法实现
 * 我们在Server to Server接口中也采用这个算法
 */
const md5 = require('md5')

class Sign {
    /**
     * 处理对象签名
     * @param {*} obj
     */
    static signObject(obj) {
        let rs = ''
        const arr = []
        const keys = Object.keys(obj).sort()

        keys.forEach((key) => {
            const val = obj[key]

            if (typeof val === 'object') {
                if (Array.isArray(val)) {
                    arr.push(`${key}=[${Sign.signArray(val)}]`)
                } else {
                    arr.push(`${key}={${Sign.signObject(val)}}`)
                }
            } else {
                arr.push(`${key}=${val}`)
            }

            // switch (typeof val) {
            //   case 'object':
            //     if (Array.isArray(val)) {
            //       arr.push(`${key}=[${Sign.signArray(val)}]`)
            //     } else {
            //       arr.push(`${key}={${Sign.signObject(val)}}`)
            //     }
            //     break
            //   default:
            //     arr.push(`${key}=${val}`)
            // }
        })

        rs = arr.join('&')

        return rs
    }

    /**
     * 处理数组签名
     * @param {*} myArr
     */
    static signArray(myArr) {
        let rs = ''
        const arr = []
        myArr.forEach((val) => {
            switch (val.constructor) {
                case Object:
                    arr.push(`{${Sign.signObject(val)}}`)
                    break
                case Array:
                    arr.push(`[${Sign.signArray(val)}]`)
                    break
                default:
                    arr.push(val)
            }
        })

        rs = arr.join(',')

        return rs
    }

    /**
     * 生成签名
     *
     * @param {string} apiKey
     * @param {string} apiSecret
     * @param {misc} params
     */
    static enc(apiKey, apiSecret, params) {
        let rs = ''
        const parameters = params

        if (apiKey) {
            parameters.apiKey = apiKey
        }

        const origin = Sign.signObject(parameters) + apiSecret

        rs = md5(origin)

        return rs
    }

    /**
     * 仅仅校验签名算法，不做timestamp检查
     *
     * @param {string} apiKey
     * @param {string} apiSecret
     * @param {misc} params
     */
    static loose(apiKey, apiSecret, params) {
        let rs = false
        const parameters = JSON.parse(JSON.stringify(params))

        if (parameters.sig) {
            parameters.apiKey = apiKey
            const { sig } = params
            delete parameters.sig

            const mySig = md5(Sign.signObject(parameters) + apiSecret)

            if (mySig === sig) {
                rs = true
            }
        }

        return rs
    }

    /**
     * 签名强校验，检查timestamp有效性（60s以内）
     *
     * @param {string} apiKey
     * @param {string} apiSecret
     * @param {misc} params
     */
    static verify(apiKey, apiSecret, params) {
        let rs = false
        const parameters = JSON.parse(JSON.stringify(params))

        if (parameters.sig && parameters.timestamp) {
            const now = Date.parse(new Date()) / 1000
            const timestamp = parseInt(params.timestamp)

            if (now - timestamp < 60) {
                parameters.apiKey = apiKey
                const { sig } = params
                delete parameters.sig

                const mySig = md5(Sign.signObject(parameters) + apiSecret)
                if (mySig === sig) {
                    rs = true
                }
            }
        }

        return rs
    }
}

module.exports = Sign
