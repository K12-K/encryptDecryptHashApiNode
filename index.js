const express = require('express')
const bodyParser = require('body-parser')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const app = express()
const PORT = process.env.PORT || 3000

app.use(bodyParser.json())

// configure header for api key
app.use((req, res, next) => {
    const SERVER_API = req.headers["x-rapidapi-key"] || req.headers['api-key']
    if (!SERVER_API) {
        return res.status(401).json({
            error: 'Unauthorized request!!! No api key provided'
        })
    }
    next()
})

// ------------------------ Hash With BCRYPT ----------------------------------- //
app.post('/bcrypt', async (req, res) => {
    try {
        const SERVER_API = req.headers["x-rapidapi-key"] || req.headers['api-key']
        const NO_OF_ROUNDS = Number.parseInt(req.query.rounds) || 10
        const data = req.body.data
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const hashedData = await bcrypt.hash(data, NO_OF_ROUNDS)
        res.status(200).json({
            message: 'Success',
            hasheddata: hashedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/bcrypt/verify', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const hasheddata = req.body.hasheddata
        if (!data || !hasheddata) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const verify = await bcrypt.compare(data, hasheddata)
        res.status(200).json({
            message: 'Success',
            verified: verify
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})


// ------------------------ Hash With MD5 ----------------------------------- //
app.post('/md5', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const md5Hasher = crypto.createHmac('md5', SERVER_API)
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        // const hashedData = md5(data, 128)
        const hashedData = md5Hasher.update(data).digest('hex')
        res.status(200).json({
            message: 'Success',
            hasheddata: hashedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/md5/verify', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const hasheddata = req.body.hasheddata
        const md5Hasher = crypto.createHmac('md5', SERVER_API)
        if (!data || !hasheddata) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const verify = (md5Hasher.update(data).digest('hex') === hasheddata)
        res.status(200).json({
            message: 'Success',
            verified: verify
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})


// ------------------------ Hash With SHA-256 ----------------------------------- //
app.post('/sha256', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const sha256Hasher = crypto.createHmac('sha256', SERVER_API)
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const hashedData = sha256Hasher.update(data).digest('hex')
        res.status(200).json({
            message: 'Success',
            hasheddata: hashedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/sha256/verify', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const hasheddata = req.body.hasheddata
        const sha256Hasher = crypto.createHmac('sha256', SERVER_API)
        if (!data || !hasheddata) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const verify = (sha256Hasher.update(data).digest('hex') === hasheddata)
        res.status(200).json({
            message: 'Success',
            verified: verify
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})


// ------------------------ Hash With SHA-512 ----------------------------------- //
app.post('/sha512', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const sha512Hasher = crypto.createHmac('sha512', SERVER_API)
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const hashedData = sha512Hasher.update(data).digest('hex')
        res.status(200).json({
            message: 'Success',
            hasheddata: hashedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/sha512/verify', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const hasheddata = req.body.hasheddata
        const sha512Hasher = crypto.createHmac('sha512', SERVER_API)
        if (!data || !hasheddata) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const verify = (sha512Hasher.update(data).digest('hex') === hasheddata)
        res.status(200).json({
            message: 'Success',
            verified: verify
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})


// ------------------------ Hash With SHA-1 ----------------------------------- //
app.post('/sha1', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const sha1Hasher = crypto.createHmac('sha1', SERVER_API)
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const hashedData = sha1Hasher.update(data).digest('hex')
        res.status(200).json({
            message: 'Success',
            hasheddata: hashedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/sha1/verify', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const hasheddata = req.body.hasheddata
        const sha1Hasher = crypto.createHmac('sha1', SERVER_API)
        if (!data || !hasheddata) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const verify = (sha1Hasher.update(data).digest('hex') === hasheddata)
        res.status(200).json({
            message: 'Success',
            verified: verify
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})


// ------------------------ Hash With RipeMD-160 ----------------------------------- //
app.post('/ripemd160', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const ripemd160Hasher = crypto.createHmac('ripemd160', SERVER_API)
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const hashedData = ripemd160Hasher.update(data).digest('hex')
        res.status(200).json({
            message: 'Success',
            hasheddata: hashedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/ripemd160/verify', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const hasheddata = req.body.hasheddata
        const ripemd160Hasher = crypto.createHmac('ripemd160', SERVER_API)
        if (!data || !hasheddata) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const verify = (ripemd160Hasher.update(data).digest('hex') === hasheddata)
        res.status(200).json({
            message: 'Success',
            verified: verify
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})


// ------------------------ Hash With Whirlpool ----------------------------------- //
app.post('/whirlpool', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const whirlpoolHasher = crypto.createHmac('whirlpool', SERVER_API)
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const hashedData = whirlpoolHasher.update(data).digest('hex')
        res.status(200).json({
            message: 'Success',
            hasheddata: hashedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/whirlpool/verify', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        const hasheddata = req.body.hasheddata
        const whirlpoolHasher = crypto.createHmac('whirlpool', SERVER_API)
        if (!data || !hasheddata) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const verify = (whirlpoolHasher.update(data).digest('hex') === hasheddata)
        res.status(200).json({
            message: 'Success',
            verified: verify
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})




////////////////////////// ENCRYPTION DECRYPTION ///////////////////////////
const SECRET_IV = "kknsjnfdjfn"
const iv = crypto.createHash('sha512').update(SECRET_IV, 'utf-8').digest('hex').substring(0, 13)

// ------------------------ Encrypt-Decrypt With AES-256-GCM ----------------------------------- //
app.post('/aes256/encrypt', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const encryptedData = await encryptData(SERVER_API, 'aes-256-gcm', 32, data)
        res.status(200).json({
            message: 'Success',
            encryptedData: encryptedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/aes256/decrypt', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const decryptedData = await decryptData(SERVER_API, 'aes-256-gcm', 32, data)
        res.status(200).json({
            message: 'Success',
            decryptedData: decryptedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

// ------------------------ Encrypt-Decrypt With AES-192-GCM ----------------------------------- //
app.post('/aes192/encrypt', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const encryptedData = await encryptData(SERVER_API, 'aes-192-gcm', 24, data)
        res.status(200).json({
            message: 'Success',
            encryptedData: encryptedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/aes192/decrypt', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const decryptedData = await decryptData(SERVER_API, 'aes-192-gcm', 24, data)
        res.status(200).json({
            message: 'Success',
            decryptedData: decryptedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

// ------------------------ Encrypt-Decrypt With AES-128-GCM ----------------------------------- //
app.post('/aes128/encrypt', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const encryptedData = await encryptData(SERVER_API, 'aes-128-gcm', 16, data)
        res.status(200).json({
            message: 'Success',
            encryptedData: encryptedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})

app.post('/aes128/decrypt', async (req, res) => {
    try {
        const SERVER_API = req.headers['x-rapidapi-key'] || req.headers['api-key']
        const data = req.body.data
        if (!data) return res.status(401).json({
            message: 'Error',
            error: 'ERROR!! Data is not provided!!'
        })
        const decryptedData = await decryptData(SERVER_API, 'aes-128-gcm', 16, data)
        res.status(200).json({
            message: 'Success',
            decryptedData: decryptedData
        })
    } catch (error) {
        res.status(401).json({
            message: 'Error',
            error: error.message
        })
    }
})


const encryptData = async (SERVER_API, algorithm, noofbytes, data) => {
    const key = crypto.createHash('sha512').update(SERVER_API, 'utf-8').digest('hex').substring(0, noofbytes)
    const aes256En = crypto.createCipheriv(algorithm, key, iv)
    const encryptedData = Buffer.concat([aes256En.update(data), aes256En.final()])
    return encryptedData.toString('hex')
}
const decryptData = async (SERVER_API, algorithm, noofbytes, data) => {
    const key = crypto.createHash('sha512').update(SERVER_API, 'utf-8').digest('hex').substring(0, noofbytes)
    const aes256De = crypto.createDecipheriv(algorithm, key, iv)
    const decryptedData = aes256De.update(Buffer.from(data, 'hex'), 'utf-8', 'utf-8')
    return decryptedData.toString()
}





app.listen(PORT, (err) => {
    if (err) return console.log('Error listening on this server')
    console.log(`Server running on port ${PORT}.`)
})
