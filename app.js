require('dotenv').config()

const express = require('express')
const bodyParser = require('body-parser')
const axios = require('axios')
const crypto = require('crypto')
const line = require('@line/bot-sdk')
const path = require('path')
const jose = require('node-jose')
const url = require('url')
const app = express()
const port = 3000
// console.log(process.env)
// console.log(process.env.CHANNEL_SECRECT)

const env_privateKey = require('./privateKey.json')

// middleware
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))
// console.log(env_privateKey)

// if(process.env.NODE_ENV !== 'production'){ // read .env file in development
//     require('dotenv').config()
// }

// create LINE SDK config from env variables
const config = {
    channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
    channelSecret: process.env.CHANNEL_SECRET,
  };
  
// create LINE SDK client
const client = new line.Client(config);

var state, targetUrl

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, './index.html'))
    state = randomString(12, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    targetUrl = `https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id=${process.env.LOGIN_CHANNEL_ID}&redirect_uri=${process.env.LOGIN_CALLBACK_URL}&state=${state}&scope=profile%20openid%20email`
})

function randomString(length, chars) {
    var result = '';
    for (var i = length; i > 0; --i) result += chars[Math.round(Math.random() * (chars.length - 1))];
    return result;
}

app.get('/lineAuthRequest', (req, res) => {
    res.redirect(targetUrl)
    console.log(state)
})

app.post('/login', (req, res) => { // generate JWT
    let privateKey = JSON.stringify(env_privateKey)
    
    let header = {
        alg: "RS256",
        typ: "JWT",
        kid: "d3ed0668-ed80-4e78-b8bf-8074d17a1fc6"
    };

    let payload = {
        iss: process.env.CHANNEL_ID, // Channel ID
        sub: process.env.CHANNEL_ID, // Channel ID
        aud: "https://api.line.me/",
        exp: Math.floor(new Date().getTime() / 1000) + 60 * 30,
        token_exp: 60 * 60 * 24 * 30
    };

    jose.JWS.createSign({format: 'compact', fields: header}, JSON.parse(privateKey))
        .update(JSON.stringify(payload))
        .final()
        .then(result => {
            console.log(result);
            // window.location.href="/"
        });
})

app.get('/auth', (req, res) => { // line login redirect route
    res.sendFile(path.join(__dirname, './auth.html'))
    const fullUrl = new URL(req.protocol + '://' + req.get('host') + req.originalUrl)
    const urlParams = fullUrl.searchParams

    if(urlParams.get('error') !== null){
        const error = urlParams.get('error')
        const error_description = urlParams.get('error_description')
        console.log('error: ', error)
        console.log('error_description: ', error_description)
    }else{
        const code = urlParams.get('code') //Authorization code
        const loginState = urlParams.get('state') //Should matches the value given to authorization url

        console.log('code: ', code)
        console.log('state: ', loginState)
        console.log('old state: ', state)

        if(state === loginState){
            getAccessToken(code)
        }
    }    
})


function getAccessToken(code){
    const params = new url.URLSearchParams(
        {
            grant_type: 'authorization_code',
            code: code,
            client_id: process.env.LOGIN_CHANNEL_ID,
            client_secret: process.env.LOGIN_CHANNEL_SECRET,
            redirect_uri: process.env.LOGIN_CALLBACK_URL
        }
    )

    // Issue an access token;
    axios.post('https://api.line.me/oauth2/v2.1/token', params ,{headers: { 'Content-Type': 'application/x-www-form-urlencoded' }})
    .then((response) => {
        // console.log(response.data)
        const data = response.data
        // console.log(data.id_token)
        // verifyToken(data.id_token)
        getUserProfile(data.access_token)
    })
}


function verifyToken(idToken){
    const params = new url.URLSearchParams(
        {
            id_token: idToken,
            client_id: process.env.LOGIN_CHANNEL_ID
        }
    )

    axios.post('https://api.line.me/oauth2/v2.1/verify', params ,{headers: { 'Content-Type': 'application/x-www-form-urlencoded' }})
    .then((response) => {
        console.log(response.data)
    })
}

function getUserProfile(accessToken){
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
    }

    axios.get('https://api.line.me/v2/profile', {headers: headers})
    .then((response) => {
        console.log(response.data)
        const data = response.data
        linkUser(data.userId, accessToken)
    })
}

function logoutUser(accessToken){
    const params = new url.URLSearchParams(
        {
            client_id: process.env.LOGIN_CHANNEL_ID,
            client_secret: process.env.LOGIN_CHANNEL_SECRET,
            access_token: accessToken
        }
    )

    axios.post('https://api.line.me/oauth2/v2.1/revoke', params, {headers: { 'Content-Type': 'application/x-www-form-urlencoded' }})
    .then((response) => {
        console.log(response.data)
    })
}

function linkUser(userId, accessToken){
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
    }

    axios.post(`https://api.line.me/v2/bot/user/${userId}/linkToken`, { headers: headers })
}

app.post("/callback", (req, res) => { // line message api webhook endpoints
    // console.log('req.headers:', req.headers)
    console.log('req.body:', req.body)
    // console.log('event:', req.body.events) // need body-parser
    // console.log('event.source:', req.body.events[0].source)
    // console.log('event.message:', req.body.events[0].message)
    if(req.body.events.length > 0){
        handleEvents(req.headers, req.body.events)
    }else{
        res.end()
    }
})

function validateSource(header){
    const channelSecret = process.env.CHANNEL_SECRET
    const body = header.host
    const lineSignature = header['x-line-signature']

    const signature = crypto
        .createHmac("SHA256", channelSecret)
        .update(body)
        .digest("base64")

    // console.log(lineSignature)
    // console.log(signature)        
}

function handleEvents(header, event){ //監聽 webhook 事件類型
    // console.log('event:', event)
    
    validateSource(header)

    switch(event[0].type){
        case 'message':
            const message = event[0].message
            
            switch(message.type){
                case 'text':
                    return client.replyMessage(event[0].replyToken, {
                        type: 'text', text: '收到文字訊息'
                    })
            }
    }
}

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})