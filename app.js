require('dotenv').config()

const express = require('express')
const bodyParser = require('body-parser')
const fetch = () => import('node-fetch')
const crypto = require('crypto')
const line = require('@line/bot-sdk')
const path = require('path')
const jose = require('node-jose')
const app = express()
const port = 3000
// console.log(process.env)
// console.log(process.env.CHANNEL_SECRECT)

const env_privateKey = require('./privateKey.json')
const jsonParser = bodyParser.json()
const urlencodedParser =bodyParser.urlencoded({extended: false})
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

app.get('/', (req, res) => {
    res.redirect(`/home?client_id=${process.env.LOGIN_CHANNEL_ID}&redirect_uri=${process.env.LOGIN_CALLBACK_URL}`)
})

app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, './index.html'))
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

app.get('/auth', (req, res) => {
    console.log(req.body)
    const queryString = window.location.search
    const urlParams = new URLSearchParams(queryString)

    const code = urlParams.get('code')
    const state = urlParams.get('state')
    console.log('code: ', code)
    console.log('state: ', state)
})

app.post("/callback", jsonParser, (req, res) => { // line message api webhook endpoints
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

function handleEvents(header, event){
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