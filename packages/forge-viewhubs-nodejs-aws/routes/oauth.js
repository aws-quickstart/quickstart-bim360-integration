/////////////////////////////////////////////////////////////////////
// Copyright (c) Autodesk, Inc. All rights reserved
// Written by Forge Partner Development
//
// Permission to use, copy, modify, and distribute this software in
// object code form for any purpose and without fee is hereby granted,
// provided that the above copyright notice appears in all copies and
// that both that copyright notice and the limited warranty and
// restricted rights notice below appear in all supporting
// documentation.
//
// AUTODESK PROVIDES THIS PROGRAM "AS IS" AND WITH ALL FAULTS.
// AUTODESK SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTY OF
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR USE.  AUTODESK, INC.
// DOES NOT WARRANT THAT THE OPERATION OF THE PROGRAM WILL BE
// UNINTERRUPTED OR ERROR FREE.
/////////////////////////////////////////////////////////////////////

const express = require('../node_modules/express');

const config = require('../config');
const { OAuth } = require('./common/oauth');

let router = express.Router();

let client_id = null;

let callback_url = null;

router.get('/callback/oauth', async (req, res, next) => {
    const { code } = req.query;
    const oauth = new OAuth(req.session);
    try {
        await oauth.setCode(code);
        res.redirect('/');
    } catch(err) {
        next(err);
    }
});

router.get('/oauth/url', async (req, res, next) => {
    try {
        let result = await Promise.all([config.forgeAWSClientId(), config.forgeAWSCallbackUrl()]);
        client_id = result[0];
        callback_url = result[1];
    
        const url =
            'https://developer.api.autodesk.com' +
            '/authentication/v1/authorize?response_type=code' +
            '&client_id=' + client_id +
            '&redirect_uri=' + callback_url +
            '&scope=' + config.scopeInternal.join(' ');
        res.end(url);
    } catch(err) {
        next(err);
    }
    
});

router.get('/oauth/signout', (req, res) => {
    req.session = null;
    res.redirect('/');
});

// Endpoint to return a 2-legged access token
router.get('/oauth/token', async (req, res, next) => {
    const oauth = new OAuth(req.session);
    if (!oauth.isAuthorized()) {
        res.status(401).end();
        return;
    }

    try {
        const accessToken = await oauth.getPublicToken();
        res.json(accessToken);
    } catch(err) {
        next(err);
    }
});

module.exports = router;
