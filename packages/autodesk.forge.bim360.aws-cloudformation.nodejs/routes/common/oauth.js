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

const { AuthClientThreeLegged } = require('forge-apis');

const configAWS = require('../../configAWS');

let client_id = null;

let client_secret = null;

let callback_url = null;

class OAuth {
    constructor(session) {
        this._session = session;
    }

    async getClient(scopes = configAWS.scopeInternal) {
        if (!client_id || !client_secret || !callback_url){
            let result = await Promise.all([configAWS.forgeAWSClientId(), configAWS.forgeAWSClientSecret(), configAWS.forgeAWSCallbackUrl()]);
            client_id = result[0];
            client_secret = result[1];
            callback_url = result[2];
        }
        return new AuthClientThreeLegged(client_id, client_secret, callback_url, scopes);
    }

    isAuthorized() {
        return !!this._session.public_token;
    }

    async getPublicToken() {
        if (this._isExpired()) {
            await this._refreshTokens();
        }

        return {
            access_token: this._session.public_token,
            expires_in: this._expiresIn()
        };
    }

    async getInternalToken() {
        if (this._isExpired()) {
            await this._refreshTokens();
        }

        return {
            access_token: this._session.internal_token,
            expires_in: this._expiresIn()
        };
    }

    // On callback, pass the CODE to this function, it will
    // get the internal and public tokens and store them 
    // on the session
    async setCode(code) {
        const internalTokenClient = await this.getClient(configAWS.scopeInternal);
        const publicTokenClient = await this.getClient(configAWS.scopePublic);
        const internalCredentials = await internalTokenClient.getToken(code);
        const publicCredentials = await publicTokenClient.refreshToken(internalCredentials);

        const now = new Date();
        this._session.internal_token = internalCredentials.access_token;
        this._session.public_token = publicCredentials.access_token;
        this._session.refresh_token = publicCredentials.refresh_token;
        this._session.expires_at = (now.setSeconds(now.getSeconds() + publicCredentials.expires_in));
    }

    _expiresIn() {
        const now = new Date();
        const expiresAt = new Date(this._session.expires_at)
        return Math.round((expiresAt.getTime() - now.getTime()) / 1000);
    };

    _isExpired() {
        return (new Date() > new Date(this._session.expires_at));
    }

    async _refreshTokens() {
        let internalTokenClient = await this.getClient(configAWS.scopeInternal);
        let publicTokenClient = await this.getClient(configAWS.scopePublic);
        const internalCredentials = await internalTokenClient.refreshToken({ refresh_token: this._session.refresh_token });
        const publicCredentials = await publicTokenClient.refreshToken(internalCredentials);

        const now = new Date();
        this._session.internal_token = internalCredentials.access_token;
        this._session.public_token = publicCredentials.access_token;
        this._session.refresh_token = publicCredentials.refresh_token;
        this._session.expires_at = (now.setSeconds(now.getSeconds() + publicCredentials.expires_in));
    }
}

module.exports = { OAuth };
