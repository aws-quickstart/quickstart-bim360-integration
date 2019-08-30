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


using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Autodesk.Forge;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http;
using System.Net;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Amazon.Runtime;

namespace forgeSample.Controllers
{
    public class OAuthController : ControllerBase
    {
        [HttpGet]
        [Route("api/forge/oauth/token")]
        public async Task<AccessToken> GetPublicTokenAsync()
        {
            Credentials credentials = await Credentials.FromSessionAsync(Request.Cookies, Response.Cookies);

            if (credentials == null)
            {
                base.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                return new AccessToken();
            }

            // return the public (viewables:read) access token
            return new AccessToken()
            {
                access_token = credentials.TokenPublic,
                expires_in = (int)credentials.ExpiresAt.Subtract(DateTime.Now).TotalSeconds
            };
        }

        /// <summary>
        /// Response for GetPublicToken
        /// </summary>
        public struct AccessToken
        {
            public string access_token { get; set; }
            public int expires_in { get; set; }
        }

        [HttpGet]
        [Route("api/forge/oauth/signout")]
        public IActionResult Singout()
        {
            // finish the session
            Credentials.Signout(base.Response.Cookies);

            return Redirect("/");
        }

        [HttpGet]
        [Route("api/forge/oauth/url")]
        public async Task<string> GetOAuthURLAsync(string key)
        {
            // prepare the sign in URL
            Scope[] scopes = { Scope.DataRead };
            ThreeLeggedApi _threeLeggedApi = new ThreeLeggedApi();
            string oauthUrl =  _threeLeggedApi.Authorize(
                await Credentials.GetAppSetting("FORGE_CLIENT_ID"),
                oAuthConstants.CODE,
                await Credentials.GetAppSetting("FORGE_CALLBACK_URL"),
                new Scope[] { Scope.DataRead, Scope.DataCreate, Scope.DataWrite, Scope.ViewablesRead }
            );
            return oauthUrl;
        }

        [HttpGet]
        [Route("api/forge/callback/oauth")] // see Web.Config FORGE_CALLBACK_URL variable
        public async Task<IActionResult> OAuthCallbackAsync(string code)
        {
            // create credentials form the oAuth CODE
            Credentials credentials = await Credentials.CreateFromCodeAsync(code, Response.Cookies);

            return Redirect("/");
        }

        [HttpGet]
        [Route("api/forge/clientid")] // see Web.Config FORGE_CALLBACK_URL variable
        public static async Task<string> GetClientIdAsync () { 
            string clientIdKey = await Credentials.GetAppSetting("FORGE_CLIENT_ID");
            return clientIdKey; 
        } 
    }

    /// <summary>
    /// Store data in session
    /// </summary>
    public class Credentials
    {
        private const string FORGE_COOKIE = "ForgeApp";

        private Credentials() { }

        public string TokenInternal { get; set; }
        public string TokenPublic { get; set; }
        public string RefreshToken { get; set; }
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// Perform the OAuth authorization via code
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        public static async Task<Credentials> CreateFromCodeAsync(string code, IResponseCookies cookies)
        {
            ThreeLeggedApi oauth = new ThreeLeggedApi();

            dynamic credentialInternal = await oauth.GettokenAsync(
              await GetAppSetting("FORGE_CLIENT_ID"), await GetAppSetting("FORGE_CLIENT_SECRET"),
              oAuthConstants.AUTHORIZATION_CODE, code, await GetAppSetting("FORGE_CALLBACK_URL"));

            dynamic credentialPublic = await oauth.RefreshtokenAsync(
              await GetAppSetting("FORGE_CLIENT_ID"), await GetAppSetting("FORGE_CLIENT_SECRET"),
              "refresh_token", credentialInternal.refresh_token, new Scope[] { Scope.ViewablesRead });

            Credentials credentials = new Credentials();
            credentials.TokenInternal = credentialInternal.access_token;
            credentials.TokenPublic = credentialPublic.access_token;
            credentials.RefreshToken = credentialPublic.refresh_token;
            credentials.ExpiresAt = DateTime.Now.AddSeconds(credentialInternal.expires_in);

            cookies.Append(FORGE_COOKIE, JsonConvert.SerializeObject(credentials));

            return credentials;
        }

        /// <summary>
        /// Restore the credentials from the session object, refresh if needed
        /// </summary>
        /// <returns></returns>
        public static async Task<Credentials> FromSessionAsync(IRequestCookieCollection requestCookie, IResponseCookies responseCookie)
        {
            if (requestCookie == null || !requestCookie.ContainsKey(FORGE_COOKIE)) return null;

            Credentials credentials = JsonConvert.DeserializeObject<Credentials>(requestCookie[FORGE_COOKIE]);
            if (credentials.ExpiresAt < DateTime.Now)
            {
                await credentials.RefreshAsync();
                responseCookie.Delete(FORGE_COOKIE);
                responseCookie.Append(FORGE_COOKIE, JsonConvert.SerializeObject(credentials));
            }

            return credentials;
        }

        public static void Signout(IResponseCookies cookies)
        {
            cookies.Delete(FORGE_COOKIE);
        }

        /// <summary>
        /// Refresh the credentials (internal & external)
        /// </summary>
        /// <returns></returns>
         private async Task RefreshAsync()
        {
            ThreeLeggedApi oauth = new ThreeLeggedApi();

            dynamic credentialInternal = await oauth.RefreshtokenAsync(
              await GetAppSetting("FORGE_CLIENT_ID"), await GetAppSetting("FORGE_CLIENT_SECRET"),
              "refresh_token", RefreshToken, new Scope[] { Scope.DataRead, Scope.DataCreate, Scope.DataWrite, Scope.ViewablesRead });

            dynamic credentialPublic = await oauth.RefreshtokenAsync(
              await GetAppSetting("FORGE_CLIENT_ID"), await GetAppSetting("FORGE_CLIENT_SECRET"),
              "refresh_token", credentialInternal.refresh_token, new Scope[] { Scope.ViewablesRead });

            TokenInternal = credentialInternal.access_token;
            TokenPublic = credentialPublic.access_token;
            RefreshToken = credentialPublic.refresh_token;
            ExpiresAt = DateTime.Now.AddSeconds(credentialInternal.expires_in);
        }

        public static async Task<string> GetForgeKeysSSM(string SSMkey)
        {
            try
            {
                AWSCredentials awsCredentials = new InstanceProfileAWSCredentials();
                GetParameterRequest parameterRequest = new GetParameterRequest() { Name = SSMkey };
                AmazonSimpleSystemsManagementClient client = new AmazonSimpleSystemsManagementClient(awsCredentials, Amazon.RegionEndpoint.GetBySystemName( Environment.GetEnvironmentVariable("AWS_REGION")));
                GetParameterResponse response = await client.GetParameterAsync(parameterRequest);
                return response.Parameter.Value;
            }
            catch (Exception e)
            {
                throw new Exception("Cannot obtain Amazon SSM value for " + SSMkey, e);
            }
        }

        /// <summary>
        /// Reads appsettings from web.config or AWS SSM Parameter Store
        /// </summary>
        public static async Task<string> GetAppSetting(string settingKey)
        {
            string environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            if (environment == "Development"){       
                return Environment.GetEnvironmentVariable(settingKey);
            }
            else if (environment == "Production") {
                string SSMkey = Environment.GetEnvironmentVariable(settingKey);
                return await GetForgeKeysSSM(SSMkey);
            }
            return string.Empty;
        }
    }
}
