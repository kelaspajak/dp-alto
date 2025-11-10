# Overview
Source: https://docs.ghost.org/admin-api

It’s possible to create and manage your content using the Ghost Admin API. Our content management interface, Ghost Admin, uses the admin API - which means that everything Ghost Admin can do is also possible with the API, and a whole lot more!

***

Secure authentication is available either as a user with role-based permissions, or as an integration with a single standard set of permissions designed to support common publishing workflows.

The API is RESTful with predictable resource URLs, standard HTTP verbs, response codes and authentication used throughout. Requests and responses are JSON-encoded with consistent patterns and inline relations and responses are customisable using powerful query parameters.

## API Clients

### JavaScript Client Library

We’ve developed an [API client for JavaScript](/admin-api/javascript/), that simplifies authenticating with the admin API, and makes reading and writing data a breeze. The client is designed for use with integrations, supporting token authentication and the endpoints available to integrations.

## Structure

### Base URL

`https://{admin_domain}/ghost/api/admin/`

All admin API requests start with this base URL. Your admin domain can be different to your main domain, and may include a subdirectory. Using the correct domain and protocol are critical to getting consistent behaviour, particularly when dealing with CORS in the browser. All Ghost(Pro) blogs have a `*.ghost.io` domain as their admin domain and require https.

### Accept-Version Header

`Accept-Version: v{major}.{minor}`

Use the `Accept-Version` header to indicate the minimum version of Ghost’s API to operate with. See [API Versioning](/faq/api-versioning/) for more details.

### JSON Format

The API uses a consistent JSON structure for all requests and responses:

```json  theme={"dark"}
{
    "resource_type": [{
        ...
    }],
    "meta": {}
}
```

* `resource_type`: will always match the resource name in the URL. All resources are returned wrapped in an array, with the exception of `/site/` and `/settings/`.
* `meta`: contains [pagination](/content-api/pagination) information for browse requests.

#### Composing requests

When composing JSON payloads to send to the API as POST or PUT requests, you must always use this same format, unless the documentation for an endpoint says otherwise.

Requests with JSON payloads require the `Content-Type: application/json` header. Most request libraries have JSON-specific handling that will do this for you.

### Pagination

All browse endpoints are paginated, returning 15 records by default. You can use the [page](#page) and [limit](#limit) parameters to move through the pages of records. The response object contains a `meta.pagination` key with information on the current location within the records:

```json  theme={"dark"}
"meta": {
    "pagination": {
      "page": 1,
      "limit": 2,
      "pages": 1,
      "total": 1,
      "next": null,
      "prev": null
    }
  }
```

### Parameters

Query parameters provide fine-grained control over responses. All endpoints accept `include` and `fields`. Browse endpoints additionally accept `filter`, `limit`, `page` and `order`. Some endpoints have their own specific parameters.

The values provided as query parameters MUST be url encoded when used directly. The [client library](/admin-api/javascript/) will handle this for you.

For more details see the [Content API](/content-api/parameters).

### Filtering

See the [Content API](/content-api/filtering).

### Errors

See the [Content API](/content-api/errors).

## Authentication

There are three methods for authenticating with the Admin API: [integration token authentication](#token-authentication), [staff access token authentication](#staff-access-token-authentication) and [user authentication](#user-authentication). Most applications integrating with the Ghost Admin API should use one of the token authentication methods.

The JavaScript Admin API Client supports token authentication and staff access token authentication.

### Choosing an authentication method

**Integration Token authentication** is intended for integrations that handle common workflows, such as publishing new content, or sharing content to other platforms.

Using tokens, you authenticate as an integration. Each integration can have associated API keys & webhooks and are able to perform API requests independently of users. Admin API keys are used to generate short-lived single-use JSON Web Tokens (JWTs), which are then used to authenticate a request. The API Key is secret, and therefore this authentication method is only suitable for secure server side environments.

**Staff access token authentication** is intended for clients where different users login and manage various resources as themselves, without having to share their password.

Using a token found in a user’s settings page you authenticate as a specific user with their role-based permissions. You can use this token the same way you would use an integration token.

**User authentication** is intended for fully-fledged clients where different users login and manage various resources as themselves.

Using an email address and password, you authenticate as a specific user with their role-based permissions. Via the session API, credentials are swapped for a cookie-based session, which is then used to authenticate further API requests. Provided that passwords are entered securely, user-authentication is safe for use in the browser. User authentication requires support for second factor authentication codes.

### Permissions

Integrations have a restricted set of fixed permissions allowing access to certain endpoints e.g. `GET /users/` or `POST /posts/`. The full set of endpoints that integrations can access are those listed as [endpoints](#endpoints) on this page.

User permissions (whether using staff tokens or user authentication) are dependent entirely on their role. You can find more details in the [team management guide](https://ghost.org/help/managing-your-team/). Authenticating as a user with the Owner or Admin role will give access to the full set of API endpoints. Many endpoints can be discovered by inspecting the requests made by Ghost Admin, the [endpoints](#endpoints) listed on this page are those stable enough to document.

There are two exceptions: Staff tokens cannot transfer ownership or delete all content.

### Token Authentication

Token authentication is a simple, secure authentication mechanism using JSON Web Tokens (JWTs). Each integration and staff user is issued with an admin API key, which is used to generate a JWT token and then provided to the API via the standard HTTP Authorization header.

The admin API key must be kept private, therefore token authentication is not suitable for browsers or other insecure environments, unlike the Content API key.

#### Key

Admin API keys can be obtained by creating a new `Custom Integration` under the Integrations screen in Ghost Admin. Keys for individual users can be found on their respective profile page.

<Frame caption={`Search "integrations" in your settings to jump right to the section.`}>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4175ad749c97e1ebb88d66d0b8980d6d" data-og-width="1400" width="1400" data-og-height="877" height="877" data-path="images/custom-integrations-list.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e4a187444e58b164e0b11070e9afdbeb 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7a5390023d1d9f12b114c11d1a3dc464 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=549c62ba31a5582ff5e288c866adccc7 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=025c9083f741d14db3783011c71abbda 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3844a517e384f6f92a7bdbe0b90607bc 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=126af6dcf9fd72cdc03f53bb9ba429f0 2500w" />
</Frame>

<br />

<Frame caption="You can regenerate the Admin API key any time, but any scripts or applications using it will need to be updated.">
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cda4a350d118c74c36bb9306cd7ddbbd" data-og-width="1400" width="1400" data-og-height="1097" height="1097" data-path="images/custom-integration-settings.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=806fc0a92f94d33540921e6a8bf96a7e 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4ddff2f6606ed8b59a43b79f544d7646 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=03c5b175be583d78be7f0f197ad99bd5 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0941cb50522f22dab4db9270db96d539 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0489f915c323a6a37d9c33f813eab379 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=61e2c0cd55b6bcc37e27d68804cad5b7 2500w" />
</Frame>

Admin API keys are made up of an id and secret, separated by a colon. These values are used separately to get a signed JWT token, which is used in the Authorization header of the request:

```bash  theme={"dark"}
curl -H "Authorization: Ghost $token" -H "Accept-Version: $version" https://{admin_domain}/ghost/api/admin/{resource}/
```

The Admin API JavaScript client handles all the technical details of generating a JWT from an admin API key, meaning you only have to provide your url, version and key to start making requests.

#### Token Generation

If you’re using a language other than JavaScript, or are not using our client library, you’ll need to generate the tokens yourself. It is not safe to swap keys for tokens in the browser, or in any other insecure environment.

There are a myriad of [libraries](https://jwt.io/#libraries) available for generating JWTs in different environments.

JSON Web Tokens are made up of a header, a payload and a secret. The values needed for the header and payload are:

```json  theme={"dark"}
// Header
{
    "alg": "HS256",
    "kid": {id}, // ID from your API key
    "typ": "JWT"
}
```

```json  theme={"dark"}
// Payload
{
    // Timestamps are seconds sine the unix epoch, not milliseconds
    "exp": {timestamp}, // Max 5 minutes after 'now'
    "iat": {timestamp}, // 'now' (max 5 minutes after 'exp')
    "aud": "/admin/"
}
```

The libraries on [https://jwt.io](https://jwt.io) all work slightly differently, but all of them allow you to specify the above required values, including setting the signing algorithm to the required HS-256. Where possible, the API will provide specific error messages when required values are missing or incorrect.

Regardless of language, you’ll need to:

1. Split the API key by the `:` into an `id` and a `secret`
2. Decode the hexadecimal secret into the original binary byte array
3. Pass these values to your JWT library of choice, ensuring that the header and payload are correct.

#### Token Generation Examples

These examples show how to generate a valid JWT in various languages & JWT libraries. The bash example shows step-by-step how to create a token without using a library.

<CodeGroup>
  ```bash Bash (cURL) theme={"dark"}
  #!/usr/bin/env bash

  # Admin API key goes here
  KEY="YOUR_ADMIN_API_KEY"

  # Split the key into ID and SECRET
  TMPIFS=$IFS
  IFS=':' read ID SECRET <<< "$KEY"
  IFS=$TMPIFS

  # Prepare header and payload
  NOW=$(date +'%s')
  FIVE_MINS=$(($NOW + 300))
  HEADER="{\"alg\": \"HS256\",\"typ\": \"JWT\", \"kid\": \"$ID\"}"
  PAYLOAD="{\"iat\":$NOW,\"exp\":$FIVE_MINS,\"aud\": \"/admin/\"}"

  # Helper function for performing base64 URL encoding
  base64_url_encode() {
      declare input=${1:-$(</dev/stdin)}
      # Use `tr` to URL encode the output from base64.
      printf '%s' "${input}" | base64 | tr -d '=' | tr '+' '-' | tr '/' '_'
  }

  # Prepare the token body
  header_base64=$(base64_url_encode "$HEADER")
  payload_base64=$(base64_url_encode "$PAYLOAD")

  header_payload="${header_base64}.${payload_base64}"

  # Create the signature
  signature=$(printf '%s' "${header_payload}" | openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:$SECRET | base64_url_encode)

  # Concat payload and signature into a valid JWT token

  TOKEN="${header_payload}.${signature}"

  # Make an authenticated request to create a post
  curl -H "Authorization: Ghost $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept-Version: v3.0" \
  -d '{"posts":[{"title":"Hello world"}]}' \
  "http://localhost:2368/ghost/api/admin/posts/"
  ```

  ```js JavaScript (Client) theme={"dark"}
  // The admin API client is the easiest way to use the API
  const GhostAdminAPI = require('@tryghost/admin-api');

  // Configure the client
  const api = new GhostAdminAPI({
      url: 'http://localhost:2368/',
      // Admin API key goes here
      key: 'YOUR_ADMIN_API_KEY',
      version: 'v3'
  });

  // Make an authenticated request
  api.posts.add({title: 'Hello world'})
      .then(response => console.log(response))
      .catch(error => console.error(error));
  ```

  ```js JavaScript theme={"dark"}
  // Create a token without the client
  const jwt = require('jsonwebtoken');
  const axios = require('axios');

  // Admin API key goes here
  const key = 'YOUR_ADMIN_API_KEY';

  // Split the key into ID and SECRET
  const [id, secret] = key.split(':');

  // Create the token (including decoding secret)
  const token = jwt.sign({}, Buffer.from(secret, 'hex'), {
      keyid: id,
      algorithm: 'HS256',
      expiresIn: '5m',
      audience: `/admin/`
  });

  // Make an authenticated request to create a post
  const url = 'http://localhost:2368/ghost/api/admin/posts/';
  const headers = { Authorization: `Ghost ${token}` };
  const payload = { posts: [{ title: 'Hello World' }] };
  axios.post(url, payload, { headers })
      .then(response => console.log(response))
      .catch(error => console.error(error));
  ```

  ```ruby Ruby theme={"dark"}
  require 'httparty'
  require 'jwt'

  # Admin API key goes here
  key = 'YOUR_ADMIN_API_KEY'

  # Split the key into ID and SECRET
  id, secret = key.split(':')

  # Prepare header and payload
  iat = Time.now.to_i

  header = {alg: 'HS256', typ: 'JWT', kid: id}
  payload = {
      iat: iat,
      exp: iat + 5 * 60,
      aud: '/admin/'
  }

  # Create the token (including decoding secret)
  token = JWT.encode payload, [secret].pack('H*'), 'HS256', header

  # Make an authenticated request to create a post
  url = 'http://localhost:2368/ghost/api/admin/posts/'
  headers = {Authorization: "Ghost #{token}", 'Accept-Version': "v4.0"}
  body = {posts: [{title: 'Hello World'}]}
  puts HTTParty.post(url, body: body, headers: headers)
  ```

  ```py Python theme={"dark"}
  import requests # pip install requests
  import jwt	# pip install pyjwt
  from datetime import datetime as date

  # Admin API key goes here
  key = 'YOUR_ADMIN_API_KEY'

  # Split the key into ID and SECRET
  id, secret = key.split(':')

  # Prepare header and payload
  iat = int(date.now().timestamp())

  header = {'alg': 'HS256', 'typ': 'JWT', 'kid': id}
  payload = {
      'iat': iat,
      'exp': iat + 5 * 60,
      'aud': '/admin/'
  }

  # Create the token (including decoding secret)
  token = jwt.encode(payload, bytes.fromhex(secret), algorithm='HS256', headers=header)

  # Make an authenticated request to create a post
  url = 'http://localhost:2368/ghost/api/admin/posts/'
  headers = {'Authorization': 'Ghost {}'.format(token)}
  body = {'posts': [{'title': 'Hello World'}]}
  r = requests.post(url, json=body, headers=headers)

  print(r)
  ```
</CodeGroup>

### Staff access token authentication

Staff access token authentication is a simple, secure authentication mechanism using JSON Web Tokens (JWTs) to authenticate as a user. Each user can create and refresh their own token, which is used to generate a JWT token and then provided to the API via the standard HTTP Authorization header. For more information on usage, please refer to the [token authentication section](#token-authentication).

The staff access token must be kept private, therefore staff access token authentication is not suitable for browsers or other insecure environments.

### User Authentication

User Authentication is an advanced, session-based authentication method that should only be used for applications where the user is present and able to provide their credentials.

Authenticating as a user requires an application to collect a user’s email and password. These credentials are then swapped for a cookie, and the cookie is then used to maintain a session.

Requests to create a session may require new device verification or two-factor auth. In this case an auth code is sent to the user’s email address, and that must be provided in order to verify the session.

#### Creating a Session

The session and authentication endpoints have custom payloads, different to the standard JSON resource format.

```js  theme={"dark"}
POST /admin/session/
```

**Request**

To create a new session, send a username and password to the sessions endpoint, in this format:

```json  theme={"dark"}
// POST /admin/session/
{
    "username": "{email address}",
    "password": "{password}"
}
```

This request should also have an Origin header. See [CSRF protection](#csrf-protection) for details.

**Success Response**

`201 Created`: A successful session creation will return HTTP `201` response with an empty body and a `set-cookie` header, in the following format:

```text  theme={"dark"}
set-cookie: ghost-admin-api-session={session token}; Path=/ghost; Expires=Mon, 26 Aug 2019 19:14:07 GMT; HttpOnly; SameSite=Lax
```

**2FA Response**

`403 Needs2FAError`: In many cases, session creation will require an auth code to be provided. In this case you’ll get a 403 and the message `User must verify session to login`.

This response still has the `set-cookie` header in the above format, which should be used in the request to provide the token:

**Verification Request**

To send the authentication token

```json  theme={"dark"}
// PUT /admin/session/verify/
{
  "token": "{auth code}"
}
```

To request an auth token to be resent:

```json  theme={"dark"}
// POST /admin/session/verify/
{}
```

#### Making authenticated API requests

The provided session cookie should be provided with every subsequent API request:

* When making the request from a browser using the `fetch` API, pass `credentials: 'include'` to ensure cookies are sent.
* When using XHR you should set the `withCredentials` property of the xhr to `true`
* When using cURL you can use the `--cookie` and `--cookie-jar` options to store and send cookies from a text file.

**CSRF Protection**

Session-based requests must also include either an Origin (preferred) or a Referer header. The value of these headers is checked against the original session creation requests, in order to prevent Cross-Site Request Forgery (CSRF) in a browser environment. In a browser environment, these headers are handled automatically. For server-side or native apps, the Origin header should be sent with an identifying URL as the value.

#### Session-based Examples

```bash  theme={"dark"}
# cURL

# Create a session, and store the cookie in ghost-cookie.txt
curl -c ghost-cookie.txt -d username=me@site.com -d password=secretpassword \
   -H "Origin: https://myappsite.com" \
   -H "Accept-Version: v3.0" \
   https://demo.ghost.io/ghost/api/admin/session/

# Use the session cookie to create a post
curl -b ghost-cookie.txt \
   -d '{"posts": [{"title": "Hello World"}]}' \
   -H "Content-Type: application/json" \
   -H "Accept-Version: v3.0" \
   -H "Origin: https://myappsite.com" \
   https://demo.ghost.io/ghost/api/admin/posts/
```

## Endpoints

These are the endpoints & methods currently available to integrations. More endpoints are available through user authentication. Each endpoint has a stability index, see [versioning](/faq/api-versioning) for more information.

| Resource                                 | Methods                               | Stability |
| ---------------------------------------- | ------------------------------------- | --------- |
| [/posts/](/admin-api/#posts)             | Browse, Read, Edit, Add, Copy, Delete | Stable    |
| [/pages/](/admin-api/#pages)             | Browse, Read, Edit, Add, Copy, Delete | Stable    |
| /tags/                                   | Browse, Read, Edit, Add, Delete       | Stable    |
| [/tiers/](/admin-api/#tiers)             | Browse, Read, Edit, Add               | Stable    |
| [/newsletters/](/admin-api/#newsletters) | Browse, Read, Edit, Add               | Stable    |
| [/offers/](/admin-api/#offers)           | Browse, Read, Edit, Add               | Stable    |
| [/members/](/admin-api/#members)         | Browse, Read, Edit, Add               | Stable    |
| [/users/](/admin-api/#users)             | Browse, Read                          | Stable    |
| [/images/](/admin-api/#images)           | Upload                                | Stable    |
| [/themes/](/admin-api/#themes)[]()       | Upload, Activate                      | Stable    |
| [/site/](/admin-api/#site)               | Read                                  | Stable    |
| [/webhooks/](/admin-api/#webhooks)       | Edit, Add, Delete                     | Stable    |


# Overview
Source: https://docs.ghost.org/admin-api/images/overview



Sending images to Ghost via the API allows you to upload images one at a time, and store them with a [storage adapter](https://ghost.org/integrations/?tag=storage). The default adapter stores files locally in /content/images/ without making any modifications, except for sanitising the filename.

```js  theme={"dark"}
POST /admin/images/upload/
```

### The image object

Images can be uploaded to, and fetched from storage. When an image is uploaded, the response is an image object that contains the new URL for the image - the location from which the image can be fetched.

`url`: *URI* The newly created URL for the image.

`ref`: *String (optional)* The reference for the image, if one was provided with the upload.

```json  theme={"dark"}
// POST /admin/images/upload/

{
    "images": [
        {
            "url": "https://demo.ghost.io/content/images/2019/02/ghost-logo.png",
            "ref": "ghost-logo.png"
        }
    ]
}
```


# Uploading an Image
Source: https://docs.ghost.org/admin-api/images/uploading-an-image



To upload an image, send a multipart formdata request by providing the `'Content-Type': 'multipart/form-data;'` header, along with the following fields encoded as [FormData](https://developer.mozilla.org/en-US/Web/API/FormData/FormData):

`file`: *[Blob](https://developer.mozilla.org/en-US/Web/API/Blob) or [File](https://developer.mozilla.org/en-US/Web/API/File)* The image data that you want to upload.

`purpose`: *String (default: `image`)* Intended use for the image, changes the validations performed. Can be one of `image` , `profile_image` or `icon`. The supported formats for `image`, `icon`, and `profile_image` are WEBP, JPEG, GIF, PNG and SVG. `profile_image` must be square. `icon` must also be square, and additionally supports the ICO format.

`ref`: *String (optional)* A reference or identifier for the image, e.g. the original filename and path. Will be returned as-is in the API response, making it useful for finding & replacing local image paths after uploads.

<RequestExample>
  ```bash  theme={"dark"}
  curl -X POST -F 'file=@/path/to/images/my-image.jpg' -F 'ref=path/to/images/my-image.jpg' -H "Authorization: 'Ghost $token'" -H "Accept-Version: $version" https://{admin_domain}/ghost/api/admin/images/upload/
  ```
</RequestExample>


# Admin API JavaScript Client
Source: https://docs.ghost.org/admin-api/javascript

Admin API keys should remain secret, and therefore this promise-based JavaScript library is designed for server-side usage only. This library handles all the details of generating correctly formed urls and tokens, authenticating and making requests.

***

## Working Example

```js  theme={"dark"}
const api = new GhostAdminAPI({
  url: 'http://localhost:2368',
  key: 'YOUR_ADMIN_API_KEY',
  version: "v6.0",
});

api.posts.add({
    title: 'My first draft API post',
    lexical: '{"root":{"children":[{"children":[{"detail":0,"format":0,"mode":"normal","style":"","text":"Hello, beautiful world! 👋","type":"extended-text","version":1}],"direction":"ltr","format":"","indent":0,"type":"paragraph","version":1}],"direction":"ltr","format":"","indent":0,"type":"root","version":1}}'
});
```

## Authentication

The client requires the host address of your Ghost API and an Admin API key in order to authenticate.

* `url` - API domain, must not end in a trailing slash.
* `key` - string copied from the “Integrations” screen in Ghost Admin
* `version` - minimum version of the API your code works with

The `url` and `key` values can be obtained by creating a new `Custom Integration` under the Integrations screen in Ghost Admin.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cda4a350d118c74c36bb9306cd7ddbbd" data-og-width="1400" width="1400" data-og-height="1097" height="1097" data-path="images/custom-integration-settings.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=806fc0a92f94d33540921e6a8bf96a7e 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4ddff2f6606ed8b59a43b79f544d7646 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=03c5b175be583d78be7f0f197ad99bd5 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0941cb50522f22dab4db9270db96d539 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0489f915c323a6a37d9c33f813eab379 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=61e2c0cd55b6bcc37e27d68804cad5b7 2500w" />
</Frame>

See the documentation on [Admin API authentication](/admin-api/#authentication) for more explanation.

## Endpoints

All endpoints & parameters provided to integrations by the [Admin API](/admin-api/) are supported.

```js  theme={"dark"}
// [Stability: stable]

// Browsing posts returns Promise([Post...]);
// The resolved array will have a meta property
api.posts.browse();
api.posts.read({id: 'abcd1234'});
api.posts.add({title: 'My first API post'});
api.posts.edit({id: 'abcd1234', title: 'Renamed my post', updated_at: post.updated_at});
api.posts.delete({id: 'abcd1234'});

// Browsing pages returns Promise([Page...])
// The resolved array will have a meta property
api.pages.browse({limit: 2});
api.pages.read({id: 'abcd1234'});
api.pages.add({title: 'My first API page'})
api.pages.edit({id: 'abcd1234', title: 'Renamed my page', updated_at: page.updated_at})
api.pages.delete({id: 'abcd1234'});

// Uploading images returns Promise([Image...])
api.images.upload({file: '/path/to/local/file'});
```

## Publishing Example

A bare minimum example of how to create a post from HTML content, including extracting and uploading images first.

```js  theme={"dark"}
const GhostAdminAPI = require('@tryghost/admin-api');
const path = require('path');

// Your API config
const api = new GhostAdminAPI({
    url: 'http://localhost:2368',
    version: "v6.0",
    key: 'YOUR_ADMIN_API_KEY'
});

// Utility function to find and upload any images in an HTML string
function processImagesInHTML(html) {
    // Find images that Ghost Upload supports
    let imageRegex = /="([^"]*?(?:\.jpg|\.jpeg|\.gif|\.png|\.svg|\.sgvz))"/gmi;
    let imagePromises = [];

    while((result = imageRegex.exec(html)) !== null) {
        let file = result[1];
            // Upload the image, using the original matched filename as a reference
            imagePromises.push(api.images.upload({
                ref: file,
                file: path.resolve(file)
            }));
    }

    return Promise
        .all(imagePromises)
        .then(images => {
            images.forEach(image => html = html.replace(image.ref, image.url));
            return html;
        });
}

// Your content
let html = '<p>My test post content.</p><figure><img src="/path/to/my/image.jpg" /><figcaption>My awesome photo</figcaption></figure>';

return processImagesInHTML(html)
    .then(html => {
        return api.posts
            .add(
                {title: 'My Test Post', html},
                {source: 'html'} // Tell the API to use HTML as the content source, instead of Lexical
            )
            .then(res => console.log(JSON.stringify(res)))
            .catch(err => console.log(err));

    })
    .catch(err => console.log(err));
```

## Installation

`yarn add @tryghost/admin-api`

`npm install @tryghost/admin-api`

### Usage

ES modules:

```js  theme={"dark"}
import GhostAdminAPI from '@tryghost/admin-api'
```

Node.js:

```js  theme={"dark"}
const GhostAdminAPI = require('@tryghost/admin-api');
```


# Creating a member
Source: https://docs.ghost.org/admin-api/members/creating-a-member



At minimum, an email is required to create a new, free member.

<RequestExample>
  ```json  theme={"dark"}
  // POST /admin/members/
  {
      "members": [
          {
              "email": "jamie@ghost.org",
          }
      ]
  }
  ```
</RequestExample>

<ResponseExample>
  ```json  theme={"dark"}
  // Response
  {
      "members": [
          {
              "id": "624d445026833200a5801bce",
              "uuid": "83525d87-ac70-40f5-b13c-f9b9753dcbe8",
              "email": "jamie@ghost.org",
              "name": null,
              "note": null,
              "geolocation": null,
              "created_at": "2022-04-06T07:42:08.000Z",
              "updated_at": "2022-04-06T07:42:08.000Z",
              "labels": [],
              "subscriptions": [],
              "avatar_image": "https://gravatar.com/avatar/7d8efd2c2a781111599a8cae293cf704?s=250&d=blank",
              "email_count": 0,
              "email_opened_count": 0,
              "email_open_rate": null,
              "status": "free",
              "last_seen_at": null,
              "tiers": [],
              "newsletters": []
          }
      ]
  }
  ```
</ResponseExample>

Additional writable member fields include:

| Key             | Description                                      |
| --------------- | ------------------------------------------------ |
| **name**        | member name                                      |
| **note**        | notes on the member                              |
| **labels**      | member labels                                    |
| **newsletters** | List of newsletters subscribed to by this member |

Create a new, free member with name, newsletter, and label:

```json  theme={"dark"}
// POST /admin/members/
{
    "members": [
        {
            "email": "jamie@ghost.org",
            "name": "Jamie",
            "labels": [
                {
                    "name": "VIP",
                    "slug": "vip"
                }
            ],
            "newsletters": [
                {
                    "id": "624d445026833200a5801bce"
                }
            ]
        }
    ]
}
```


# Overview
Source: https://docs.ghost.org/admin-api/members/overview



The members resource provides an endpoint for fetching, creating, and updating member data.

Fetch members (by default, the 15 newest members are returned):

```json  theme={"dark"}
// GET /admin/members/?include=newsletters%2Clabels
{
    "members": [
        {
            "id": "623199bfe8bc4d3097caefe0",
            "uuid": "4fa3e4df-85d5-44bd-b0bf-d504bbe22060",
            "email": "jamie@example.com",
            "name": "Jamie",
            "note": null,
            "geolocation": null,
            "created_at": "2022-03-16T08:03:11.000Z",
            "updated_at": "2022-03-16T08:03:40.000Z",
            "labels": [
                {
                    "id": "623199dce8bc4d3097caefe9",
                    "name": "Label 1",
                    "slug": "label-1",
                    "created_at": "2022-03-16T08:03:40.000Z",
                    "updated_at": "2022-03-16T08:03:40.000Z"
                }
            ],
            "subscriptions": [],
            "avatar_image": "https://gravatar.com/avatar/76a4c5450dbb6fde8a293a811622aa6f?s=250&d=blank",
            "email_count": 0,
            "email_opened_count": 0,
            "email_open_rate": null,
            "status": "free",
            "last_seen_at": "2022-05-20T16:29:29.000Z",
            "newsletters": [
                {
                    "id": "62750bff2b868a34f814af08",
                    "name": "My Ghost Site",
                    "description": null,
                    "status": "active"
                }
            ]
        },
        ...
    ]
}
```

### Subscription object

A paid member includes a subscription object that provides subscription details.

```json  theme={"dark"}
// Subscription object
[
    {
        "id": "sub_1KlTkYSHlkrEJE2dGbzcgc61",
        "customer": {
            "id": "cus_LSOXHFwQB7ql18",
            "name": "Jamie",
            "email": "jamie@ghost.org"
        },
        "status": "active",
        "start_date": "2022-04-06T07:57:58.000Z",
        "default_payment_card_last4": "4242",
        "cancel_at_period_end": false,
        "cancellation_reason": null,
        "current_period_end": "2023-04-06T07:57:58.000Z",
        "price": {
            "id": "price_1Kg0ymSHlkrEJE2dflUN66EW",
            "price_id": "6239692c664a9e6f5e5e840a",
            "nickname": "Yearly",
            "amount": 100000,
            "interval": "year",
            "type": "recurring",
            "currency": "USD"
        },
        "tier": {...},
        "offer": null
    }
]
```

| Key                               | Description                                                     |
| --------------------------------- | --------------------------------------------------------------- |
| **customer**                      | Stripe customer attached to the subscription                    |
| **start\_date**                   | Subscription start date                                         |
| **default\_payment\_card\_last4** | Last 4 digits of the card                                       |
| **cancel\_at\_period\_end**       | If the subscription should be canceled or renewed at period end |
| **cancellation\_reason**          | Reason for subscription cancellation                            |
| **current\_period\_end**          | Subscription end date                                           |
| **price**                         | Price information for subscription including Stripe price ID    |
| **tier**                          | Member subscription tier                                        |
| **offer**                         | Offer details for a subscription                                |


# Updating a member
Source: https://docs.ghost.org/admin-api/members/updating-a-member



```js  theme={"dark"}
PUT /admin/members/{id}/
```

All writable fields of a member can be updated. It’s recommended to perform a `GET` request to fetch the latest data before updating a member.

A minimal example for updating the name of a member.

<RequestExample>
  ```json  theme={"dark"}
  // PUT /admin/members/{id}/
  {
      "members": [
          {
              "name": "Jamie II"
          }
      ]
  }
  ```
</RequestExample>


# Creating a Newsletter
Source: https://docs.ghost.org/admin-api/newsletters/creating-a-newsletter



```js  theme={"dark"}
POST /admin/newsletters/
```

Required fields: `name`

Options: `opt_in_existing`

When `opt_in_existing` is set to `true`, existing members with a subscription to one or more active newsletters are also subscribed to this newsletter. The response metadata will include the number of members opted-in.

<RequestExample>
  ```json  theme={"dark"}
  // POST /admin/newsletters/?opt_in_existing=true
  {
      "newsletters": [
          {
              "name": "My newly created newsletter",
              "description": "This is a newsletter description",
              "sender_reply_to": "newsletter",
              "status": "active",
              "subscribe_on_signup": true,
              "show_header_icon": true,
              "show_header_title": true,
              "show_header_name": true,
              "title_font_category": "sans_serif",
              "title_alignment": "center",
              "show_feature_image": true,
              "body_font_category": "sans_serif",
              "show_badge": true
          }
      ]
  }
  ```
</RequestExample>


# Overview
Source: https://docs.ghost.org/admin-api/newsletters/overview



Newsletters allow finer control over distribution of site content via email, allowing members to opt-in or opt-out of different categories of content. By default each site has one newsletter.

### The newsletter object

```json  theme={"dark"}
// GET admin/newsletters/?limit=50
{
    "newsletters": [
        {
            "id": "62750bff2b868a34f814af08",
            "name": "My Ghost site",
            "description": null,
            "slug": "default-newsletter",
            "sender_name": null,
            "sender_email": null,
            "sender_reply_to": "newsletter",
            "status": "active",
            "visibility": "members",
            "subscribe_on_signup": true,
            "sort_order": 0,
            "header_image": null,
            "show_header_icon": true,
            "show_header_title": true,
            "title_font_category": "sans_serif",
            "title_alignment": "center",
            "show_feature_image": true,
            "body_font_category": "sans_serif",
            "footer_content": null,
            "show_badge": true,
            "created_at": "2022-05-06T11:52:31.000Z",
            "updated_at": "2022-05-20T07:43:43.000Z",
            "show_header_name": true,
            "uuid": "59fbce16-c0bf-4583-9bb3-5cd52db43159"
        }
    ],
    "meta": {
        "pagination": {
            "page": 1,
            "limit": 50,
            "pages": 1,
            "total": 1,
            "next": null,
            "prev": null
        }
    }
}
```

| Key                       | Description                                                                                                                                          |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **name**                  | Public name for the newsletter                                                                                                                       |
| **description**           | (nullable) Public description of the newsletter                                                                                                      |
| **status**                | `active` or `archived` - denotes if the newsletter is active or archived                                                                             |
| **slug**                  | The reference to this newsletter that can be used in the `newsletter` option when sending a post via email                                           |
| **sender\_name**          | (nullable) The sender name of the emails                                                                                                             |
| **sender\_email**         | (nullable) The email from which to send emails. Requires validation.                                                                                 |
| **sender\_reply\_to**     | The reply-to email address for sent emails. Can be either `newsletter` (= use `sender_email`) or `support` (use support email from Portal settings). |
| **subscribe\_on\_signup** | `true`/`false`. Whether members should automatically subscribe to this newsletter on signup                                                          |
| **header\_image**         | (nullable) Path to an image to show at the top of emails. Recommended size 1200x600                                                                  |
| **show\_header\_icon**    | `true`/`false`. Show the site icon in emails                                                                                                         |
| **show\_header\_title**   | `true`/`false`. Show the site name in emails                                                                                                         |
| **show\_header\_name**    | `true`/`false`. Show the newsletter name in emails                                                                                                   |
| **title\_font\_category** | Title font style. Either `serif` or `sans_serif`                                                                                                     |
| **show\_feature\_image**  | `true`/`false`. Show the post's feature image in emails                                                                                              |
| **body\_font\_category**  | Body font style. Either `serif` or `sans_serif`                                                                                                      |
| **footer\_content**       | (nullable) Extra information or legal text to show in the footer of emails. Should contain valid HTML.                                               |
| **show\_badge**           | `true`/`false`. Show you’re a part of the indie publishing movement by adding a small Ghost badge in the footer                                      |


# Sender email validation
Source: https://docs.ghost.org/admin-api/newsletters/sender-email-validation



When updating the `sender_email` field, email verification is required before emails are sent from the new address. After updating the property, the `sent_email_verification` metadata property will be set, containing `sender_email`. The `sender_email` property will remain unchanged until the address has been verified by clicking the link that is sent to the address specified in `sender_email`.

<RequestExample>
  ```json  theme={"dark"}
  PUT /admin/newsletters/62750bff2b868a34f814af08/
  {
      "newsletters": [
          {
              "sender_email": "daily-newsletter@domain.com"
          }
      ]
  }
  ```
</RequestExample>

<ResponseExample>
  ```json  theme={"dark"}
  // Response
  {
      "newsletters": [
          {
              "id": "62750bff2b868a34f814af08",
              "name": "My newly created newsletter",
              "description": "This is an edited newsletter description",
              "sender_name": "Daily Newsletter",
              "sender_email": null,
              "sender_reply_to": "newsletter",
              "status": "active",
              "subscribe_on_signup": true,
              "sort_order": 1,
              "header_image": null,
              "show_header_icon": true,
              "show_header_title": true,
              "title_font_category": "sans_serif",
              "title_alignment": "center",
              "show_feature_image": true,
              "body_font_category": "sans_serif",
              "footer_content": null,
              "show_badge": true,
              "show_header_name": true
          }
      ],
      "meta": {
          "sent_email_verification": [
              "sender_email"
          ]
      }
  }
  ```
</ResponseExample>


# Updating a Newsletter
Source: https://docs.ghost.org/admin-api/newsletters/updating-a-newsletter



<ResponseExample>
  ```json  theme={"dark"}
  PUT /admin/newsletters/629711f95d57e7229f16181c/
  {
      "newsletters": [
          {
              "id": "62750bff2b868a34f814af08",
              "name": "My newly created newsletter",
              "description": "This is an edited newsletter description",
              "sender_name": "Daily Newsletter",
              "sender_email": null,
              "sender_reply_to": "newsletter",
              "status": "active",
              "subscribe_on_signup": true,
              "sort_order": 1,
              "header_image": null,
              "show_header_icon": true,
              "show_header_title": true,
              "title_font_category": "sans_serif",
              "title_alignment": "center",
              "show_feature_image": true,
              "body_font_category": "sans_serif",
              "footer_content": null,
              "show_badge": true,
              "show_header_name": true
          }
      ]
  }
  ```
</ResponseExample>


# Creating an Offer
Source: https://docs.ghost.org/admin-api/offers/creating-an-offer



```js  theme={"dark"}
POST /admin/offers/
```

Required fields: `name`, `code`, `cadence`, `duration`, `amount`, `tier.id` , `type`

When offer `type` is `fixed`, `currency` is also required and must match the tier’s currency. New offers are created as active by default.

Below is an example for creating an offer with all properties including prices, description, and benefits.

<RequestExample>
  ```json  theme={"dark"}
  // POST /admin/offers/
  {
      "offers": [
          {
              "name": "Black Friday",
              "code": "black-friday",
              "display_title": "Black Friday Sale!",
              "display_description": "10% off on yearly plan",
              "type": "percent",
              "cadence": "year",
              "amount": 12,
              "duration": "once",
              "duration_in_months": null,
              "currency_restriction": false,
              "currency": null,
              "status": "active",
              "redemption_count": 0,
              "tier": {
                  "id": "62307cc71b4376a976734038",
                  "name": "Gold"
              }
          }
      ]
  }
  ```
</RequestExample>


# Overview
Source: https://docs.ghost.org/admin-api/offers/overview



Use offers to create a discount or special price for members signing up on a tier.

### The offer object

When you fetch, create, or edit an offer, the API responds with an array of one or more offer objects. These objects include related `tier` data.

```json  theme={"dark"}
// GET /admin/offers/
{
    "offers": [
        {
            "id": "6230dd69e8bc4d3097caefd3",
            "name": "Black friday",
            "code": "black-friday",
            "display_title": "Black friday sale!",
            "display_description": "10% off our yearly price",
            "type": "percent",
            "cadence": "year",
            "amount": 10,
            "duration": "once",
            "duration_in_months": null,
            "currency_restriction": false,
            "currency": null,
            "status": "active",
            "redemption_count": 0,
            "tier": {
                "id": "62307cc71b4376a976734038",
                "name": "Platinum"
            }
        }
    ]
}
```

| Key                       | Description                                                                                                                                                                 |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **display\_title**        | Name displayed in the offer window                                                                                                                                          |
| **display\_description**  | Text displayed in the offer window                                                                                                                                          |
| **name**                  | Internal name for an offer, must be unique                                                                                                                                  |
| **code**                  | Shortcode for the offer, for example: [https://yoursite.com/black-friday](https://yoursite.com/black-friday)                                                                |
| **status**                | `active` or `archived` - denotes if the offer is active or archived                                                                                                         |
| **type**                  | `percent` or `fixed` - whether the amount off is a percentage or fixed                                                                                                      |
| **amount**                | Offer discount amount, as a percentage or fixed value as set in `type`. *Amount is always denoted by the smallest currency unit (e.g., 100 cents instead of \$1.00 in USD)* |
| **currency**              | `fixed` type offers only - specifies tier's currency as three letter ISO currency code                                                                                      |
| **currency\_restriction** | Denotes whether the offer \`currency\` is restricted. If so, changing the currency invalidates the offer                                                                    |
| **duration**              | `once`/`forever`/`repeating`. `repeating` duration is only available when `cadence` is `month`                                                                              |
| **duration\_in\_months**  | Number of months offer should be repeated when `duration` is `repeating`                                                                                                    |
| **redemption\_count**     | Number of times the offer has been redeemed                                                                                                                                 |
| **tier**                  | Tier on which offer is applied                                                                                                                                              |
| **cadence**               | `month` or `year` - denotes if offer applies to tier's monthly or yearly price                                                                                              |


# Updating an Offer
Source: https://docs.ghost.org/admin-api/offers/updating-an-offer



For existing offers, only `name` , `code`, `display_title` and `display_description` are editable.

The example updates `display title` and `code`.

<RequestExample>
  ```json  theme={"dark"}
  // PUT /admin/offers/{id}/
  {
      "offers": [
          {
              "display_title": "Black Friday 2022",
              "code": "black-friday-2022"
          }
      ]
  }
  ```
</RequestExample>


# Overview
Source: https://docs.ghost.org/admin-api/pages/overview



Pages are [static resources](/publishing/) that are not included in channels or collections on the Ghost front-end. They are identical to posts in terms of request and response structure when working with the APIs.

```js  theme={"dark"}
GET /admin/pages/
GET /admin/pages/{id}/
GET /admin/pages/slug/{slug}/
POST /admin/pages/
POST /admin/pages/{id}/copy
PUT /admin/pages/{id}/
DELETE /admin/pages/{id}/
```


# Creating a Post
Source: https://docs.ghost.org/admin-api/posts/creating-a-post



```js  theme={"dark"}
POST /admin/posts/
```

Required fields: `title`

Create draft and published posts with the add posts endpoint. All fields except `title` can be empty or have a default that is applied automatically. Below is a minimal example for creating a published post with content:

```json  theme={"dark"}
// POST /admin/posts/
{
    "posts": [
        {
            "title": "My test post",
            "lexical": "{\"root\":{\"children\":[{\"children\":[{\"detail\":0,\"format\":0,\"mode\":\"normal\",\"style\":\"\",\"text\":\"Hello, beautiful world! 👋\",\"type\":\"extended-text\",\"version\":1}],\"direction\":\"ltr\",\"format\":\"\",\"indent\":0,\"type\":\"paragraph\",\"version\":1}],\"direction\":\"ltr\",\"format\":\"\",\"indent\":0,\"type\":\"root\",\"version\":1}}",
            "status": "published"
        }
    ]
}
```

A post must always have [at least one author](#tags-and-authors), and this will default to the staff user with the owner role when [token authentication](#token-authentication) is used.

#### Source HTML

The post creation endpoint is also able to convert HTML into Lexical. The conversion generates the best available Lexical representation, meaning this operation is lossy and the HTML rendered by Ghost may be different from the source HTML. For the best results ensure your HTML is well-formed, e.g. uses block and inline elements correctly.

To use HTML as the source for your content instead of Lexical, use the `source` parameter:

```json  theme={"dark"}
// POST /admin/posts/?source=html
{
    "posts": [
        {
            "title": "My test post",
            "html": "<p>My post content. Work in progress...</p>",
            "status": "published"
        }
    ]
}
```

For lossless HTML conversion, you can wrap your HTML in a single Lexical card:

```html  theme={"dark"}
<!--kg-card-begin: html-->
<p>HTML goes here</p>
<!--kg-card-end: html-->
```

#### Tags and Authors

You can link tags and authors to any post you create in the same request body, using either short or long form to identify linked resources.

Short form uses a single string to identify a tag or author resource. Tags are identified by name and authors are identified by email address:

```json  theme={"dark"}
// POST /admin/posts/
{
    "posts": [
        {
            "title": "My test post",
            "tags": ["Getting Started", "Tag Example"],
            "authors": ["example@ghost.org", "test@ghost.org"],
            "lexical": "{\"root\":{\"children\":[{\"children\":[{\"detail\":0,\"format\":0,\"mode\":\"normal\",\"style\":\"\",\"text\":\"Hello, beautiful world! 👋\",\"type\":\"extended-text\",\"version\":1}],\"direction\":\"ltr\",\"format\":\"\",\"indent\":0,\"type\":\"paragraph\",\"version\":1}],\"direction\":\"ltr\",\"format\":\"\",\"indent\":0,\"type\":\"root\",\"version\":1}}",
            "status": "published"
        }
    ]
}
```

Long form requires an object with at least one identifying key-value pair:

```json  theme={"dark"}
// POST /admin/posts/
{
    "posts": [
        {
            "title": "My test post",
            "tags": [
                { "name": "my tag", "description": "a very useful tag" },
                { "name": "#hidden" }
            ],
            "authors": [
                { "id": "5c739b7c8a59a6c8ddc164a1" },
                { "id": "5c739b7c8a59a6c8ddc162c5" },
                { "id": "5c739b7c8a59a6c8ddc167d9" }
            ]
        }
    ]
}
```

Tags that cannot be matched are automatically created. If no author can be matched, Ghost will fallback to using the staff user with the owner role.


# Deleting a Post
Source: https://docs.ghost.org/admin-api/posts/deleting-a-post



```js  theme={"dark"}
DELETE /admin/posts/{id}/
```

Delete requests have no payload in the request or response. Successful deletes will return an empty 204 response.


# Email only posts
Source: https://docs.ghost.org/admin-api/posts/email-only-posts



To send a post as an email without publishing it on the site, the `email_only` property must be set to `true` when publishing or scheduling the post in combination with the `newsletter` parameter:

<RequestExample>
  ```json  theme={"dark"}
  // PUT admin/posts/5b7ada404f87d200b5b1f9c8/?newsletter=weekly-newsletter
  {
      "posts": [
          {
              "updated_at": "2022-06-05T20:52:37.000Z",
              "status": "published",
              "email_only": true
          }
      ]
  }
  ```
</RequestExample>

When an email-only post has been sent, the post will have a `status` of `sent`.


# Overview
Source: https://docs.ghost.org/admin-api/posts/overview



Posts are the [primary resource](/publishing/) in a Ghost site, providing means for publishing, managing and displaying content.

At the heart of every post is a Lexical field, containing a standardised JSON-based representation of your content, which can be rendered in multiple formats.

```js  theme={"dark"}
GET /admin/posts/
GET /admin/posts/{id}/
GET /admin/posts/slug/{slug}/
POST /admin/posts/
PUT /admin/posts/{id}/
DELETE /admin/posts/{id}/
```

### The post object

Whenever you fetch, create, or edit a post, the API will respond with an array of one or more post objects. These objects will include all related tags, authors, and author roles.

By default, the API expects and returns content in the **Lexical** format only. To include **HTML** in the response use the `formats` parameter:

```json  theme={"dark"}
// GET /admin/posts/?formats=html,lexical
{
    "posts": [
        {
            "slug": "welcome-short",
            "id": "5ddc9141c35e7700383b2937",
            "uuid": "a5aa9bd8-ea31-415c-b452-3040dae1e730",
            "title": "Welcome",
            "lexical": "{\"root\":{\"children\":[{\"children\":[{\"detail\":0,\"format\":0,\"mode\":\"normal\",\"style\":\"\",\"text\":\"Hello, beautiful world! 👋\",\"type\":\"extended-text\",\"version\":1}],\"direction\":\"ltr\",\"format\":\"\",\"indent\":0,\"type\":\"paragraph\",\"version\":1}],\"direction\":\"ltr\",\"format\":\"\",\"indent\":0,\"type\":\"root\",\"version\":1}}",
            "html": "<p>Hello, beautiful world! 👋</p>",
            "comment_id": "5ddc9141c35e7700383b2937",
            "feature_image": "https://static.ghost.org/v3.0.0/images/welcome-to-ghost.png",
            "feature_image_alt": null,
            "feature_image_caption": null,
            "featured": false,
            "status": "published",
            "visibility": "public",
            "created_at": "2019-11-26T02:43:13.000Z",
            "updated_at": "2019-11-26T02:44:17.000Z",
            "published_at": "2019-11-26T02:44:17.000Z",
            "custom_excerpt": null,
            "codeinjection_head": null,
            "codeinjection_foot": null,
            "custom_template": null,
            "canonical_url": null,
            "tags": [
                {
                    "created_at": "2019-11-26T02:39:31.000Z",
                    "description": null,
                    "feature_image": null,
                    "id": "5ddc9063c35e7700383b27e0",
                    "meta_description": null,
                    "meta_title": null,
                    "name": "Getting Started",
                    "slug": "getting-started",
                    "updated_at": "2019-11-26T02:39:31.000Z",
                    "url": "https://docs.ghost.io/tag/getting-started/",
                    "visibility": "public"
                }
            ],
            "authors": [
                {
                    "id": "5951f5fca366002ebd5dbef7",
                    "name": "Ghost",
                    "slug": "ghost-user",
                    "email": "info@ghost.org",
                    "profile_image": "//www.gravatar.com/avatar/2fab21a4c4ed88e76add10650c73bae1?s=250&d=mm&r=x",
                    "cover_image": null,
                    "bio": null,
                    "website": "https://ghost.org",
                    "location": "The Internet",
                    "facebook": "ghost",
                    "twitter": "@ghost",
                    "accessibility": null,
                    "status": "locked",
                    "meta_title": null,
                    "meta_description": null,
                    "tour": null,
                    "last_seen": null,
                    "created_at": "2019-11-26T02:39:32.000Z",
                    "updated_at": "2019-11-26T04:30:57.000Z",
                    "roles": [
                        {
                            "id": "5ddc9063c35e7700383b27e3",
                            "name": "Author",
                            "description": "Authors",
                            "created_at": "2019-11-26T02:39:31.000Z",
                            "updated_at": "2019-11-26T02:39:31.000Z"
                        }
                    ],
                    "url": "https://docs.ghost.io/author/ghost-user/"
                }
            ],
            "primary_author": {
                "id": "5951f5fca366002ebd5dbef7",
                "name": "Ghost",
                "slug": "ghost-user",
                "email": "info@ghost.org",
                "profile_image": "//www.gravatar.com/avatar/2fab21a4c4ed88e76add10650c73bae1?s=250&d=mm&r=x",
                "cover_image": null,
                "bio": null,
                "website": "https://ghost.org",
                "location": "The Internet",
                "facebook": "ghost",
                "twitter": "@ghost",
                "accessibility": null,
                "status": "locked",
                "meta_title": null,
                "meta_description": null,
                "tour": null,
                "last_seen": null,
                "created_at": "2019-11-26T02:39:32.000Z",
                "updated_at": "2019-11-26T04:30:57.000Z",
                "roles": [
                    {
                        "id": "5ddc9063c35e7700383b27e3",
                        "name": "Author",
                        "description": "Authors",
                        "created_at": "2019-11-26T02:39:31.000Z",
                        "updated_at": "2019-11-26T02:39:31.000Z"
                    }
                ],
                "url": "https://docs.ghost.io/author/ghost-user/"
            },
            "primary_tag": {
                "id": "5ddc9063c35e7700383b27e0",
                "name": "Getting Started",
                "slug": "getting-started",
                "description": null,
                "feature_image": null,
                "visibility": "public",
                "meta_title": null,
                "meta_description": null,
                "created_at": "2019-11-26T02:39:31.000Z",
                "updated_at": "2019-11-26T02:39:31.000Z",
                "og_image": null,
                "og_title": null,
                "og_description": null,
                "twitter_image": null,
                "twitter_title": null,
                "twitter_description": null,
                "codeinjection_head": null,
                "codeinjection_foot": null,
                "canonical_url": null,
                "accent_color": null,
                "parent": null,
                "url": "https://docs.ghost.io/tag/getting-started/"
            },
            "url": "https://docs.ghost.io/welcome-short/",
            "excerpt": "👋 Welcome, it's great to have you here.",
            "og_image": null,
            "og_title": null,
            "og_description": null,
            "twitter_image": null,
            "twitter_title": null,
            "twitter_description": null,
            "meta_title": null,
            "meta_description": null,
            "email_only": false,
            "newsletter": {
                "id": "62750bff2b868a34f814af08",
                "name": "Weekly newsletter",
                "description": null,
                "slug": "default-newsletter",
                "sender_name": "Weekly newsletter",
                "sender_email": null,
                "sender_reply_to": "newsletter",
                "status": "active",
                "visibility": "members",
                "subscribe_on_signup": true,
                "sort_order": 0,
                "header_image": null,
                "show_header_icon": true,
                "show_header_title": true,
                "title_font_category": "sans_serif",
                "title_alignment": "center",
                "show_feature_image": true,
                "body_font_category": "sans_serif",
                "footer_content": null,
                "show_badge": true,
                "created_at": "2022-06-06T11:52:31.000Z",
                "updated_at": "2022-06-20T07:43:43.000Z",
                "show_header_name": true,
                "uuid": "59fbce16-c0bf-4583-9bb3-5cd52db43159"
            },
            "email": {
                "id": "628f3b462de0a130909d4a6a",
                "uuid": "955305de-d89e-4468-927f-2d2b8fec88e5",
                "status": "submitted",
                "recipient_filter": "status:-free",
                "error": null,
                "error_data": "[]",
                "email_count": 256,
                "delivered_count": 256,
                "opened_count": 59,
                "failed_count": 0,
                "subject": "Welcome",
                "from": "\"Weekly newsletter\"<noreply@example.com>",
                "reply_to": "noreply@example.com",
                "html": "...",
                "plaintext": "...",
                "track_opens": true,
                "submitted_at": "2022-05-26T08:33:10.000Z",
                "created_at": "2022-06-26T08:33:10.000Z",
                "updated_at": "2022-06-26T08:33:16.000Z"
            }
        }
    ]
}
```

#### Parameters

When retrieving posts from the admin API, it is possible to use the `include`, `formats`, `filter`, `limit`, `page` and `order` parameters as documented for the [Content API](/content-api/#parameters).

Some defaults are different between the two APIs, however the behaviour and availability of the parameters remains the same.


# Publishing a Post
Source: https://docs.ghost.org/admin-api/posts/publishing-a-post



Publish a draft post by updating its status to `published`:

<RequestExample>
  ```json  theme={"dark"}
  // PUT admin/posts/5b7ada404f87d200b5b1f9c8/
  {
      "posts": [
          {
              "updated_at": "2022-06-05T20:52:37.000Z",
              "status": "published"
          }
      ]
  }
  ```
</RequestExample>


# Scheduling a Post
Source: https://docs.ghost.org/admin-api/posts/scheduling-a-post



A post can be scheduled by updating or setting the `status` to `scheduled` and setting `published_at` to a datetime in the future:

<RequestExample>
  ```json  theme={"dark"}
  // PUT admin/posts/5b7ada404f87d200b5b1f9c8/
  {
      "posts": [
          {
              "updated_at": "2022-06-05T20:52:37.000Z",
              "status": "scheduled",
              "published_at": "2023-06-10T11:00:00.000Z"
          }
      ]
  }
  ```
</RequestExample>

At the time specified in `published_at`, the post will be published, email newsletters will be sent (if applicable), and the status of the post will change to `published`. For email-only posts, the status will change to `sent`.


# Sending a Post via email
Source: https://docs.ghost.org/admin-api/posts/sending-a-post



To send a post by email, the `newsletter` query parameter must be passed when publishing or scheduling the post, containing the newsletter’s `slug`.

Optionally, a filter can be provided to send the email to a subset of members subscribed to the newsletter by passing the `email_segment` query parameter containing a valid NQL filter for members. Commonly used values are `status:free` (all free members), `status:-free` (all paid members) and `all`. If `email_segment` is not specified, the default is `all` (no additional filtering applied).

Posts are sent by email if and only if an active newsletter is provided.

<RequestExample>
  ```json  theme={"dark"}
  // PUT admin/posts/5b7ada404f87d200b5b1f9c8/?newsletter=weekly-newsletter&email_segment=status%3Afree
  {
      "posts": [
          {
              "updated_at": "2022-06-05T20:52:37.000Z",
              "status": "published"
          }
      ]
  }
  ```
</RequestExample>

When a post has been sent by email, the post object will contain the related `newsletter` and `email` objects. If the related email object has a `status` of `failed`, sending can be retried by reverting the post’s status to `draft` and then republishing the post.

<ResponseExample>
  ```json  theme={"dark"}
  {
      "posts": [
          {
              "id": "5ddc9141c35e7700383b2937",
              ...
              "email": {
                  "id": "628f3b462de0a130909d4a6a",
                  "uuid": "955305de-d89e-4468-927f-2d2b8fec88e5",
                  "status": "failed",
                  "recipient_filter": "all",
                  "error": "Email service is currently unavailable - please try again",
                  "error_data": "[{...}]",
                  "email_count": 2,
                  "delivered_count": 0,
                  "opened_count": 0,
                  "failed_count": 0,
                  "subject": "Welcome",
                  "from": "\"Weekly newsletter\"<noreply@example.com>",
                  "reply_to": "noreply@example.com",
                  "html": "...",
                  "plaintext": "...",
                  "track_opens": true,
                  "submitted_at": "2022-05-26T08:33:10.000Z",
                  "created_at": "2022-06-26T08:33:10.000Z",
                  "updated_at": "2022-06-26T08:33:16.000Z"
              },
              ...
          }
      ]
  }
  ```
</ResponseExample>


# Updating a Post
Source: https://docs.ghost.org/admin-api/posts/updating-a-post



```js  theme={"dark"}
PUT /admin/posts/{id}/
```

Required fields: `updated_at`

All writable fields of a post can be updated via the edit endpoint. The `updated_at` field is required as it is used to handle collision detection and ensure you’re not overwriting more recent updates. It is recommended to perform a GET request to fetch the latest data before updating a post. Below is a minimal example for updating the title of a post:

<RequestExample>
  ```json  theme={"dark"}
  // PUT admin/posts/5b7ada404f87d200b5b1f9c8/
  {
      "posts": [
          {
              "title": "My new title",
              "updated_at": "2022-06-05T20:52:37.000Z"
          }
      ]
  }
  ```
</RequestExample>

#### Tags and Authors

Tag and author relations will be replaced, not merged. Again, the recommendation is to always fetch the latest version of a post, make any amends to this such as adding another tag to the tags array, and then send the amended data via the edit endpoint.


# Overview
Source: https://docs.ghost.org/admin-api/themes/overview



Themes can be uploaded from a local ZIP archive and activated.

```js  theme={"dark"}
POST /admin/themes/upload;
PUT /admin/themes/{ name }/activate;
```

### The theme object

When a theme is uploaded or activated, the response is a `themes` array containing one theme object with metadata about the theme, as well as its status (active or not).

`name`: *String* The name of the theme. This is the value that is used to activate the theme.

`package`: *Object* The contents of the `package.json` file is exposed in the API as it contains useful theme metadata.

`active`: *Boolean* The status of the theme showing if the theme is currently used or not.

`templates`: *Array* The list of templates defined by the theme.

```json  theme={"dark"}
// POST /admin/images/upload/
{
    themes: [{
      name: "Alto-master",
      package: {...},
      active: false,
      templates: [{
        filename: "custom-full-feature-image",
        name: "Full Feature Image",
        for: ["page", "post"],
        slug: null
      }, ...]
    }]
}
```


# Uploading a theme
Source: https://docs.ghost.org/admin-api/themes/uploading-a-theme



To upload a theme ZIP archive, send a multipart formdata request by providing the `'Content-Type': 'multipart/form-data;'` header, along with the following field encoded as [FormData](https://developer.mozilla.org/en-US/docs/Web/API/FormData/FormData):

`file`: *[Blob](https://developer.mozilla.org/en-US/docs/Web/API/Blob) or [File](https://developer.mozilla.org/en-US/docs/Web/API/File)* The theme archive that you want to upload.

<RequestExample>
  ```bash  theme={"dark"}
  curl -X POST -F 'file=@/path/to/themes/my-theme.zip' -H "Authorization: Ghost $token" -H "Accept-Version: $version" https://{admin_domain}/ghost/api/admin/themes/upload
  ```
</RequestExample>


# Creating a Tier
Source: https://docs.ghost.org/admin-api/tiers/creating-a-tier



```js  theme={"dark"}
POST /admin/tiers/
```

Required fields: `name`

Create public and hidden tiers by using this endpoint. New tiers are always set as `active` when created.

The example below creates a paid Tier with all properties including custom monthly/yearly prices, description, benefits, and welcome page.

<RequestExample>
  ```json  theme={"dark"}
  // POST /admin/tiers/
  {
      "tiers": [
          {
              "name": "Platinum",
              "description": "Access to everything",
              "welcome_page_url": "/welcome-to-platinum",
              "visibility": "public",
              "monthly_price": 1000,
              "yearly_price": 10000,
              "currency": "usd",
              "benefits": [
                  "Benefit 1",
                  "Benefit 2"
              ]
          }
      ]
  }
  ```
</RequestExample>


# Overview
Source: https://docs.ghost.org/admin-api/tiers/overview



Tiers allow publishers to create multiple options for an audience to become paid subscribers. Each tier can have its own price points, benefits, and content access levels. Ghost connects tiers directly to the publication’s Stripe account.

### The tier object

Whenever you fetch, create, or edit a tier, the API responds with an array of one or more tier objects.

By default, the API doesn’t return monthly/yearly prices or benefits. To include them in the response, use the `include` parameter with any or all of the following values: `monthly_price`, `yearly_price`, `benefits`.

```json  theme={"dark"}
// GET admin/tiers/?include=monthly_price,yearly_price,benefits
{
    "tiers": [
        {
            "id": "622727ad96a190e914ab6664",
            "name": "Free",
            "description": null,
            "slug": "free",
            "active": true,
            "type": "free",
            "welcome_page_url": null,
            "created_at": "2022-03-08T09:53:49.000Z",
            "updated_at": "2022-03-08T10:43:15.000Z",
            "stripe_prices": null,
            "monthly_price": null,
            "yearly_price": null,
            "benefits": [],
            "visibility": "public"
        },
        {
            "id": "622727ad96a190e914ab6665",
            "name": "Bronze",
            "description": "Access to basic features",
            "slug": "default-product",
            "active": true,
            "type": "paid",
            "welcome_page_url": null,
            "created_at": "2022-03-08T09:53:49.000Z",
            "updated_at": "2022-03-14T19:22:46.000Z",
            "stripe_prices": null,
            "monthly_price": 500,
            "yearly_price": 5000,
            "currency": "usd",
            "benefits": [
                "Free daily newsletter",
                "3 posts a week"
            ],
            "visibility": "public"
        }
    ],
    "meta": {
        "pagination": {
            "page": 1,
            "limit": 15,
            "pages": 1,
            "total": 2,
            "next": null,
            "prev": null
        }
    }
}
```

### Parameters

When retrieving tiers from the Admin API, it’s possible to use the `include` and `filter` parameters.

Available **include** values:

* `monthly_price` - include monthly price data
* `yearly_price` - include yearly price data
* `benefits` - include benefits data

Available **filter** values:

* `type:free|paid` - for filtering paid or free tiers
* `visibility:public|none` - for filtering tiers based on their visibility
* `active:true|false` - for filtering active or archived tiers

For browse requests, it’s also possible to use `limit`, `page`, and `order` parameters as documented in the [Content API](/content-api/#parameters).

By default, tiers are ordered by ascending monthly price amounts.


# Updating a Tier
Source: https://docs.ghost.org/admin-api/tiers/updating-a-tier



```js  theme={"dark"}
PUT /admin/tiers/{id}/
```

Required fields: `name`

Update all writable fields of a tier by using the edit endpoint. For example, rename a tier or set it as archived with this endpoint.

<RequestExample>
  ```json  theme={"dark"}
  // PUT /admin/tiers/{id}/
  {
      "tiers": [
          {
              "name": "Silver",
              "description": "silver"
          }
      ]
  }
  ```
</RequestExample>


# Deleting a user
Source: https://docs.ghost.org/admin-api/users/deleting-a-user



```js  theme={"dark"}
DELETE /admin/users/{id}/
```

This will delete the user. Note: You cannot delete the Owner user.


# Invites
Source: https://docs.ghost.org/admin-api/users/invites



The invites resource provides an endpoint for inviting staff users to the Ghost instance. To invite a user you must specify the ID of the role they should receive (fetch roles, detailed above, to find the role IDs for your site), and the email address that the invite link should be sent to.

<RequestExample>
  ```json  theme={"dark"}
  // POST /admin/invites/
  {
      "invites": [
          {
              "role_id": "64498c2a7c11e805e0b4ad4b",
              "email": "person@example.com"
          },
          ...
      ]
  }
  ```
</RequestExample>


# Overview
Source: https://docs.ghost.org/admin-api/users/overview



The users resource provides an endpoint for fetching and editing staff user data.

Fetch users (by default, the 15 newest staff users are returned):

```json  theme={"dark"}
// GET /admin/users/?include=count.posts%2Cpermissions%2Croles%2Croles.permissions
{
    "id": "1",
    "name": "Jamie Larson",
    "slug": "jamie",
    "email": "jamie@example.com",
    "profile_image": "http://localhost:2368/content/images/1970/01/jamie-profile.jpg",
    "cover_image": null,
    "bio": null,
    "website": null,
    "location": null,
    "facebook": null,
    "twitter": null,
    "accessibility": null,
    "status": "active",
    "meta_title": null,
    "meta_description": null,
    "tour": null,
    "last_seen": "1970-01-01T00:00:00.000Z",
    "comment_notifications": true,
    "free_member_signup_notification": true,
    "paid_subscription_started_notification": true,
    "paid_subscription_canceled_notification": false,
    "mention_notifications": true,
    "milestone_notifications": true,
    "created_at": "1970-01-01T00:00:00.000Z",
    "updated_at": "1970-01-01T00:00:00.000Z",
    "permissions": [],
    "roles": [{
        "id": "64498c2a7c11e805e0b4ad4f",
        "name": "Owner",
        "description": "Site Owner",
        "created_at": "1970-01-01T00:00:00.000Z",
        "updated_at": "1970-01-01T00:00:00.000Z",
        "permissions": []
    }],
    "count": {
        "posts": 1
    },
    "url": "http://localhost:2368/author/jamie/"
    },
        ...
    ]
}
```

Note that the Owner user does not have permissions assigned to it, or to the Owner role. This is because the Owner user has *all* permissions implicitly.


# Roles
Source: https://docs.ghost.org/admin-api/users/roles



The roles resource provides an endpoint for fetching role data.

<RequestExample>
  ```json  theme={"dark"}
  // GET /admin/roles/
  {
      "roles": [
          {
              "id": "64498c2a7c11e805e0b4ad4b",
              "name": "Administrator",
              "description": "Administrators",
              "created_at": "1920-01-01T00:00:00.000Z",
              "updated_at": "1920-01-01T00:00:00.000Z"
          },
          ...
      ]
  }
  ```
</RequestExample>


# Updating a user
Source: https://docs.ghost.org/admin-api/users/updating-a-user



```js  theme={"dark"}
PUT /admin/users/{id}/
```

All writable fields of a user can be updated. It’s recommended to perform a `GET` request to fetch the latest data before updating a user.

<RequestExample>
  ```json  theme={"dark"}
  // PUT /admin/users/{id}/
  {
      "users": [
          {
              "name": "Cameron Larson"
          }
      ]
  }
  ```
</RequestExample>


# Creating a Webhook
Source: https://docs.ghost.org/admin-api/webhooks/creating-a-webhook



```js  theme={"dark"}
POST /admin/webhooks/
```

Required fields: `event`, `target_url` Conditionally required field: `integration_id` - required if request is done using [user authentication](#user-authentication) Optional fields: `name`, `secret`, `api_version`

Example to create a webhook using [token authenticated](#token-authentication) request.

<RequestExample>
  ```json  theme={"dark"}
  // POST /admin/webhooks/
  {
      "webhooks": [{
              "event": "post.added",
              "target_url": "https://example.com/hook/"
      }]
  }
  ```
</RequestExample>

When creating a webhook through [user authenticated](#user-authentication) request, minimal payload would look like following:

```json  theme={"dark"}
// POST /admin/webhooks/
{
    "webhooks": [{
            "event": "post.added",
            "target_url": "https://example.com/hook/",
            "integration_id": "5c739b7c8a59a6c8ddc164a1"
    }]
}
```

and example response for both requests would be:

<ResponseExample>
  ```json  theme={"dark"}
  {
      "webhooks": [
          {
              "id": "5f04028cc9b839282b0eb5e3",
              "event": "post.added",
              "target_url": "https://example.com/hook/",
              "name": null,
              "secret": null,
              "api_version": "v6",
              "integration_id": "5c739b7c8a59a6c8ddc164a1",
              "status": "available",
              "last_triggered_at": null,
              "last_triggered_status": null,
              "last_triggered_error": null,
              "created_at": "2020-07-07T05:05:16.000Z",
              "updated_at": "2020-09-15T04:01:07.643Z"
          }
      ]
  }
  ```
</ResponseExample>


# Deleting a Webhook
Source: https://docs.ghost.org/admin-api/webhooks/deleting-a-webhook



```js  theme={"dark"}
DELETE /admin/webhooks/{id}/
```

Delete requests have no payload in the request or response. Successful deletes will return an empty 204 response.


# Overview
Source: https://docs.ghost.org/admin-api/webhooks/overview



Webhooks allow you to build or set up [custom integrations](https://ghost.org/integrations/custom-integrations/#api-webhook-integrations), which subscribe to certain events in Ghost. When one of such events is triggered, Ghost sends a HTTP POST payload to the webhook’s configured URL. For instance, when a new post is published Ghost can send a notification to configured endpoint to trigger a search index re-build, slack notification, or whole site deploy. For more information about webhooks read [this webhooks reference](/webhooks/).

```js  theme={"dark"}
POST /admin/webhooks/
PUT /admin/webhooks/{id}/
DELETE /admin/webhooks/{id}/
```

### The webhook object

Webhooks can be created, updated, and removed. There is no API to retrieve webhook resources independently.


# Updating a Webhook
Source: https://docs.ghost.org/admin-api/webhooks/updating-a-webhook



```js  theme={"dark"}
PUT /admin/webhooks/{id}/
```

All writable fields of a webhook can be updated via edit endpoint. These are following fields:

* `event` - one of [available events](/webhooks/#available-events)
* `target_url` - the target URL to notify when event happens
* `name` - custom name
* `api_version` - API version used when creating webhook payload for an API resource

<RequestExample>
  ```json  theme={"dark"}
  // PUT admin/webhooks/5f04028cc9b839282b0eb5e3
  {
      "webhooks": [{
              "event": "post.published.edited",
              "name": "webhook example"
      }]
  }
  ```
</RequestExample>

<ResponseExample>
  ```json  theme={"dark"}
  {
      "webhooks": [
          {
              "id": "5f04028cc9b839282b0eb5e3",
              "event": "post.published.edited",
              "target_url": "https://example.com/hook/",
              "name": "webhook example",
              "secret": null,
              "api_version": "v6",
              "integration_id": "5c739b7c8a59a6c8ddc164a1",
              "status": "available",
              "last_triggered_at": null,
              "last_triggered_status": null,
              "last_triggered_error": null,
              "created_at": "2020-07-07T05:05:16.000Z",
              "updated_at": "2020-09-15T04:05:07.643Z"
          }
      ]
  }
  ```
</ResponseExample>


# Architecture
Source: https://docs.ghost.org/architecture

Ghost is structured as a modern, decoupled web application with a sensible service-based architecture.

***

1. **A robust core JSON API**
2. **A beautiful admin client app**
3. **A simple, powerful front-end theme layer**

These three areas work together to make every Ghost site function smoothly, but because they’re decoupled there’s plenty of room for customisation.

***

### How things fit together

<Frame>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ghost-architecture.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f5fb386c78b639f48884a9c2c1247de7" data-og-width="2432" width="2432" data-og-height="1778" height="1778" data-path="images/ghost-architecture.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ghost-architecture.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1ec7be4c890965b982fd7503f759a0b7 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ghost-architecture.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=5f6904774eee6c302f483db481499450 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ghost-architecture.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=38a262f20c44302d387beb8b8dcfcb6c 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ghost-architecture.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=809744602549f4939ce7a322208d0333 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ghost-architecture.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=0edeaa570219df18f4a86000942b2b17 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ghost-architecture.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=620613b952c38f525e9c8e7abf8217d5 2500w" />
</Frame>

Physically, the Ghost codebase is structured in two main directories:

* `core` - Contains the core files which make up Ghost
* `content` - Contains the files which may be added or changed by the user such as themes and images

#### Data & Storage

Ghost ships with the [Bookshelf.js ORM](https://bookshelfjs.org/) layer by default allowing for a range of databases to be used. Currently SQLite3 is the supported default in development while MySQL is recommended for production. Other databases are available, and compatible, but not supported by the core team.

Additionally, while Ghost uses local file storage by default it’s also possible to use custom storage adapters to make your filesystem completely external. There are fairly wide range of pre-made [storage adapters for Ghost](https://ghost.org/integrations/?tag=storage) already available for use.

#### Ghost-CLI

Orchestrating these different components is done via a comprehensive CLI and set of utilities to keep everything running and up to date.

#### Philosophy

Ghost is architected to be familiar and easy to work with for teams who are already used to working with JavaScript based codebases, whilst still being accessible to a broad audience. It’s neither the most bleeding-edge structure in the world, nor the most simple, but strives to be right balance between the two.

<Note>
  You can help build the future. Ghost is currently hiring Product Engineers - check out what it’s like to be part of the team and see our open roles at [careers.ghost.org](https://careers.ghost.org/)
</Note>

***

## Ghost Core

At its heart, Ghost is a RESTful JSON API — designed to create, manage and retrieve publication content with ease.

Ghost’s API is split by function into two parts: Content and Admin. Each has its own authentication methods, structure and extensive tooling so that common publication usecases are solved with minimal effort.

Whether you want to publish content from your favourite desktop editor, build a custom interface for handling editorial workflow, share your most recent posts on your marketing site, or use Ghost as a full headless CMS, Ghost has the tools to support you.

### Content API

Ghost’s public Content API is what delivers published content to the world and can be accessed in a read-only manner by any client to render in a website, app or other embedded media.

Access control is managed via an API key, and even the most complex filters are made simple with our [query language](/content-api/#filtering). The Content API is designed to be fully cachable, meaning you can fetch data as often as you like without limitation.

### Admin API

Managing content is done via Ghost’s Admin API, which has both read and write access used to create and update content.

The Admin API provides secure role-based authentication so that you can publish from anywhere with confidence, either as a staff user via session authentication or via an integration with a third-party service.

When authenticated with the **admin** or **owner** role, the Admin API provides full control for creating, editing and deleting all data in your publication, giving you even more power and flexibility than the standard Ghost admin client.

### JavaScript SDK

Ghost core comes with an accompanying JavaScript [API Client](/content-api/javascript/) and [SDK](/content-api/javascript/#javascript-sdk) designed to remove pain around authentication and data access.

It provides tools for working with API data to accomplish common use cases such as returning a list of tags for a post, rendering meta data in the `<head>`, and outputting data with sensible fallbacks.

Leveraging FLOSS & npm, an ever-increasing amount of Ghost’s JavaScript tooling has been made available. If you’re working in JavaScript, chances are you won’t need to code anything more than wiring.

### Webhooks

Notify an external service when content has changed or been updated by calling a configured HTTP endpoint. This makes it a breeze to do things like trigger a rebuild in a static site generator, or notify Slack that something happened.

By combining Webhooks and the API it is possible to integrate into any aspect of your content lifecycle, to enable a wide range of content distribution and workflow automation use cases.

### Versioning

Ghost ships with a mature set of core APIs, with only minimal changes between major versions. We maintain a [stability index](/faq/api-versioning/) so that you can be sure about depending on them in production.

Ghost major versions ship every 8-12 months, meaning code you write against our API today will be stable for a minimum of 2 years.

***

## Admin Client

A streamlined clientside admin interface for editors who need a powerful tool to manage their content.

Traditionally, people writing content and people writing code rarely agree on the best platform to use. Tools with great editors generally lack speed and extensibility, and speedy frameworks basically always sacrifice user experience.

### Overview

Thanks to its decoupled architecture Ghost is able to have the best of both worlds. Ghost-Admin is a completely independent client application to the Ghost Core API which doesn’t have any impact on performance. And, writers don’t need to suffer their way through learning Git just to publish a new post.

Great for editors. Great for developers.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/admin.png?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7a27f5a44193050f8b1d061eef4f12e8" data-og-width="2152" width="2152" data-og-height="1428" height="1428" data-path="images/admin.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/admin.png?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=c7896a777550634a042809180f373497 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/admin.png?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e0bf4e065b17c7af3957993f97957bab 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/admin.png?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=dc796b5760ececfd6db3601698a24511 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/admin.png?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=82db69c2c88c4d918e62701bd4519cc3 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/admin.png?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=badc200bdb25fcf55fd704c50b3a362d 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/admin.png?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=960fcbf04b98c493368e719e1b15d52c 2500w" />
</Frame>

### Publishing workflow

Hacking together some Markdown files and throwing a static-site generator on top is nice in theory, but anyone who has tried to manage a content archive knows how quickly this falls apart even under light usage. What happens when you want to schedule a post to be published on Monday?

<Frame>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/publish.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f044f032c8b5ad2d0c30196abe6a4fd4" data-og-width="1772" width="1772" data-og-height="1162" height="1162" data-path="images/publish.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/publish.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=3bc170b2f38543824e9e324dea3f37b1 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/publish.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f8040707eb8045056929584ac2748cc4 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/publish.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=2b0ad3e6775069ebac7ea17f362ebd5d 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/publish.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=57eafefc3c6a89cc6e55751fa1f8b2eb 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/publish.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=d99a171f61eac331dbf22b2ed6f223ca 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/publish.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=50e12d676b34416e8be796515f2cd8fb 2500w" />
</Frame>

Great editorial teams need proper tools which help them be effective, which is why Ghost-Admin has all the standard editorial workflow features available at the click of a button. From inputting custom social and SEO data to customising exactly how and where content will be output.

### Best-in-class editor

Ghost Admin also comes with a world-class editor for authoring posts, which is directly tied to a rock-solid document storage format. More on that a bit later!

<Frame>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/editor.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=cabbe0890ca7470557d89cf0945faacb" data-og-width="1772" width="1772" data-og-height="1162" height="1162" data-path="images/editor.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/editor.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=27747bb5e53833c74645cbc080a9c11e 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/editor.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9b9083f0eeda131b84abca0b8b1e6df1 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/editor.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=46263057054d57c64167f6731009c77c 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/editor.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=0119f341d57c1478377c4609374f025a 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/editor.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=d179a69ce95cf4532e706364e660d2e3 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/editor.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=5e573c0f2cbeccd833df48cd7d9bd4ca 2500w" />
</Frame>

But, our default client app isn’t the only way to interact with content on the Ghost [Admin API](/admin-api/). You can send data into Ghost from pretty much anywhere, or even write your own custom admin client if you have a particular usecase which requires it.

Ghost-Admin is extremely powerful but entirely optional.

***

## Front-end

Ghost is a full headless CMS which is completely agnostic of any particular front end or static site framework.

Just like Ghost’s admin client, its front-end is both optional and interchangeable. While Ghost’s early architecture represented more of a standard monolithic web-app, it’s now compatible with just about any front-end you can throw at it.

It doesn’t even have to be a website!

### Handlebars Themes

Ghost ships with its own [Handlebars.js](/themes/) theme layer served by an Express.js webserver, so out of the box it automatically comes with a default front-end. This is a really fast way to get a site up and running, and despite being relatively simple Handlebars is both powerful and extremely performant.

Ghost Handlebars Themes have the additional benefit of being fairly widely adopted since the platform first launched back in 2013, so there’s a broad [third party marketplace](https://ghost.org/marketplace/) of pre-built themes as well as [extensive documentation](/themes/) on how to build a custom theme.

### Static Site Generators

Thanks to its decoupled architecture Ghost is also compatible with just about any of the front-end frameworks or static site generators which have become increasingly popular thanks to being fun to work with, extremely fast, and more and more powerful as the JAMstack grows in maturity. So it works with the tools you already use.

This very documentation site is running on a [Gatsby.js](/jamstack/gatsby/) front-end, connected to both **Ghost** and **GitHub** as content sources, hosted statically on [Netlify](https://netlify.com) with dynamic serverless functions powered by [AWS Lambda](https://aws.amazon.com/lambda/) (like the feedback form at the bottom of this page). It’s a brave new world!

We’re working on greatly expanding our range of documentation, tools and SDKs to better serve the wider front-end development community.

### Custom front-ends

Of course you can also just build your own completely custom front-end, too. Particularly if you’re using the Ghost API as a service to drive content infrastructure for a mobile or native application which isn’t based on the web.


# Breaking Changes
Source: https://docs.ghost.org/changes

A catalog of critical changes between major Ghost versions

***

New major versions typically involve some backwards incompatible changes. These mostly affect custom themes and the API. Our theme compatibility tool [GScan](/themes/gscan/) will guide you through any theme updates. If you use custom integrations, the APIs, webhooks or Ghost in headless mode you should review the breaking changes list carefully before updating.

#### How to update?

The [update guide](/update/) explains how to update from Ghost 1.0 or higher to the **latest version**. Ghost(Pro) customers should use the [update guide for Ghost (Pro)](https://ghost.org/help/how-to-upgrade-ghost/).

#### When to update?

The best time to do a [major version](/faq/major-versions-lts) update is shortly after the first minor version - so for Ghost 6.x, the best time to update will be when 6.1.0 is released, which is usually a week or two after the first 6.x release.

This is when any bugs or unexpected compatibility issues have been resolved but the [team & community](https://forum.ghost.org) are still context loaded about the changes. The longer you hold off, the bigger the gap becomes between the software you are using and the latest version.

## Ghost 6.0

Most changes in Ghost 6.0 are non-breaking cleanup, with the most notable exception being the removal of `?limit=all` support from all API endpoints.

#### Return max 100 results from APIs (removing `?limit=all` support)

Providing for requesting all data from an endpoint by setting the `limit` parameter to `"all"` has been a useful feature for many tools and integrations.
However, on larger sites it can cause performance and stability issues. Therefore we've removed this feature and added a max page size of 100, in line with other similar platforms.

Requesting `?limit=all` from any API endpoint will not error, but instead will return a maximum of 100 items. Attempting to request more than 100 items will also fall back to returning a maximum of 100 items.

To fetch more than 100 items, pagination should be used, being mindful to build in small delays so as not to trigger any rate limits or fair usage policies of your hosts.

If you're using Ghost as a headless CMS, have custom integrations, or an advanced custom theme please be sure to change these to handle pagination before updating to Ghost 6.0.

#### Supported Node versions

* Ghost 6.0 is only compatible with Node.js v22
* Support for both Node.js v18 (EOL) and Node.js v20 have been dropped

#### Supported databases

**MySQL 8** remains the only supported database for both development and production environments.

* SQLite3 is supported only in development environments. With Node.js v22, sqlite3 requires python setup tools to install correctly.

#### Miscellaneous Changes

* Feature: Removed AMP - [Google no longer prioritizes AMP](https://developers.google.com/search/blog/2021/04/more-details-page-experience). Ghost's AMP feature has been deprecated for some time, and is completely removed in Ghost 6.0.
* Database: Removed `created_by` & `updated_by` from all tables - these properties were unused and are now deleted. Use the `actions` table instead.
* Database: Cleaned up users without an ObjectID - a very old holdover from incremental IDs prior to Ghost 1.0 was that owner users were still created with ID 1. This has been fixed and cleaned up. This update may take a while on larger sites.
* Admin API: Removed `GET /ghost/api/admin/session/` endpoint - this was an unused endpoint that has been cleaned up. Use `GET /ghost/api/admin/users/me/` instead.
* Themes: Stopped serving files without an extension from theme root - the behaviour of serving files from themes has changed slightly. Assets will now correctly 404 if missing. Files without an extension will not be served at all.

## Ghost 5.0

Ghost 5.0 includes significant changes to the Ghost API and database support to ensure optimal performance.

### Mobiledoc deprecation

With the release of the [new editor](https://ghost.org/changelog/editor-beta/), Ghost uses [Lexical](https://lexical.dev/) to store post content, which replaces the previous format Mobiledoc. Transitioning to Lexical enables Ghost to build new powerful features that weren’t possible with Mobiledoc. To remain compatible with Ghost, integrations that rely on Mobiledoc should switch to using Lexical. [For more resources on working with Lexical, see their docs](https://lexical.dev/docs/intro).

#### Supported databases

**MySQL 8** is the only supported database for both development and production environments.

* SQLite3 is supported only in development environments where scalability and data consistency across updates is not critical (during local theme development, for example)
* MySQL 5 is no longer supported in any environment

Note: MariaDB is not an officially supported database for Ghost.

#### Portal

If you’re embedding portal on an external site, you’ll need to update your script tag.

You can generate a Content API key and check your API url in the Custom Integration section in Ghost Admin. For more information see the [Content API docs](/content-api/).

```html  theme={"dark"}
<script defer src="https://unpkg.com/@tryghost/portal@latest/umd/portal.min.js" data-ghost="{site_url}" data-api="{api_url}/ghost/api/content/" data-key="{content_api_key}"></script>
```

#### Themes

Themes can be validated against 5.x in [GScan](https://gscan.ghost.org).

* Card assets will now be included by default, including bookmark and gallery cards. ([docs](/themes/helpers/data/config/))
* Previously deprecated features have been removed: `@blog`, single authors.

**Custom membership flows**

The syntax used to build custom membership flows has changed significantly.

* Tier benefits are now returned as a list of strings. ([docs](/themes/helpers/data/tiers/#fetching-tiers-with-the-get-helper))
* Paid Tiers now have numeric `monthly_price` and `yearly_price` attributes, and a separate `currency` attribute. ([docs](/themes/helpers/data/tiers/))
* The following legacy product and price helpers used to build custom membership flows have been removed: `@price`, `@products`, `@product` and `@member.product`. See below for examples of the new syntax for building a custom signup form and account page. ([docs](/themes/members/#member-subscriptions))

**Sign up form**

```handlebars  theme={"dark"}
{{! Fetch all available tiers }}
{{#get "tiers" include="monthly_price,yearly_price,benefits" limit="100"}}
  {{#foreach tiers}}
    <div>
      <h2>{{name}}</h2> {{! Output tier name }}
      <p>{{description}}<p> {{! Output tier description }}

      {{#if monthly_price}} {{! If tier has a monthly price, generate a Stripe sign up link }}
        <a href="javascript:" data-portal="signup/{{id}}/monthly">Monthly –
            {{price monthly_price currency=currency}}</a>
       {{/if}}
       {{#if yearly_price}} {{! If tier has a yearly price, generate a Stripe sign up link }}
        <a href="javascript:" data-portal="signup/{{id}}/monthly">Monthly –
            {{price yearly_price currency=currency}}</a>
       {{/if}}

       <ul>
       {{#foreach benefits as |benefit| }} {{! Output list of benefits }}
         <li>{{benefit}}</li>
       {{/foreach}}
       </ul>
    </div>
  {{/foreach}}
{{/get}}
```

**Account page**

```handlebars  theme={"dark"}
<h2>{{@member.name}}</h2>
<p>{{@member.email}}</p>
    {{#foreach @member.subscriptions}}
    <p>Tier name: <strong>{{tier.name}}</strong></p>
    <p>Subscription status: <strong>{{status}}</strong></p>
    <p>Amount: {{price plan numberFormat="long"}}/{{plan.interval}}</p>
    <p>Start date: {{date start_date}}</p>
    <p>End date: {{date current_period_end}}</p>
    {{cancel_link}} {{! Generate a link to cancel the membership }}
    {{/foreach}}
</div>
```

#### API versioning

Ghost 5.0 no longer includes multiple API versions for backwards compatibility with previous versions. The URLs for the APIs are now `ghost/api/content` and `ghost/api/admin`. Breaking changes will continue to be made only in major versions; new features and additions may be added in minor version updates.

Backwards compatibility is now provided by sending an `accept-version` header with API requests specifying the compatibility version a client expects. When this header is present in a request, Ghost will respond with a `content-version` header indicating the version that responded. In the case that the provided `accept-version` is below the minimum version supported by Ghost and a request either cannot be served or has changed significantly, Ghost will notify the site’s administrators via email informing them of the problem.

Requests to the old, versioned URLs are rewritten internally with the relevant `accept-version` header set. These requests will return a `deprecation` header.

#### Admin API changes

* The `/posts` and `/pages` endpoints no longer accept `page:(true|false)` as a filter in the query parameters
* The `email_recipient_filter` and `send_email_when_published` parameters have been removed from the `/posts` endpoint, and email sending is now controlled by the new `newsletter` and `email_segment` parameters
* The `/mail` endpoint has been removed
* The `/email_preview` endpoint has been renamed to `/email_previews`
* The `/authentication/reset_all_passwords` endpoint has been renamed to `/authentication/global_password_reset` and returns a `204 No Content` response on success
* The `/authentication/passwordreset` endpoint has been renamed to `/authentication/password_reset`, and accepts and returns a `password_reset` object
* The `DELETE /settings/stripe/connect` endpoint now returns a `204 No Content` response on success
* The `POST /settings/members/email` endpoint now returns a `204 No Content` response on success

#### Content API changes

* The `GET /posts` and `GET /pages` endpoints no longer return the `page:(true|false)` attribute in the response

#### Members

* The `members/api/site` and `members/api/offers` endpoints have been removed, and Portal now uses the Content API
* All `/products/*` endpoints have been replaced with `/tiers/*`, and all references to `products` in requests/responses have been updated to use `tiers`
* Tier benefits are now returned as a list of strings
* Paid Tiers now have numeric `monthly_price` and `yearly_price` attributes, and a separate `currency` attribute
* The member `subscribed` flag has been deprecated in favor of the `newsletters` relation, which includes the newsletters a member is subscribed to

#### Miscellaneous Changes

* Removed support for serving secure requests when `config.url` is set to `http`
* Removed support for configuring the server to connect to a socket instead of a port
* Deleting a user will no longer remove their posts, but assign them to the site owner instead
* Site-level email design settings have been replaced with design settings on individual newsletters (see [`/newsletters/* endpoints`](/admin-api/#newsletters))

## Ghost 4.0

Ghost 4.0 focuses on bringing Memberships out of beta. There are a few additional changes:

* New `/v4/` (stable) and `/canary/` (experimental) API versions have been added.
* The `/v3/` (maintenance) endpoints will not receive any further changes.
* The `/v2/` (deprecated) endpoints will be removed in the next major version.
* v4 Admin API `/settings/` endpoint no longer supports the `?type` query parameter.
* v4 Admin API `/settings/` endpoint only accepts boolean values for the key `unsplash`.
* Redirects: definitions should now be uploaded in YAML format - `redirects.json` has been deprecated in favour of `redirects.yaml`.
* Themes: **must** now define which version of the API they want to use by adding `"engines": {"ghost-api": "vX"}}` to the `package.json` file.
* Themes: due to content images having `width` / `height` attributes, themes with CSS that use `max-width` may need to add `height: auto` to prevent images appearing squashed or stretched.
* Themes: The default format for the `{{date}}` helper is now a localised short date string (`ll`).
* Themes: `@site.lang` has been deprecated in favour of `@site.locale`.
* Private mode: the cookie has been renamed from `express:sess` to `ghost-private`.
* Other: It’s no longer possible to require or use Ghost as an NPM module.

### Members

Members functionality is no longer considered beta and is always enabled. The following are breaking changes from the behaviour in Ghost 3.x:

* v3/v4 Admin API `/members/` endpoint no longer supports the `?paid` query parameter
* v3/v4 Admin API `/members/` endpoints now have subscriptions on the `subscriptions` key, rather than `stripe.subscriptions`.
* v3/v4 Admin API `/posts/` endpoint has deprecated the `send_email_when_published` flag in favour of `email_recipient_filter`.
* Themes: The `@labs.members` theme helper always returns `true`, and will be removed in the next major version.
* Themes: The default post visibility in `foreach` in themes is now `all`.
* Themes: The `default_payment_card_last4` property of member subscriptions now returns `****` instead of `null` if the data is unavailable.
* Portal: query parameters no longer use `portal-` prefixes.
* Portal: the root container has been renamed from `ghost-membersjs-root` to `ghost-portal-root`.
* Other: Stripe keys are no longer included in exports.
* Other: Using Stripe related features in a local development environment requires `WEBHOOK_SECRET`, and live stripe keys are no longer supported in non-production environments.

## Ghost 3.0

* The Subscribers labs feature has been replaced with the [Members](/members/) labs feature.
* The v0.1 API endpoints & Public API Beta have been removed. Ghost now has a set of fully supported [Core APIs](/architecture/).
* The Apps beta concept has been removed. Use the Core APIs & [integrations](https://ghost.org/integrations/) instead.
* Themes using [GhostHunter](https://github.com/jamalneufeld/ghostHunter) must upgrade to [GhostHunter 0.6.0](https://github.com/jamalneufeld/ghostHunter#ghosthunter-v060).
* Themes using `ghost.url.api()` must upgrade to the [Content API client library](/content-api/javascript/).
* Themes may be missing CSS for editor cards added in 2.x. Use [GScan](https://gscan.ghost.org/) to make sure your theme is fully 3.0 compatible.
* Themes must replace `{{author}}` for either `{{#primary_author}}` or `{{authors}}`.
* New `/v3/` (stable) and `/canary/` (experimental) API versions have been added.
* The `/v2/` (maintenance) endpoints will not receive any further changes.
* v3 Content API `/posts/` & `/pages/` don’t return `primary_tag` or `primary_author` when `?include=tags,authors` isn’t specified (these were returned as null previously).
* v3 Content API `/posts/` & `/pages/` no longer return page: `true|false`.
* v3 Content + Admin API `/settings/` no longer returns ghost\_head or `ghost_foot`, use `codeinjection_head` and `codeinjection_foot` instead.
* v3 Admin API `/subscribers/*` endpoints are removed and replaced with `/members/*`.
* v3 Content + Admin API consistently stores relative and serves absolute URLs for all images and links, including inside content & srcsets.

### Switching from v0.1 API

* The Core APIs are stable, with both read & write access fully supported.
* v0.1 Public API (read only access) is replaced by the [Content API](/content-api/).
* v0.1 Private API (write access) is replaced by the [Admin API](/admin-api/).
* v0.1 Public API `client_id` and `client_secret` are replaced with a single `key`, found by configuring a new Custom Integration in Ghost Admin.
* v0.1 Public API `ghost-sdk.min.js` and `ghost.url.api()` are replaced with the `@tryghost/content-api` [client library](/content-api/javascript/).
* v0.1 Private API client auth is replaced with JWT auth & user auth now uses a session cookie. The `@tryghost/admin-api` [client library](/admin-api/javascript/) supports easily creating content via JWT auth.
* Scripts need updating to handle API changes, e.g. posts and pages being served on separate endpoints and users being called authors in the Content API.

## Ghost 2.0

* API: The `/v2/` API replaces the deprecated `/v0.1/` API.
* Themes: The editor has gained many new features in 2.x, you may need to add CSS to your theme for certain cards to display correctly.
* Themes: `{{#get "users"}}` should be replaced with `{{#get "authors"}}`
* Themes: multiple authors are now supported, swap uses of author for either `{{#primary_author}}` or `{{authors}}`.
* Themes: can now define which version of the API they want to use by adding `"engines": {"ghost-api": "vX"}}` to the `package.json` file.
* Themes: there are many minor deprecations and warnings, e.g. `@blog` has been renamed to `@site`, use [GScan](https://gscan.ghost.org) to make sure your theme is fully 2.0 compatible.
* v2 Content+Admin API has split `/posts/` & `/pages/` endpoints, instead of just `/posts/`.
* v2 Content API has an `/authors/` endpoint instead of `/users/`.
* v2 Admin API `/posts/` and `/pages/` automatically include tags and authors without needing `?includes=`.
* v2 Content + Admin API attempts to always save relative & serve absolute urls for images and links, but this behaviour is inconsistent 🐛.

## Ghost 1.0

* This is a major upgrade, with breaking changes and no automatic migration path. All publications upgrading from Ghost 0.x versions must be [upgraded](/faq/update-0x/) to Ghost 1.0 before they can be successfully upgraded to Ghost 2.0 and beyond.
* See [announcement post](https://ghost.org/changelog/1-0/) and [developer details](https://ghost.org/changelog/ghost-1-0-0/) for full information on what we changed in 1.0.
* v0.1 Public API `/shared/ghost-url.min.js` util has been moved and renamed to `/public/ghost-sdk.min.js`
* Ghost 0.11.x exports don’t include `clients` and `trusted_domains` so these aren’t imported to your new site - you’ll need to update any scripts with a new `client_id` and `client_secret` from your 1.0 install.
* Themes: Many image fields were renamed, use [GScan](https://gscan.ghost.org) to make sure your theme is 1.0 compatible.


# Configuration
Source: https://docs.ghost.org/config

For self-hosted Ghost users, a custom configuration file can be used to override Ghost’s default behaviour. This provides you with a range of options to configure your publication to suit your needs.

***

## Overview

When you install Ghost using the supported and recommended method using `ghost-cli`, a custom configuration file is created for you by default. There are some configuration options which are required by default, and many optional configurations.

The three required options are `url` and `database` which are configured during setup, and `mail` which needs to be configured once you’ve installed Ghost.

This article explains how to setup your mail config, as well as walk you through all of the available config options.

## Custom configuration files

The configuration is managed by [nconf](https://github.com/indexzero/nconf/). A custom configuration file must be a valid JSON file located in the root folder and changes to the file can be implemented using `ghost restart`.

Since Node.js has the concept of environments built in, Ghost supports two environments: **development** and **production**. All public Ghost publications run in production mode, while development mode can be used to test or build on top of Ghost locally.

<Note>
  Check out the official install guides for [development](/install/local/) and [production](/install/ubuntu/).
</Note>

The configuration files reflect the environment you are using:

* `config.development.json`
* `config.production.json`

#### Ghost in development

If you would like to start Ghost in development, you don’t have to specify any environment, because development is default. To test Ghost in production, you can use:

```bash  theme={"dark"}
NODE_ENV=production node index.js
```

If you want to make changes when developing and working on Ghost, you can create a special configuration file that will be ignored in git:

* `config.local.json`

This file is merged on top of `config.development.json` so you can use both at the same time.

#### Debugging the configuration output

Start Ghost with:

```bash  theme={"dark"}
DEBUG=ghost:*,ghost-config node index.js
```

#### Running Ghost with config env variables

> ALL configuration options are overridable with environment variables!
> Values set through env vars take priority over data in configuration files

Start Ghost using environment variables which match the name and case of each config option:

```bash  theme={"dark"}
url=http://ghost.local:2368 node index.js
```

For nested config options, separate with two underscores:

```bash  theme={"dark"}
database__connection__host=mysql node index.js
```

If you want to set a var of list type:

```bash  theme={"dark"}
logging__transports='["stdout","file"]' node index.js
```

## Configuration options

There are a number of configuration options which are explained in detail in this article. Below is an index of all configuration options:

| Name                | Required?     | Description                                                                                                                      |
| ------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `url`               | In production | Set the public URL for your blog                                                                                                 |
| `database`          | In production | Type of database used (default: MySQL)                                                                                           |
| `mail`              | In production | Add a mail service                                                                                                               |
| `admin`             | Optional      | Set the protocol and hostname for your admin panel                                                                               |
| `server`            | Optional      | Host and port for Ghost to listen on                                                                                             |
| `privacy`           | Optional      | Disable features set in [privacy.md](https://github.com/TryGhost/Ghost/blob/2f09dd888024f143d28a0d81bede1b53a6db9557/PRIVACY.md) |
| `security`          | Optional      | Disable security features that are enabled by default                                                                            |
| `paths`             | Optional      | Customise internal paths                                                                                                         |
| `referrerPolicy`    | Optional      | Control the content attribute of the meta referrer tag                                                                           |
| `useMinFiles`       | Optional      | Generate assets URL with .min notation                                                                                           |
| `storage`           | Optional      | Set a custom storage adapter                                                                                                     |
| `scheduling`        | Optional      | Set a custom scheduling adapter                                                                                                  |
| `logging`           | Optional      | Configure logging for Ghost                                                                                                      |
| `spam`              | Optional      | Configure spam settings                                                                                                          |
| `caching`           | Optional      | Configure HTTP caching settings                                                                                                  |
| `compress`          | Optional      | Disable compression of server responses                                                                                          |
| `imageOptimization` | Optional      | Configure image manipulation and processing                                                                                      |
| `opensea`           | Optional      | Increase rate limit for fetching NFT embeds from OpenSea.io                                                                      |
| `tenor`             | Optional      | Enable integration with Tenor.com for embedding GIFs directly from the editor                                                    |
| `twitter`           | Optional      | Add support for rich Twitter embeds in newsletters                                                                               |
| `portal`            | Optional      | Relocate or remove the scripts for Portal                                                                                        |
| `sodoSearch`        | Optional      | Relocate or remove the scripts for Sodo search                                                                                   |
| `comments`          | Optional      | Relocate or remove the scripts for comments                                                                                      |

### URL

*(Required in production)*

Once a Ghost publication is installed, the first thing to do is set a URL. When installing using `ghost-cli`, the install process requests the URL during the setup process.

Enter the URL that is used to access your publication. If using a subpath, enter the full path, `https://example.com/blog/`. If using SSL, always enter the URL with `https://`.

#### SSL

We always recommend using SSL to run your Ghost publication in production. Ghost has a number of configuration options for working with SSL, and securing the URLs for the admin `/ghost/` and the frontend of your publication. Without SSL your username and password are sent in plaintext.

`ghost-cli` prompts to set up SSL during the installation process. After a successful SSL setup, you can find your SSL certificate in `/etc/letsencrypt`.

If you see errors such as `access denied from url`, then the provided URL in your config file is incorrect and needs to be updated.

### Database

*(Required in production)*

Ghost is configured using MySQL by default:

```json  theme={"dark"}
"database": {
  "client": "mysql",
  "connection": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "your_database_user",
    "password": "your_database_password",
    "database": "your_database_name"
  }
}
```

Alternatively, you can configure sqlite3:

```json  theme={"dark"}
"database": {
  "client": "sqlite3",
  "connection": {
    "filename": "content/data/ghost-test.db"
  },
  "useNullAsDefault": true,
  "debug": false
}
```

#### Number of connections

It’s possible to limit the number of simultaneous connections using the pool setting. The default values are a minimum of 2 and a maximum of 10, which means Ghost always maintains two active database connections. You can set the minimum to 0 to prevent this:

```json  theme={"dark"}
"database": {
  "client": ...,
  "connection": { ... },
  "pool": {
    "min": 2,
    "max": 20
  }
}
```

#### SSL

In a typical Ghost installation, the MySQL database will be on the same server as Ghost itself. With cloud computing and database-as-a-service providers you might want to enable SSL connections to the database.

For Amazon RDS you’ll need to configure the connection with `"ssl": "Amazon RDS"`:

```json  theme={"dark"}
"database": {
  "client": "mysql",
  "connection": {
    "host": "your_cloud_database",
    "port": 3306,
    "user": "your_database_user",
    "password": "your_database_password",
    "database": "your_database_name",
    "ssl": "Amazon RDS"
  }
}
```

For other hosts, you’ll need to output your CA certificate (not your CA private key) as a single line string including literal new line characters `\n` (you can get the single line string with `awk '{printf "%s\\n", $0}' CustomRootCA.crt`) and add it to the configuration:

```json  theme={"dark"}
"database": {
  "client": "mysql",
  "connection": {
    "host": "your_cloud_database",
    "port": 3306,
    "user": "your_database_user",
    "password": "your_database_password",
    "database": "your_database_name",
    "ssl": {
      "ca": "-----BEGIN CERTIFICATE-----\nMIIFY... truncated ...pq8fa/a\n-----END CERTIFICATE-----\n"
    }
  }
}
```

For a certificate chain, include all CA certificates in the single line string:

```json  theme={"dark"}
"database": {
  "client": "mysql",
  "connection": {
    "host": "your_cloud_database",
    "port": 3306,
    "user": "your_database_user",
    "password": "your_database_password",
    "database": "your_database_name",
    "ssl": {
      "ca": "-----BEGIN CERTIFICATE-----\nMIIFY... truncated ...pq8fa/a\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFY... truncated ...wn8v90/a\n-----END CERTIFICATE-----\n"
    }
  }
}
```

### Mail

*(Required in production)*

The most important piece of configuration once the installation is complete is to set up mail. Configuring mail allows Ghost to send transactional emails such as user invitations, password resets, member signups, and member login links. With the help of a bulk email service, you can also configure Ghost to send newsletters to members.

Ghost uses [Nodemailer](https://github.com/nodemailer/nodemailer/) under the hood, and tries to use the direct mail service if available.

We recommend ensuring transactional emails are functional before moving on to bulk mail configuration.

#### Configuring with Mailgun

[Mailgun](https://www.mailgun.com/) is a service for sending emails and provides more than adequate resources to send bulk emails at a reasonable price. Find out more about [using Mailgun with Ghost here](/faq/mailgun-newsletters/).

Mailgun allows you to use your own domain for sending transactional emails. Otherwise, you can use a subdomain that Mailgun provides you with (also known as the sandbox domain, limited to 300 emails per day). You can change this at any time.

Mailgun is an optional service for sending transactional emails, but it is required for bulk mail — [read more](/faq/mailgun-newsletters/).

#### Create a Mailgun account

Once your site is fully set up [create a Mailgun account](https://signup.mailgun.com/). After your account is verified navigate to **Domain settings** under **Sending** in the Mailgun admin. There you’ll find your SMTP credentials.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0c2ceac3-mailgun-smtp_hub94c62b257175129863d85e1a9325a52_48235_866x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8f1aac5beb8ab4f262741b55f65e1af2" data-og-width="866" width="866" data-og-height="604" height="604" data-path="images/0c2ceac3-mailgun-smtp_hub94c62b257175129863d85e1a9325a52_48235_866x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0c2ceac3-mailgun-smtp_hub94c62b257175129863d85e1a9325a52_48235_866x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a2acd77b76088ac1bf891950dc188241 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0c2ceac3-mailgun-smtp_hub94c62b257175129863d85e1a9325a52_48235_866x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7134b675c98f669a3f49787d13f0bd78 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0c2ceac3-mailgun-smtp_hub94c62b257175129863d85e1a9325a52_48235_866x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=b07a63b4bc2c60bcd4c60c5687bc0a10 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0c2ceac3-mailgun-smtp_hub94c62b257175129863d85e1a9325a52_48235_866x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7698bc5149b8cbba992c4d890ed91181 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0c2ceac3-mailgun-smtp_hub94c62b257175129863d85e1a9325a52_48235_866x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=dbc238b4794359342871139ea845924e 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0c2ceac3-mailgun-smtp_hub94c62b257175129863d85e1a9325a52_48235_866x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7a8e405548a24da806728e55564e9744 2500w" />
</Frame>

In addition to this information, you’ll need the password, which can be obtained by clicking the **Reset Password** button. Keep these details for future reference.

Mailgun provides options for using their own subdomains for sending emails, as well as custom domains for a [competitive price](/faq/mailgun-newsletters/#did-you-know-mailgun-doesn-t-have-free-accounts-anymore).

#### Add credentials to `config.production.json`

Open your production config file in any code editor and add the following mail configuration, making sure to update the values to the same credentials shown in your own Mailgun SMTP settings:

```json  theme={"dark"}
// config.production.json

"mail": {
  "transport": "SMTP",
  "options": {
    "service": "Mailgun",
    "auth": {
      "user": "postmaster@example.mailgun.org",
      "pass": "1234567890"
    }
  }
},
```

Once you are finished, hit save and then run `ghost restart` for your changes to take effect. These same credentials can be used for development environments, by adding them to the `config.development.json` file.

Mailgun provides a sandbox mode, which restricts emails to authorized recipients. Once sandbox mode is enabled, add and verify the email addresses you want to send emails to prior to testing.

#### Secure connection

Depending on your Mailgun settings you may want to force a secure SMTP connection. Update your `config.production.json` with the following for a secure connection:

```json  theme={"dark"}
// config.production.json

"mail": {
  "transport": "SMTP",
  "options": {
    "service": "Mailgun",
    "host": "smtp.mailgun.org",
    "port": 465,
    "secure": true,
    "auth": {
      "user": "postmaster@example.mailgun.org",
      "pass": "1234567890"
    }
  }
},
```

As always, hit save and run `ghost restart` for your changes to take effect.

#### Amazon SES

It’s also possible to use [Amazon Simple Email Service](https://aws.amazon.com/ses/). Use the SMTP username and password given when signing up and configure your `config.[env].json` file as follows:

```json  theme={"dark"}
"mail": {
    "transport": "SMTP",
    "options": {
        "host": "YOUR-SES-SERVER-NAME",
        "port": 465,
        "service": "SES",
        "auth": {
            "user": "YOUR-SES-SMTP-ACCESS-KEY-ID",
            "pass": "YOUR-SES-SMTP-SECRET-ACCESS-KEY"
        }
    }
}
```

#### Email addresses

**Default email address**

Ghost uses the value set in `mail.from` as the default email address:

```json  theme={"dark"}
"mail": {
    "from": "support@example.com",
}
```

A custom name can also optionally be provided:

```json  theme={"dark"}
"mail": {
    "from": "'Acme Support' <support@example.com>",
}
```

Try to use a real, working email address - as this greatly improves delivery rates for important emails sent by Ghost (Like password reset requests and user invitations). If you have a company support email address, this is a good place to use it.

**Support email address**

When setting a custom support email address via **Settings** → **Portal settings** → **Account page**, you override the default email address for member communications like sign-in/sign-up emails and member notifications.

**Newsletter addresses**

It’s also possible to set a separate sender and reply-to address per newsletter, which will be used instead of the default. Configure these addresses via **Settings** → **Newsletters**.

The table below shows which email is used based on email type. In the table, if an address is not, it falls back to the next available address until reaching the default.

| Email type           | Address used        | Examples                           |
| -------------------- | ------------------- | ---------------------------------- |
| Member notifications | Support, Default    | Signup/sign links, comment replies |
| Newsletters          | Newsletter, Default | Configurable per newsletter        |
| Staff notifications  | Default             | Recommendations, signups           |

Irrespective of how you configure email addresses, maximize deliverability by ensuring DKIM, SPF, and DMARC records are configured for your sending domains.

### Admin URL

Admin can be used to specify a different protocol for your admin panel or a different hostname (domain name). It can’t affect the path at which the admin panel is served (this is always /ghost/).

```json  theme={"dark"}
"admin": {
  "url": "http://example.com"
}
```

### Server

The server host and port are the IP address and port number that Ghost listens on for requests. By default, requests are routed from port 80 to Ghost by nginx (recommended), or Apache.

```json  theme={"dark"}
"server": {
    "host": "127.0.0.1",
    "port": 2368
}
```

### Privacy

All features inside the privacy.md file are enabled by default. It is possible to turn these off in order to protect privacy:

* Update check
* Gravatar
* RPC ping
* Structured data

For more information about the features, read the [privacy.md page](https://github.com/TryGhost/Ghost/blob/2f09dd888024f143d28a0d81bede1b53a6db9557/PRIVACY.md).

To turn off **all** of the features, use:

```json  theme={"dark"}
"privacy": {
    "useTinfoil": true
}
```

Alternatively, configure each feature individually:

```json  theme={"dark"}
"privacy": {
    "useUpdateCheck": false,
    "useGravatar": false,
    "useRpcPing": false,
    "useStructuredData": false
}
```

### Security

By default Ghost will email an auth code when it detects a login from a new device. To disable this feature, use:

```json  theme={"dark"}
"security": {
    "staffDeviceVerification": false
}
```

Note: if you want to force 2FA for all staff logins, not just new devices, you can do so under the Settings > Staff in the admin panel

### Paths

The configuration of paths can be relative or absolute. To use a content directory that does not live inside the Ghost folder, specify a paths object with a new contentPath:

```json  theme={"dark"}
"paths": {
    "contentPath": "content/"
},
```

When using a custom content path, the content directory must exist and contain subdirectories for data, images, themes, logs, and adapters.

<Note>
  If using a SQLite database, you’ll also need to update the path to your database to match the new location of the data folder.
</Note>

### Referrer Policy

Set the value of the content attribute of the meta referrer HTML tag by adding referrerPolicy to your config. `origin-when-crossorigin` is the default. Read through all possible [options](https://www.w3.org/TR/referrer-policy/#referrer-policies/).

## Adapters

Ghost allows for customizations at multiple layers through an adapter system. Customizable layers include: `storage`, `caching`, `sso`, and `scheduling`.

Use the `adapters` configuration block with “storage”, “caching”, “sso,” or “scheduling” keys to initialize a custom adapter. For example, the following configuration uses `storage-module-name` to handle all `storage` capabilities in Ghost. Note that the `active` key indicates a default adapter used for all features if no other adapters are declared.

```json  theme={"dark"}
"adapters": {
  "storage": {
    "active": "storage-module-name",
    "storage-module-name": {
      "key": "value"
    }
  }
}
```

Customize parts of Ghost’s features by declaring adapters at the feature level. For example, to use a custom `cache` adapter only for the `imageSizes` feature, configure the cache adapter as follows:

```json  theme={"dark"}
"adapters": {
  "cache": {
    "custom-redis-cache-adapter": {
      "host": "localhost",
      "port": 6379,
      "password": "secret_password"
    },
    "imageSizes": {
      "adapter": "custom-redis-cache-adapter",
      "ttl": 3600
    }
  }
}
```

The above declaration uses the `custom-redis-cache-adapter` only for the `imageSizes` cache feature with these values:

```json  theme={"dark"}
{
  "host": "localhost",
  "port": 6379,
  "password": "secret_password",
  "ttl": 3600
}
```

### Storage adapters

The storage layer is used to store images uploaded from the Ghost Admin UI, API, or when images are included in a zip file uploaded via the importer. Using a custom storage module allows you to change where images are stored without changing Ghost core.

By default, Ghost stores uploaded images in the file system. The default location is the Ghost content path in your Ghost folder under `content/images` or an alternative custom content path that’s been configured.

To use a custom storage adapter, your custom configuration file needs to be updated to provide configuration for your new storage module and set it as active:

```json  theme={"dark"}
"storage": {
    "active": "my-module",
    "my-module": {
        "key": "abcdef"
    }
}
```

The storage block should have 2 items:

* An active key, which contains the name\* of your module
* A key that reflects the name\* of your module, containing any config your module needs

#### Available storage features

* `images` - storage of image files uploaded through `POST '/images/upload'` endpoint
* `media` - storage of media files uploaded through `POST '/media/upload'` and `POST/media/thumbnail/upload` endpoints
* `files` - storage of generic files uploaded through `POST '/files/upload'` endpoint

#### Available custom storage adapters

* [local-file-store](https://github.com/TryGhost/Ghost/blob/fa1861aad3ba4e5e1797cec346f775c5931ca856/ghost/core/core/server/adapters/storage/LocalFilesStorage.js) (default) saves images to the local filesystem
* [http-store](https://gist.github.com/ErisDS/559e11bf3e84b89a9594) passes image requests through to an HTTP endpoint
* [s3-store](https://github.com/spanishdict/ghost-s3-compat) saves to Amazon S3 and proxies requests to S3
* [s3-store](https://github.com/colinmeinke/ghost-storage-adapter-s3) saves to Amazon S3 and works with 0.10+
* [qn-store](https://github.com/Minwe/qn-store) saves to Qiniu
* [ghost-cloudinary-store](https://github.com/mmornati/ghost-cloudinary-store) saves to Cloudinary
* [ghost-storage-cloudinary](https://github.com/eexit/ghost-storage-cloudinary) saves to Cloudinary with RetinaJS support
* [upyun-ghost-store](https://github.com/sanddudu/upyun-ghost-store) saves to Upyun
* [ghost-upyun-store](https://github.com/pupboss/ghost-upyun-store) saves to Upyun
* [ghost-google-drive](https://github.com/robincsamuel/ghost-google-drive) saves to Google Drive
* [ghost-azure-storage](https://github.com/tparnell8/ghost-azurestorage) saves to Azure Storage
* [ghost-imgur](https://github.com/wrenth04/ghost-imgur) saves to Imgur
* [google-cloud-storage](https://github.com/thombuchi/ghost-google-cloud-storage) saves to Google Cloud Storage
* [ghost-oss-store](https://github.com/MT-Libraries/ghost-oss-store) saves to Aliyun OSS
* [ghost-b2](https://github.com/martiendt/ghost-storage-adapter-b2) saves to Backblaze B2
* [ghost-github](https://github.com/ifvictr/ghost-github) saves to GitHub
* [pages-store](https://github.com/zce/pages-store) saves to GitHub Pages or other pages service, e.g. Coding Pages
* [WebDAV Storage](https://github.com/bartt/ghost-webdav-storage-adapter) saves to a WebDAV server.
* [ghost-qcloud-cos](https://github.com/ZhelinCheng/ghost-qcloud-cos) saves to Tencent Cloud COS.
* [ghost-bunny-cdn-storage](https://github.com/betschki/ghost-bunny-cdn-storage/) saves to BunnyCDN.

#### Creating a custom storage adapter

To replace the storage module with a custom solution, use the requirements detailed below. You can also take a look at our [default local storage implementation](https://github.com/TryGhost/Ghost/blob/fa1861aad3ba4e5e1797cec346f775c5931ca856/ghost/core/core/server/adapters/storage/LocalFilesStorage.js).

**Location**

1. Create a new folder named `storage` inside `content/adapters`
2. Inside of `content/adapters/storage`, create a file or a folder: `content/adapters/storage/my-module.js` or `content/adapters/storage/my-module` — if using a folder, create a file called `index.js` inside it.

**Base adapter class inheritance**

A custom storage adapter must inherit from the base storage adapter. By default, the base storage adapter is installed by Ghost and available in your custom adapter.

```js  theme={"dark"}
const BaseAdapter = require('ghost-storage-base');

class MyCustomAdapter extends BaseAdapter{
  constructor() {
    super();
  }
}

module.exports = MyCustomAdapter;
```

**Required methods**

Your custom storage adapter must implement five required functions:

* `save` - The `.save()` method stores the image and returns a promise which resolves the path from which the image should be requested in future.
* `exists` - Used by the base storage adapter to check whether a file exists or not
* `serve` - Ghost calls `.serve()` as part of its middleware stack, and mounts the returned function as the middleware for serving images
* `delete`
* `read`

```js  theme={"dark"}
const BaseAdapter = require('ghost-storage-base');

class MyCustomAdapter extends BaseAdapter{
  constructor() {
    super();
  }

  exists() {

  }

  save() {

  }

  serve() {
    return function customServe(req, res, next) {
      next();
    }
  }

  delete() {

  }

  read() {

  }
}

module.exports = MyCustomAdapter;
```

### Cache adapters

The cache layer is used for storing data that needs to be quickly accessible in a format requiring no additional processing. For example, the “imageSizes” cache stores images generated at different sizes based on the fetched URL. This request is a relatively expensive operation, which would otherwise slow down the response time of the Ghost server. Having calculated image sizes cached per image URL makes the image size lookup almost instant with only a little overhead on the initial image fetch.

By default, Ghost keeps caches in memory. The upsides of this approach are:

* no need for external dependencies
* very fast access to data

The downsides are:

* Having no persistence between Ghost restarts — cache has to be repopulated on every restart
* RAM is a limited resource that can be depleted by too many cached values

With custom cache adapters, like Redis storage, the cache can expand its size independently of the server’s system memory and persist its values between Ghost restarts.

#### Ghost’s built-in Redis cache adapter

Ghost’s built-in Redis cache adapter solves the downsides named above by persisting across Ghost restarts and not being limited by the Ghost instance’s RAM capacity. [Implementing a Redis cache](https://redis.io/docs/getting-started/installation/) is a good solution for sites with high load and complicated templates, ones using lots of `get` helpers. Note that this adapter requires Redis to be set up and running in addition to Ghost.

To use the Redis cache adapter, change the value for the cache adapter from “Memory” to “Redis” in the site’s configuration file. In the following example, image sizes and the tags Content API endpoint are cached in Redis for optimized performance.

```json  theme={"dark"}
    "adapters": {
        "cache": {
            "imageSizes": {
                "adapter": "Redis",
                "ttl": 3600,
                "keyPrefix": "image-sizes:"
            }
        }
    },
```

Note that the `ttl` value is in seconds.

#### Custom cache adapters

To use a custom cache adapter, update your custom configuration file. At the moment, only the `imageSizes` feature supports full customization. Configuration is as follows:

```json  theme={"dark"}
"cache": {
    "imageSizes": "my-cache-module",
    "my-cache-module": {
        "key": "cache_module_value"
    }
}
```

The `cache` block should have 2 items:

* A feature key, `"imageSizes"`, which contains the name of your custom caching module
* A `key` that reflects the name of your caching module, containing any config your module needs

#### Creating a custom cache adapter

To replace the caching module, use the requirements below. You can also take a look at our [default in-memory caching implementation](https://github.com/TryGhost/Ghost/blob/eb6534bd7fd905b9f402c1f446c87bff455b6f17/ghost/core/core/server/adapters/cache/Memory.js).

#### Location

1. Create a new folder named `cache` inside `content/adapters`
2. Inside of `content/adapters/cache`, create a file or a folder: `content/adapters/cache/my-cache-module.js` or `content/adapters/cache/my-cache-module` - if using a folder, create a file called `index.js` inside it.

#### Base cache adapter class inheritance

A custom cache adapter must inherit from the base cache adapter. By default the base cache adapter is installed by Ghost and available in your custom adapter.

```js  theme={"dark"}
const BaseCacheAdapter = require('@tryghost/adapter-base-cache');

class MyCustomCacheAdapter extends BaseCacheAdapter{
  constructor() {
    super();
  }
}

module.exports = MyCustomCacheAdapter;
```

#### Required methods

Your custom cache adapter must implement the following required functions:

* `get` - fetches the stored value based on the key value (`.get('some_key')`). It’s an async method - the implementation returns a `Promise` that resolves with the stored value.
* `set` - sets the value in the underlying cache based on key and value parameters. It’s an async method - the implementation returns a `Promise` that resolves once the value is stored.
* `keys` - fetches all keys present in the cache. It’s an async method — the implementation returns a `Promise` that resolves with an array of strings.
* `reset` - clears the cache. This method is not meant to be used in production code - it’s here for test suite purposes *only*.

```js  theme={"dark"}
const BaseCacheAdapter = require('@tryghost/adapter-base-cache');

class MyCustomCacheAdapter extends BaseCacheAdapter {

    constructor(config) {
        super();
    }

    /**
     * @param {String} key
     */
    async get(key) {
    }

    /**
     * @param {String} key
     * @param {*} value
     */
    async set(key, value) {
    }

    /**
     * @returns {Promise<Array<String>>} all keys present in the cache
     */
    async keys() {
    }

    /**
     * @returns {Promise<*>} clears the cache. Not meant for production
     */
    async reset() {
    }
}

module.exports = MyCustomCacheAdapter;
```

### Logging

Configure how Ghost should log, for example:

```json  theme={"dark"}
"logging": {
  "path": "something/",
  "useLocalTime": true,
  "level": "info",
  "rotation": {
    "enabled": true,
    "count": 15,
    "period": "1d"
  },
  "transports": ["stdout", "file"]
}
```

#### `level`

The default log level is `info` which prints all info, warning and error logs. Set it to `error` to only print errors.

#### `rotation`

Tell Ghost to rotate your log files. By default Ghost keeps 10 log files and rotates every day. Rotation is enabled by default in production and disabled in development.

#### `transports`

Define where Ghost should log to. By default Ghost writes to stdout and into file for production, and to stdout only for development.

#### `path`

Log your content path, e.g. `content/logs/`. Set any path but ensure the permissions are correct to write into this folder.

#### `useLocalTime`

Configure log timestamps to use the local timezone. Defaults to `false`.

### Spam

Tell Ghost how to treat [spam requests](https://github.com/TryGhost/Ghost/blob/ff61b330491b594997b5b156215417b5d7687743/ghost/core/core/shared/config/defaults.json#L64).

### Caching

Configure [HTTP caching](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching) for HTTP responses served from Ghost.

`caching` configuration is available for responses containing `public` value in `Cache-Control` header. Each key under `caching` section contains `maxAge` property that controls the `max-age` value in `Cache-Control` header. For example, the following configuration:

```json  theme={"dark"}
"caching": {
    "contentAPI": {
        "maxAge": 10
    }
}
```

Adds `Cache-Control: public, max-age=10` header with all Content API responses, which might be useful to set for high-volume sites where content does not change often.

The following configuration keys are available with default `maxAge` values:

* “frontend” - with `"maxAge": 0`, controls responses coming from public Ghost pages (like the homepage)
* “contentAPI” - with `"maxAge": 0`, controls responses coming from [Content API](/content-api/)
* “robotstxt” - with `"maxAge": 3600`, controls responses for `robots.txt` [files](/themes/structure/#robotstxt)
* “sitemap” - with `"maxAge": 3600`, controls responses for `sitemap.xml` [files](https://ghost.org/changelog/xml-sitemaps/)
* “sitemapXSL” - with `"maxAge": 86400`, controls responses for `sitemap.xsl` files
* “wellKnown” - with `"maxAge": 86400`, controls responses coming from `*/.wellknown/*` endpoints
* “cors” - with `"maxAge": 86400`, controls responses for `OPTIONS` [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) requests
* “publicAssets” - with `"maxAge": 31536000`, controls responses for public assets like `public/ghost.css`, `public/cards.min.js`, etc.
* “301” - with `"maxAge": 31536000`, controls 301 redirect responses
* “customRedirects” - with `"maxAge": 31536000`, controls redirects coming from [custom redirects](/themes/routing/#redirects)

### Compress

The compression flag is turned on by default using `"compress": true`. Alternatively, you can turn it off with `"compress": false`.

### Image optimization

When uploading images into the Ghost editor, they are automatically processed and compressed by default. This can be disabled in your `config.[env].json` file using:

```json  theme={"dark"}
"imageOptimization": {
  "resize": false
}
```

Image compression details:

* Resize the image to 2000px max width
* JPEGs are compressed to 80% quality.
* Metadata is removed

The original image is kept with the suffix `_o`.

### OpenSea

When creating NFT embeds, Ghost fetches the information from the [OpenSea](https://opensea.io) API. This API is rate limited, and OpenSea request that you use an API key in production environments.

You can [request an OpenSea API key](https://docs.opensea.io/reference/api-keys) from them directly, without needing an account.

```json  theme={"dark"}
"opensea": {
    "privateReadOnlyApiKey": "..."
}
```

### Tenor

To enable searching for GIFs directly in the editor, provide an API key for [Tenor](https://tenor.com).

You can [request a Tenor API key](https://developers.google.com/tenor/guides/quickstart) from Google’s cloud console, for free.

```json  theme={"dark"}
"tenor": {
    "googleApiKey": "..."
}
```

### Twitter

In order to display Twitter cards in newsletter emails, Ghost needs to be able to fetch data from the Twitter API and requires a Bearer Token to do so.

You can [request Twitter API access](https://developer.twitter.com) from them via their developer portal.

```json  theme={"dark"}
"twitter": {
    "privateReadOnlyToken": "..."
}
```

### Pintura

[Pintura](https://pqina.nl/pintura/) is an image editor that integrates with Ghost. After purchasing a license, upload the JS and CSS files via **Integrations** → **Pintura**.

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/60f0ab83-pintura-self-hosted_hubf952de862dc133080128958e1208795_480708_1397x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=3f76c81eb6130b3632500c1e8aae172c" data-og-width="1397" width="1397" data-og-height="961" height="961" data-path="images/60f0ab83-pintura-self-hosted_hubf952de862dc133080128958e1208795_480708_1397x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/60f0ab83-pintura-self-hosted_hubf952de862dc133080128958e1208795_480708_1397x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=614e54044353e5e29294ad66c6881c97 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/60f0ab83-pintura-self-hosted_hubf952de862dc133080128958e1208795_480708_1397x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=004523461a6ac6a7dc4bb707fd60c720 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/60f0ab83-pintura-self-hosted_hubf952de862dc133080128958e1208795_480708_1397x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a9d31adfc4b71f724977793942eb4cec 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/60f0ab83-pintura-self-hosted_hubf952de862dc133080128958e1208795_480708_1397x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=48fd793f8daf7418c96add7d962aa334 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/60f0ab83-pintura-self-hosted_hubf952de862dc133080128958e1208795_480708_1397x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=24acdac9fa5808b59444178460bb5de6 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/60f0ab83-pintura-self-hosted_hubf952de862dc133080128958e1208795_480708_1397x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=688eda290698db7b4f6d787b47ca1ff4 2500w" />
</Frame>

### Portal

Ghost automatically loads the scripts for Portal from jsDelivr.net. The default configuration is shown below.

The script can be relocated by changing the URL, or disabled entirely by setting `"url": false`.

```json  theme={"dark"}
"portal": {
    "url": "https://cdn.jsdelivr.net/npm/@tryghost/portal@~{version}/umd/portal.min.js"
}
```

### Search

Ghost automatically loads the scripts & styles for search from jsDelivr.net. The default configuration is shown below.

The script and stylesheet can be relocated by changing the URLs, or disabled entirely by setting `"url": false`.

```json  theme={"dark"}
"sodoSearch": {
    "url": "https://cdn.jsdelivr.net/npm/@tryghost/sodo-search@~{version}/umd/sodo-search.min.js",
    "styles": "https://cdn.jsdelivr.net/npm/@tryghost/sodo-search@~{version}/umd/main.css"
},
```

### Comments

Ghost automatically loads the scripts & styles for comments from jsDelivr.net. The default configuration is shown below.

The script and stylesheet can be relocated by changing the URLs, or disabled entirely by setting `"url": false`.

```json  theme={"dark"}
"comments": {
    "url": "https://cdn.jsdelivr.net/npm/@tryghost/comments-ui@~{version}/umd/comments-ui.min.js",
    "styles": "https://cdn.jsdelivr.net/npm/@tryghost/comments-ui@~{version}/umd/main.css"
}
```


# Overview
Source: https://docs.ghost.org/content-api

Ghost’s RESTful Content API delivers published content to the world and can be accessed in a read-only manner by any client to render in a website, app, or other embedded media.

***

Access control is managed via an API key, and even the most complex filters are made simple with our SDK. The Content API is designed to be fully cachable, meaning you can fetch data as often as you like without limitation.

***

## API Clients

### JavaScript Client Library

We’ve developed an [API client for JavaScript](/content-api/javascript/) that will allow you to quickly and easily interact with the Content API. The client is an advanced wrapper on top of our REST API - everything that can be done with the Content API can be done using the client, with no need to deal with the details of authentication or the request & response format.

***

## URL

`https://{admin_domain}/ghost/api/content/`

Your admin domain can be different to your site domain. Using the correct domain and protocol are critical to getting consistent behaviour, particularly when dealing with CORS in the browser. All Ghost(Pro) blogs have a `*.ghost.io domain` as their admin domain and require https.

### Key

`?key={key}`

Content API keys are provided via a query parameter in the URL. These keys are safe for use in browsers and other insecure environments, as they only ever provide access to public data. Sites in private mode should consider where they share any keys they create.

Obtain the Content API URL and key by creating a new `Custom Integration` under the **Integrations** screen in Ghost Admin.

<Frame caption={`Search "integrations" in your settings to jump right to the section.`}>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4175ad749c97e1ebb88d66d0b8980d6d" data-og-width="1400" width="1400" data-og-height="877" height="877" data-path="images/custom-integrations-list.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e4a187444e58b164e0b11070e9afdbeb 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7a5390023d1d9f12b114c11d1a3dc464 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=549c62ba31a5582ff5e288c866adccc7 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=025c9083f741d14db3783011c71abbda 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3844a517e384f6f92a7bdbe0b90607bc 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integrations-list.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=126af6dcf9fd72cdc03f53bb9ba429f0 2500w" />
</Frame>

<br />

<Frame caption="You can regenerate the Content API key any time, but any scripts or applications using it will need to be updated.">
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cda4a350d118c74c36bb9306cd7ddbbd" data-og-width="1400" width="1400" data-og-height="1097" height="1097" data-path="images/custom-integration-settings.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=806fc0a92f94d33540921e6a8bf96a7e 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4ddff2f6606ed8b59a43b79f544d7646 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=03c5b175be583d78be7f0f197ad99bd5 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0941cb50522f22dab4db9270db96d539 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0489f915c323a6a37d9c33f813eab379 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=61e2c0cd55b6bcc37e27d68804cad5b7 2500w" />
</Frame>

### Accept-Version Header

`Accept-Version: v{major}.{minor}`

Use the `Accept-Version` header to indicate the minimum version of Ghost’s API to operate with. See [API Versioning](/faq/api-versioning/) for more details.

### Working Example

```bash  theme={"dark"}
# cURL
# Real endpoint - copy and paste to see!
curl -H "Accept-Version: v6.0" "https://demo.ghost.io/ghost/api/content/posts/?key=22444f78447824223cefc48062"
```

***

## Endpoints

The Content API provides access to Posts, Pages, Tags, Authors, Tiers, and Settings. All endpoints return JSON and are considered [stable](/faq/api-versioning/).

### Working Example

| Verb | Path                                           | Method                |
| ---- | ---------------------------------------------- | --------------------- |
| GET  | [/posts/](/content-api/posts)                  | Browse posts          |
| GET  | [/posts/\{id}/](/content-api/posts)            | Read a post by ID     |
| GET  | [/posts/slug/\{slug}/](/content-api/posts)     | Read a post by slug   |
| GET  | [/authors/](/content-api/authors)              | Browse authors        |
| GET  | [/authors/\{id}/](/content-api/authors)        | Read an author by ID  |
| GET  | [/authors/slug/\{slug}/](/content-api/authors) | Read a author by slug |
| GET  | [/tags/](/content-api/tags)                    | Browse tags           |
| GET  | [/tags/\{id}/](/content-api/tags)              | Read a tag by ID      |
| GET  | [/tags/slug/\{slug}/](/content-api/tags)       | Read a tag by slug    |
| GET  | [/pages/](/content-api/pages)                  | Browse pages          |
| GET  | [/pages/\{id}/](/content-api/pages)            | Read a page by ID     |
| GET  | [/pages/slug/\{slug}/](/content-api/pages)     | Read a page by slug   |
| GET  | [/tiers/](/content-api/tiers)                  | Browse tiers          |
| GET  | [/settings/](/content-api/settings)            | Browse settings       |

The Content API supports two types of request: Browse and Read. Browse endpoints allow you to fetch lists of resources, whereas Read endpoints allow you to fetch a single resource.

***

## Resources

The API will always return valid JSON in the same structure:

```json  theme={"dark"}
{
    "resource_type": [{
        ...
    }],
    "meta": {}
}
```

* `resource_type`: will always match the resource name in the URL. All resources are returned wrapped in an array, with the exception of `/site/` and `/settings/`.
* `meta`: contains [pagination](/content-api/pagination) information for browse requests.


# Authors
Source: https://docs.ghost.org/content-api/authors

Authors are a subset of [users](/staff/) who have published posts associated with them.

```js  theme={"dark"}
GET /content/authors/
GET /content/authors/{id}/
GET /content/authors/slug/{slug}/
```

Authors that are not associated with a post are not returned. You can supply `include=count.posts` to retrieve the number of posts associated with an author.

<ResponseExample>
  ```json  theme={"dark"}
  {
      "authors": [
          {
              "slug": "cameron",
              "id": "5ddc9b9510d8970038255d02",
              "name": "Cameron Almeida",
              "profile_image": "https://docs.ghost.io/content/images/2019/03/1c2f492a-a5d0-4d2d-b350-cdcdebc7e413.jpg",
              "cover_image": null,
              "bio": "Editor at large.",
              "website": "https://example.com",
              "location": "Cape Town",
              "facebook": "example",
              "twitter": "@example",
              "meta_title": null,
              "meta_description": null,
              "url": "https://docs.ghost.io/author/cameron/"
          }
      ]
  }
  ```
</ResponseExample>


# Errors
Source: https://docs.ghost.org/content-api/errors



The Content API will generate errors for the following cases:

* Status 400: Badly formed queries e.g. filter parameters that are not correctly encoded
* Status 401: Authentication failures e.g. unrecognized keys
* Status 403: Permissions errors e.g. under-privileged users
* Status 404: Unknown resources e.g. data which is not public
* Status 500: Server errors e.g. where something has gone

Errors are also formatted in JSON, as an array of error objects. The HTTP status code of the response along with the `errorType` property indicate the type of error.

The `message` field is designed to provide clarity on what exactly has gone wrong.

<ResponseExample>
  ```json  theme={"dark"}
  {
      "errors": [
          {
              "message": "Unknown Content API Key",
              "errorType": "UnauthorizedError"
          }
      ]
  }
  ```
</ResponseExample>


# Filtering
Source: https://docs.ghost.org/content-api/filtering



Ghost uses a query language called NQL to allow filtering API results. You can filter any field or included field using matches, greater/less than or negation, as well as combining with and/or. NQL doesn’t yet support ’like’ or partial matches.

Filter strings must be URL encoded. The [\{\{get}}](/themes/helpers/functional/get/) helper and [client library](/content-api/javascript/) handle this for you.

At it’s most simple, filtering works the same as in GMail, GitHub or Slack - you provide a field and a value, separated by a colon.

### Syntax Reference

#### Filter Expressions

A **filter expression** is a string which provides the **property**, **operator** and **value** in the form **property:*operator*value**:

* **property** - a path representing the field to filter on
* **:** - separator between **property** and an **operator**-**value** expression
* **operator** (optional) - how to compare values (`:` on its own is roughly `=`)
* **value** - the value to match against

#### Property

Matches: `[a-zA-Z_][a-zA-Z0-9_.]`

* can contain only alpha-numeric characters and `_`
* cannot contain whitespace
* must start with a letter
* supports `.` separated paths, E.g. `authors.slug` or `posts.count`
* is always lowercase, but accepts and converts uppercase

#### Value

Can be one of the following

* **null**

* **true**

* **false**

* a ***number*** (integer)

* a **literal**

  * Any character string which follows these rules:
  * Cannot start with `-` but may contain it
  * Cannot contain any of these symbols: `'"+,()><=[]` unless they are escaped
  * Cannot contain whitespace

* a **string**

  * `'` string here `'` Any character except a single or double quote surrounded by single quotes
  * Single or Double quote \_\_MUST \_\_be escaped\*
  * Can contain whitespace
  * A string can contain a date any format that can be understood by `new Date()`

* a **relative date**

  * Uses the pattern now-30d
  * Must start with now
  * Can use - or +
  * Any integer can be used for the size of the interval
  * Supports the following intervals: d, w, M, y, h, m, s

#### Operators

* `-` - not
* `>` - greater than
* `>=` - greater than or equals
* `<` - less than
* `<=` - less than or equals
* `~` - contains
* `~^` - starts with
* `~$` - ends with
* `[` value, value, … `]` - “in” group, can be negated with `-`

#### Combinations

* `+` - represents and
* `,` - represents or
* `(` filter expression `)` - overrides operator precedence

#### Strings vs Literals

Most of the time, there’s no need to put quotes around strings when building filters in Ghost. If you filter based on slugs, slugs are always compatible with literals. However, in some cases you may need to use a string that contains one of the other characters used in the filter syntax, e.g. dates & times contain`:`. Use single-quotes for these.


# Content API JavaScript Client
Source: https://docs.ghost.org/content-api/javascript

Ghost provides a flexible promise-based JavaScript library for accessing the Content API. The library can be used in any JavaScript project, client or server side and abstracts away all the pain points of working with API data.

***

## Working Example

```js  theme={"dark"}
const api = new GhostContentAPI({
  url: 'https://demo.ghost.io',
  key: '22444f78447824223cefc48062',
  version: "v6.0"
});

// fetch 5 posts, including related tags and authors
api.posts
    .browse({limit: 5, include: 'tags,authors'})
    .then((posts) => {
        posts.forEach((post) => {
            console.log(post.title);
        });
    })
    .catch((err) => {
        console.error(err);
    });
```

## Authentication

The client requires the host address of your Ghost API and a Content API key in order to authenticate.

The version string is optional, and indicates the minimum version of Ghost your integration can work with.

The Content API URL and key can be obtained by creating a new `Custom Integration` under the **Integrations** screen in Ghost Admin.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cda4a350d118c74c36bb9306cd7ddbbd" data-og-width="1400" width="1400" data-og-height="1097" height="1097" data-path="images/custom-integration-settings.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=806fc0a92f94d33540921e6a8bf96a7e 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4ddff2f6606ed8b59a43b79f544d7646 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=03c5b175be583d78be7f0f197ad99bd5 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0941cb50522f22dab4db9270db96d539 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0489f915c323a6a37d9c33f813eab379 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/custom-integration-settings.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=61e2c0cd55b6bcc37e27d68804cad5b7 2500w" />
</Frame>

* `url` - API domain, must not end in a trailing slash.
* `key` - hex string copied from the “Integrations” screen in Ghost Admin
* `version` - should be set to ‘v6.0’

See the documentation on [Content API authentication](/content-api/#authentication) for more explanation.

## Endpoints

All endpoints & parameters provided by the [Content API](/content-api/) are supported.

```js  theme={"dark"}
// Browsing posts returns Promise([Post...]);
// The resolved array will have a meta property
api.posts.browse({limit: 2, include: 'tags,authors'});
api.posts.browse();

// Reading posts returns Promise(Post);
api.posts.read({id: 'abcd1234'});
api.posts.read({slug: 'something'}, {formats: ['html', 'plaintext']});

// Browsing authors returns Promise([Author...])
// The resolved array will have a meta property
api.authors.browse({page: 2});
api.authors.browse();

// Reading authors returns Promise(Author);
api.authors.read({id: 'abcd1234'});
api.authors.read({slug: 'something'}, {include: 'count.posts'}); // include can be array for any of these

// Browsing tags returns Promise([Tag...])
// The resolved array will have a meta property
api.tags.browse({order: 'slug ASC'});
api.tags.browse();

// Reading tags returns Promise(Tag);
api.tags.read({id: 'abcd1234'});
api.tags.read({slug: 'something'}, {include: 'count.posts'});

// Browsing pages returns Promise([Page...])
// The resolved array will have a meta property
api.pages.browse({limit: 2});
api.pages.browse();

// Reading pages returns Promise(Page);
api.pages.read({id: 'abcd1234'});
api.pages.read({slug: 'something'}, {fields: ['title']});

// Browsing settings returns Promise(Settings...)
// The resolved object has each setting as a key value pair
api.settings.browse();
```

For all resources except settings, the `browse()` method will return an array of objects, and the `read()` method will return a single object. The `settings.browse()` endpoint always returns a single object with all the available key-value pairs.

See the documentation on [Content API resources](/content-api/#resources) for a full description of the response for each resource.

## Installation

`yarn add @tryghost/content-api`

`npm install @tryghost/content-api`

You can also use the standalone UMD build:

`https://unpkg.com/@tryghost/content-api@{version}/umd/content-api.min.js`

### Usage

ES modules:

```js  theme={"dark"}
import GhostContentAPI from '@tryghost/content-api'
```

Node.js:

```js  theme={"dark"}
const GhostContentAPI = require('@tryghost/content-api');
```

In the browser:

```html  theme={"dark"}
<script src="https://unpkg.com/@tryghost/content-api@{version}/umd/content-api.min.js"></script>
<script>
    const api = new GhostContentAPI({
        // authenticate here
    });
</script>
```

Get the [latest version](https://unpkg.com/@tryghost/content-api) from [unpkg.com](https://unpkg.com).

## Filtering

Ghost provides the `filter` parameter to fetch your content with endless possibilities! Especially useful for retrieving posts according to their tags, authors or other properties.

Ghost uses the NQL query language to create filters in a simple yet powerful string format. See the [NQL Syntax Reference](/content-api/#filtering) for full details.

Filters are provided to client libraries via the `filter` property of any `browse` method.

```js  theme={"dark"}
api.posts.browse({filter: 'featured:true'});
```

Incorrectly formatted filters will result in a 400 Bad Request Error. Filters that don’t match any data will return an empty array.

### Working Example

```js  theme={"dark"}
const api = new GhostContentAPI({
  host: 'https://demo.ghost.io',
  key: '22444f78447824223cefc48062',
  version: "v6.0"
});

// fetch 5 posts, including related tags and authors
api.posts.browse({
    filter: 'tag:fiction+tag:-fables'
})
.then((posts) => {
    posts.forEach((post) => {
        console.log(post.title);
    });
})
.catch((err) => {
    console.error(err);
});
```

### Common Filters

* `featured:true` - all resources with a field `featured` that is set to `true`.
* `featured:true+feature_image:null` - looks for featured posts which don’t have a feature image set by using `+` (and).
* `tag:hash-noimg` - `tag` is an alias for `tags.slug` and `hash-noimg` would be the slug for an internal tag called `#NoImg`. This filter would allow us to find any post that has this internal tag.
* `tags:[photo, video, audio]` - filters posts which have any one of the listed tags, `[]` (grouping) is more efficient than using or when querying the same field.
* `primary_author:my-author` - `primary_author` is an alias for the first author, allowing for filtering based on the first author.
* `published_at:>'2017-06-03 23:43:12'` - looks for posts published after a date, using a date string wrapped in single quotes and the `>` operator

## JavaScript SDK

A collection of packages for common API usecases

### Helpers

* Package: `@tryghost/helpers`
* Builds: CJS, ES, UMD

The shared helpers are designed for performing data formatting tasks, usually when creating custom frontends. These are the underlying tools that power our [handlebars](/themes/) and [gatsby](/jamstack/gatsby/#custom-helpers) helpers.

#### Tags

Filters and outputs tags. By default, the helper will output a comma separated list of tag names, excluding any internal tags.

```js  theme={"dark"}
import {tags} from '@tryghost/helpers'

// Outputs e.g. Posted in: New Things, Releases, Features.
posts.forEach((post) => {
    tags(post, {prefix: 'Posted in: ', suffix: '.'});
});
```

The first argument must be a post object, or any object that has a `tags` array.

**Options**

The tag helper supports multiple options so that you can control exactly what is output, without having to write any logic.

* `limit` \{integer} - limits the number of tags to be returned
* `from` \{integer, default:1} - index of the tag to start iterating from
* `to` \{integer} - index of the last tag to iterate over
* `separator` \{string, default:","} - string used between each tag
* `prefix` \{string} - string to output before each tag
* `suffix` \{string} - string to output after each tag
* `visibility` \{string, default:“public”} - change to “all” to include internal tags
* `fallback` \{object} - a fallback tag to output if there are none
* `fn` \{function} - function to call on each tag, default returns tag.name

#### Reading Time

Calculates the estimated reading time based on the HTML for a post & available images.

```js  theme={"dark"}
import {readingTime} from '@tryghost/helpers'

// Outputs e.g. A 5 minute read.
posts.forEach((post) => {
    readingTime(post, {minute: 'A 1 minute read.', minutes: 'A % minute read.'});
});
```

The first argument must be a post object, or any object that has an `html` string. If a `feature_image` is present, this is taken into account.

**Options**

The output of the reading time helper can be customised through format strings.

* `minute` \{string, default:“1 min read”} - format for reading times \<= 1 minute
* `minutes` \{string, default:"% min read"} - format for reading times > 1 minute

#### Installation

`yarn add @tryghost/helpers`

`npm install @tryghost/helpers`

You can also use the standalone UMD build:

`https://unpkg.com/@tryghost/helpers@{version}/umd/helpers.min.js`

**Usage**

ES modules:

```js  theme={"dark"}
import {tags, readingTime} from '@tryghost/helpers'
```

Node.js:

```js  theme={"dark"}
const {tags, readingTime} = require('@tryghost/helpers');
```

In the browser:

```html  theme={"dark"}
<script src="https://unpkg.com/@tryghost/helpers@{version}/umd/helpers.min.js"></script>
<script>
    const {tags, readingTime} = GhostHelpers;
</script>
```

Get the [latest version](https://unpkg.com/@tryghost/helpers) from [https://unpkg.com](https://unpkg.com).

### String

* Package: `@tryghost/string`
* Builds: CJS

Utilities for processing strings.

#### Slugify

The function Ghost uses to turn a post title or tag name into a slug for use in URLs.

```js  theme={"dark"}
const {slugify} = require('@tryghost/string');
const slug = slugify('你好 👋!'); // slug === "ni-hao"
```

The first argument is the string to transform. The second argument is an optional options object.

**Options**

The output can be customised by passing options

* `requiredChangesOnly` \{boolean, default:false} - don’t perform optional cleanup, e.g. removing extra dashes

#### Installation

`yarn add @tryghost/string`

`npm install @tryghost/string`

**Usage**

Node.js:

```js  theme={"dark"}
const {slugify} = require('@tryghost/string');
```


# Pages
Source: https://docs.ghost.org/content-api/pages

Pages are static resources that are not included in channels or collections on the Ghost front-end. The API will only return pages that were created as resources and will not contain routes created with [dynamic routing](/themes/routing/).

```js  theme={"dark"}
GET /content/pages/
GET /content/pages/{id}/
GET /content/pages/slug/{slug}/
```

Pages are structured identically to posts. The response object will look the same, only the resource key will be `pages`.

By default, pages are ordered by title when fetching more than one.


# Pagination
Source: https://docs.ghost.org/content-api/pagination



All browse endpoints are paginated, returning 15 records by default. You can use the [page](/content-api/parameters#page) and [limit](/content-api/parameters#limit) parameters to move through the pages of records. The response object contains a `meta.pagination` key with information on the current location within the records:

```json  theme={"dark"}
"meta":{
    "pagination":{
      "page":1,
      "limit":2,
      "pages":1,
      "total":1,
      "next":null,
      "prev":null
    }
  }
```


# Parameters
Source: https://docs.ghost.org/content-api/parameters



Query parameters provide fine-grained control over responses. All endpoints accept `include` and `fields`. Browse endpoints additionally accept `filter`, `limit`, `page` and `order`.

The values provided as query parameters MUST be url encoded when used directly. The [client libraries](/content-api/javascript/) will handle this for you.

### Include

Tells the API to return additional data related to the resource you have requested. The following includes are available:

* Posts & Pages: `authors`, `tags`
* Authors: `count.posts`
* Tags: `count.posts`
* Tiers: `monthly_price`, `yearly_price`, `benefits`

Includes can be combined with a comma, e.g., `&include=authors,tags`.

For posts and pages:

* `&include=authors` will add `"authors": [{...},]` and `"primary_author": {...}`
* `&include=tags` will add `"tags": [{...},]` and `"primary_tag": {...}`

For authors and tags:

* `&include=count.posts` will add `"count": {"posts": 7}` to the response.

For tiers:

* `&include=monthly_price,yearly_price,benefits` will add monthly price, yearly price, and benefits data.

### Fields

Limit the fields returned in the response object. Useful for optimizing queries, but does not play well with include.

E.g. for posts `&fields=title,url` would return:

```json  theme={"dark"}
{
    "posts": [
        {
            "id": "5b7ada404f87d200b5b1f9c8",
            "title": "Welcome to Ghost",
            "url": "https://demo.ghost.io/welcome/"
        }
    ]
}
```

### Formats

(Posts and Pages only)

By default, only `html` is returned, however each post and page in Ghost has 2 available formats: `html` and `plaintext`.

* `&formats=html,plaintext` will additionally return the plaintext format.

### Filter

(Browse requests only)

Apply fine-grained filters to target specific data.

* `&filter=featured:true` on posts returns only those marked featured.
* `&filter=tag:getting-started` on posts returns those with the tag slug that matches `getting-started`.
* `&filter=visibility:public` on tiers returns only those marked as publicly visible.

The possibilities are extensive! Query strings are explained in detail in the [filtering](/content-api/filtering) section.

### Limit

(Browse requests only)

By default, only 15 records are returned at once.

* `&limit=5` would return only 5 records
* `&limit=100` will return 100 records (max)

### Page

(Browse requests only)

By default, the first 15 records are returned.

* `&page=2` will return the second set of 15 records.

### Order

(Browse requests only)

Different resources have a different default sort order:

* Posts: `published_at DESC` (newest post first)
* Pages: `title ASC` (alphabetically by title)
* Tags: `name ASC` (alphabetically by name)
* Authors: `name ASC` (alphabetically by name)
* Tiers: `monthly_price ASC` (from lowest to highest monthly price)

The syntax for modifying this follows SQL order by syntax:

* `&order=published_at%20asc` would return posts with the newest post last


# Posts
Source: https://docs.ghost.org/content-api/posts

Posts are the primary resource in a Ghost site. Using the posts endpoint it is possible to get lists of posts filtered by various criteria.

```js  theme={"dark"}
GET /content/posts/
GET /content/posts/{id}/
GET /content/posts/slug/{slug}/
```

By default, posts are returned in reverse chronological order by published date when fetching more than one.

The most common gotcha when fetching posts from the Content API is not using the [include](/content-api/parameters#include) parameter to request related data such as tags and authors. By default, the response for a post will not include these:

```json  theme={"dark"}
{
    "posts": [
        {
            "slug": "welcome-short",
            "id": "5ddc9141c35e7700383b2937",
            "uuid": "a5aa9bd8-ea31-415c-b452-3040dae1e730",
            "title": "Welcome",
            "html": "<p>👋 Welcome, it's great to have you here.</p>",
            "comment_id": "5ddc9141c35e7700383b2937",
            "feature_image": "https://static.ghost.org/v3.0.0/images/welcome-to-ghost.png",
            "feature_image_alt": null,
            "feature_image_caption": null,
            "featured": false,
            "visibility": "public",
            "created_at": "2019-11-26T02:43:13.000+00:00",
            "updated_at": "2019-11-26T02:44:17.000+00:00",
            "published_at": "2019-11-26T02:44:17.000+00:00",
            "custom_excerpt": null,
            "codeinjection_head": null,
            "codeinjection_foot": null,
            "custom_template": null,
            "canonical_url": null,
            "url": "https://docs.ghost.io/welcome-short/",
            "excerpt": "👋 Welcome, it's great to have you here.",
            "reading_time": 0,
            "access": true,
            "og_image": null,
            "og_title": null,
            "og_description": null,
            "twitter_image": null,
            "twitter_title": null,
            "twitter_description": null,
            "meta_title": null,
            "meta_description": null,
            "email_subject": null
        }
    ]
}
```

Posts allow you to include `authors` and `tags` using `&include=authors,tags`, which will add an `authors` and `tags` array to the response, as well as both a `primary_author` and `primary_tag` object.

<RequestExample>
  ```bash Request theme={"dark"}
  # cURL
  # Real endpoint - copy and paste to see!
  curl "https://demo.ghost.io/ghost/api/content/posts/?key=22444f78447824223cefc48062&include=tags,authors"
  ```
</RequestExample>

<ResponseExample>
  ```json Response theme={"dark"}
  {
      "posts": [
          {
              "slug": "welcome-short",
              "id": "5c7ece47da174000c0c5c6d7",
              "uuid": "3a033ce7-9e2d-4b3b-a9ef-76887efacc7f",
              "title": "Welcome",
              "html": "<p>👋 Welcome, it's great to have you here.</p>",
              "comment_id": "5c7ece47da174000c0c5c6d7",
              "feature_image": "https://casper.ghost.org/v2.0.0/images/welcome-to-ghost.jpg",
              "feature_image_alt": null,
              "feature_image_caption": null,
              "featured": false,
              "meta_title": null,
              "meta_description": null,
              "created_at": "2019-03-05T19:30:15.000+00:00",
              "updated_at": "2019-03-26T19:45:31.000+00:00",
              "published_at": "2012-11-27T15:30:00.000+00:00",
              "custom_excerpt": "Welcome, it's great to have you here.",
              "codeinjection_head": null,
              "codeinjection_foot": null,
              "og_image": null,
              "og_title": null,
              "og_description": null,
              "twitter_image": null,
              "twitter_title": null,
              "twitter_description": null,
              "custom_template": null,
              "canonical_url": null,
              "authors": [
                  {
                      "id": "5951f5fca366002ebd5dbef7",
                      "name": "Ghost",
                      "slug": "ghost",
                      "profile_image": "https://demo.ghost.io/content/images/2017/07/ghost-icon.png",
                      "cover_image": null,
                      "bio": "The professional publishing platform",
                      "website": "https://ghost.org",
                      "location": null,
                      "facebook": "ghost",
                      "twitter": "@tryghost",
                      "meta_title": null,
                      "meta_description": null,
                      "url": "https://demo.ghost.io/author/ghost/"
                  }
              ],
              "tags": [
                  {
                      "id": "59799bbd6ebb2f00243a33db",
                      "name": "Getting Started",
                      "slug": "getting-started",
                      "description": null,
                      "feature_image": null,
                      "visibility": "public",
                      "meta_title": null,
                      "meta_description": null,
                      "url": "https://demo.ghost.io/tag/getting-started/"
                  }
              ],
              "primary_author": {
                  "id": "5951f5fca366002ebd5dbef7",
                  "name": "Ghost",
                  "slug": "ghost",
                  "profile_image": "https://demo.ghost.io/content/images/2017/07/ghost-icon.png",
                  "cover_image": null,
                  "bio": "The professional publishing platform",
                  "website": "https://ghost.org",
                  "location": null,
                  "facebook": "ghost",
                  "twitter": "@tryghost",
                  "meta_title": null,
                  "meta_description": null,
                  "url": "https://demo.ghost.io/author/ghost/"
              },
              "primary_tag": {
                  "id": "59799bbd6ebb2f00243a33db",
                  "name": "Getting Started",
                  "slug": "getting-started",
                  "description": null,
                  "feature_image": null,
                  "visibility": "public",
                  "meta_title": null,
                  "meta_description": null,
                  "url": "https://demo.ghost.io/tag/getting-started/"
              },
              "url": "https://demo.ghost.io/welcome-short/",
              "excerpt": "Welcome, it's great to have you here."
          }
      ]
  }
  ```
</ResponseExample>


# Settings
Source: https://docs.ghost.org/content-api/settings

Settings contain the global settings for a site.

```js  theme={"dark"}
GET /content/settings/
```

The settings endpoint is a special case. You will receive a single object, rather than an array. This endpoint doesn’t accept any query parameters.

<ResponseExample>
  ```json  theme={"dark"}
  {
      "settings": {
          "title": "Ghost",
          "description": "The professional publishing platform",
          "logo": "https://docs.ghost.io/content/images/2014/09/Ghost-Transparent-for-DARK-BG.png",
          "icon": "https://docs.ghost.io/content/images/2017/07/favicon.png",
          "accent_color": null,
          "cover_image": "https://docs.ghost.io/content/images/2019/10/publication-cover.png",
          "facebook": "ghost",
          "twitter": "@tryghost",
          "lang": "en",
          "timezone": "Etc/UTC",
          "codeinjection_head": null,
          "codeinjection_foot": "<script src=\"//rum-static.pingdom.net/pa-5d8850cd3a70310008000482.js\" async></script>",
          "navigation": [
              {
                  "label": "Home",
                  "url": "/"
              },
              {
                  "label": "About",
                  "url": "/about/"
              },
              {
                  "label": "Getting Started",
                  "url": "/tag/getting-started/"
              },
              {
                  "label": "Try Ghost",
                  "url": "https://ghost.org"
              }
          ],
          "secondary_navigation": [],
          "meta_title": null,
          "meta_description": null,
          "og_image": null,
          "og_title": null,
          "og_description": null,
          "twitter_image": null,
          "twitter_title": null,
          "twitter_description": null,
          "members_support_address": "noreply@docs.ghost.io",
          "url": "https://docs.ghost.io/"
      }
  }
  ```
</ResponseExample>


# Tags
Source: https://docs.ghost.org/content-api/tags

Tags are the [primary taxonomy](/publishing/#tags) within a Ghost site.

```js  theme={"dark"}
GET /content/tags/
GET /content/tags/{id}/
GET /content/tags/slug/{slug}/
```

By default, internal tags are always included, use `filter=visibility:public` to limit the response directly or use the [tags helper](/themes/helpers/data/tags/) to handle filtering and outputting the response.

Tags that are not associated with a post are not returned. You can supply `include=count.posts` to retrieve the number of posts associated with a tag.

<ResponseExample>
  ```json  theme={"dark"}
  {
      "tags": [
          {
              "slug": "getting-started",
              "id": "5ddc9063c35e7700383b27e0",
              "name": "Getting Started",
              "description": null,
              "feature_image": null,
              "visibility": "public",
              "meta_title": null,
              "meta_description": null,
              "og_image": null,
              "og_title": null,
              "og_description": null,
              "twitter_image": null,
              "twitter_title": null,
              "twitter_description": null,
              "codeinjection_head": null,
              "codeinjection_foot": null,
              "canonical_url": null,
              "accent_color": null,
              "url": "https://docs.ghost.io/tag/getting-started/"
          }
      ]
  }
  ```
</ResponseExample>

By default, tags are ordered by name when fetching more than one.


# Tiers
Source: https://docs.ghost.org/content-api/tiers

Tiers allow publishers to create multiple options for an audience to become paid subscribers. Each tier can have its own price points, benefits, and content access levels. Ghost connects tiers directly to the publication’s Stripe account.

#### Usage

The tiers endpoint returns a list of tiers for the site, filtered by their visibility criteria.

```js  theme={"dark"}
GET /content/tiers/
```

Tiers are returned in order of increasing monthly price.

```json  theme={"dark"}
{
    "tiers": [
        {
            "id": "62307cc71b4376a976734037",
            "name": "Free",
            "description": null,
            "slug": "free",
            "active": true,
            "type": "free",
            "welcome_page_url": null,
            "created_at": "2022-03-15T11:47:19.000Z",
            "updated_at": "2022-03-15T11:47:19.000Z",
            "stripe_prices": null,
            "benefits": null,
            "visibility": "public"
        },
        {
            "id": "6230d7c8c62265c44f24a594",
            "name": "Gold",
            "description": null,
            "slug": "gold",
            "active": true,
            "type": "paid",
            "welcome_page_url": "/welcome-to-gold",
            "created_at": "2022-03-15T18:15:36.000Z",
            "updated_at": "2022-03-15T18:16:00.000Z",
            "stripe_prices": null,
            "benefits": null,
            "visibility": "public"
        }
    ]
}
```

<RequestExample>
  ```bash  theme={"dark"}
  # cURL
  # Real endpoint - copy and paste to see!
  curl "https://demo.ghost.io/ghost/api/content/tiers/?key=22444f78447824223cefc48062&include=benefits,monthly_price,yearly_price"
  ```
</RequestExample>

<ResponseExample>
  ```json  theme={"dark"}
  {
      "tiers": [
          {
              "id": "61ee7f5c5a6309002e738c41",
              "name": "Free",
              "description": null,
              "slug": "61ee7f5c5a6309002e738c41",
              "active": true,
              "type": "free",
              "welcome_page_url": "/",
              "created_at": "2022-01-24T10:28:44.000Z",
              "updated_at": null,
              "stripe_prices": null,
              "monthly_price": null,
              "yearly_price": null,
              "benefits": [],
              "visibility": "public"
          },
          {
              "id": "60815dbe9af732002f9e02fa",
              "name": "Ghost Subscription",
              "description": null,
              "slug": "ghost-subscription",
              "active": true,
              "type": "paid",
              "welcome_page_url": "/",
              "created_at": "2021-04-22T12:27:58.000Z",
              "updated_at": "2022-01-12T17:22:29.000Z",
              "stripe_prices": null,
              "monthly_price": 500,
              "yearly_price": 5000,
              "currency": "usd",
              "benefits": [],
              "visibility": "public"
          }
      ],
      "meta": {
          "pagination": {
              "page": 1,
              "limit": 15,
              "pages": 1,
              "total": 2,
              "next": null,
              "prev": null
          }
      }
  }
  ```
</ResponseExample>


# Versioning
Source: https://docs.ghost.org/content-api/versioning



See [API versioning](/faq/api-versioning/) for full details of the API versions and their stability levels.


# Contributing To Ghost
Source: https://docs.ghost.org/contributing

Ghost is completely open source software built almost entirely by volunteer contributors who use it every day.

***

The best part about structuring a software project this way is that not only does everyone get to own the source code without restriction, but as people all over the world help to improve it: Everyone benefits.

## Core team

In addition to [full time product team](https://ghost.org/about/) working for Ghost Foundation, there are a number of community members who have contributed to the project for a lengthy period of time and are considered part of the core team. They are:

* [Austin Burdine](https://github.com/acburdine) - Ghost-CLI
* [Felix Rieseberg](https://github.com/felixrieseberg) - Ghost Desktop
* [Vicky Chijwani](https://github.com/vickychijwani) - Ghost Mobile
* [David Balderston](https://github.com/dbalders) - Community

#### How core team members are added

People typically invited to join the Core Team officially after an extended period of successful contribution to Ghost and demonstrating good judgement. In particular, this means having humility, being open to feedback and changing their mind, knowing the limits of their abilities and being able to communicate all of these things such that it is noticed. Good judgement is what produces trust, not quality, quantity or pure technical skill.

When we believe a core contributor would make a great ambassador for Ghost and feel able to trust them to make good decisions about its future - that’s generally when we’ll ask them to become a member of the formal Core Team.

Core Team members are granted commit rights to Ghost projects, access to the Ghost Foundation private Slack, and occasionally join our international team retreats.

## Community guidelines

All participation in the Ghost community is subject to our incredibly straightforward [code of conduct](https://ghost.org/conduct/) and wider [community guidelines](https://forum.ghost.org/t/faq-guidelines/5).

The vast majority of the Ghost community is incredible, and we work hard to make sure it stays that way. We always welcome people who are friendly and participate constructively, but we outright ban anyone who is behaving in a poisonous manner.

## Ghost Trademark

**Ghost** is a registered trademark of Ghost Foundation Ltd. We’re happy to extend a flexible usage license of the Ghost trademark to community projects, companies and individuals, however it please read the **[Ghost trademark usage policy](https://ghost.org/trademark/)** before using the Ghost name in your project.

## Development guide

If you’re a developer looking to help, but you’re not sure where to begin: Check out the [good first issue](https://github.com/TryGhost/Ghost/labels/good%20first%20issue) label on GitHub, which contains small pieces of work that have been specifically flagged as being friendly to new contributors.

Or, if you’re looking for something a little more challenging to sink your teeth into, there’s a broader [help wanted](https://github.com/TryGhost/Ghost/labels/help%20wanted) label encompassing issues which need some love.

When you’re ready, check out the full **[Ghost Contributing Guide](https://github.com/TryGhost/Ghost/blob/main/.github/CONTRIBUTING.md)** for detailed instructions about how to hack on Ghost Core and send changes upstream.

<Note>
  Ghost is currently hiring Product Engineers! Check out what it’s like to be part of the team and see our open roles at [careers.ghost.org](https://careers.ghost.org/)
</Note>

## Other ways to help

The primary way to contribute to Ghost is by writing code, but if you’re not a developer there are still ways you can help. We always need help with:

* Helping our Ghost users on [the forum](https://forum.ghost.org)
* Creating tutorials and guides
* Testing and quality assurance
* Hosting local events or meetups
* Promoting Ghost to others

There are lots of ways to make discovering and using Ghost a better experience.

## Donations

As a non-profit organisation we’re always grateful to receive any and all donations to help our work, and allow us to employ more people to work on Ghost directly.

#### Partnerships

We’re very [happy to partner](https://ghost.org/partners/) with startups and companies who are able to provide Ghost with credit, goods and services which help us build free, open software for everyone. Please reach out to us `hello@ghost.org` if you’re interested in partnering with us to help Ghost.

#### Open Collective

**New:** We have a number of ongoing donation and sponsorship opportunities for individuals or companies looking to make ongoing contributions to the open source software which they use on [Open Collective](https://opencollective.com/ghost).

#### Bitcoin

For those who prefer to make a one time donation, we’re very happy to accept BTC. Unless you explicitly want your donation to be anonymous, please send us a tweet or an email and let us know who you are! We’d love to say thank you.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c60e8c5b-btc-wallet_huc4fe22c23acec5bcf43cd862bd3a3a9a_3915_356x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=80f6943236fbcd6e80ea60dc4aff59ea" data-og-width="356" width="356" data-og-height="356" height="356" data-path="images/c60e8c5b-btc-wallet_huc4fe22c23acec5bcf43cd862bd3a3a9a_3915_356x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c60e8c5b-btc-wallet_huc4fe22c23acec5bcf43cd862bd3a3a9a_3915_356x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=a34fc7de7a51f7d6b7fd937eb58d4aec 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c60e8c5b-btc-wallet_huc4fe22c23acec5bcf43cd862bd3a3a9a_3915_356x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2c4a202e484bd7ae7515682019678e0d 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c60e8c5b-btc-wallet_huc4fe22c23acec5bcf43cd862bd3a3a9a_3915_356x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=1822c5aa62179c21d626f554a45ca319 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c60e8c5b-btc-wallet_huc4fe22c23acec5bcf43cd862bd3a3a9a_3915_356x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=40fb8bfefdca0826f0e650158a45fe08 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c60e8c5b-btc-wallet_huc4fe22c23acec5bcf43cd862bd3a3a9a_3915_356x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2debf1eb60fe9b96bdce4dacc6af6515 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c60e8c5b-btc-wallet_huc4fe22c23acec5bcf43cd862bd3a3a9a_3915_356x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e9841383d0e0532af58c8fb49be5c265 2500w" />
</Frame>

**Ghost BTC Address:**\
`3CrQfpWaZPFfD4kAT7kh6avbW7bGBHiBq9`


# Ghost Developer FAQs
Source: https://docs.ghost.org/faq

Frequently asked questions and answers about running Ghost

<CardGroup cols={2}>
  <Card title="API versioning" href="/faq/api-versioning/">
    Ghost ships with a mature set of APIs. Each API endpoint has a status, which indicates suitability for production use. Read more about Ghost’s [architecture](/architecture/).
  </Card>

  <Card title="Clustering, sharding, HA and other multi-server setups" href="/faq/clustering-sharding-multi-server/">
    Ghost doesn’t support load-balanced clustering or multi-server setups of any description, there should only be *one* Ghost instance per site.
  </Card>

  <Card title="Filter property not working in routing" href="/faq/filter-property-routes-yaml/">
    Working with more complex iterations of the filter property in the routes.yaml file can cause conflicts or unexpected behaviour. Here are the most common issues.
  </Card>

  <Card title="How can I backup my site data?" href="/faq/manual-backup/">
    Learn how to backup your self-hosted Ghost install
  </Card>

  <Card title="How to resolve errors when running ghost start" href="/faq/errors-running-ghost-start/">
    If an error occurs when trying to run `ghost start` or `ghost restart`, try using `ghost run` first to check that Ghost can start successfully. The `start` and `restart` commands are talking to your process manager (e.g. systemd) which can hide underlying errors from Ghost.
  </Card>

  <Card title="Image upload issues" href="/faq/image-upload-issues/">
    Image uploads can be affected by the default max upload size of 50mb. If you need more, you’ll need to increase the limit by editing your nginx config file, and setting the limit manually.
  </Card>

  <Card title="Mail config error in Ghost with Google Cloud" href="/faq/mail-config-error-google-cloud/">
    There’s a known issue that Google Cloud Platform does NOT allow any traffic on port 25 on a [Compute Engine instance](https://cloud.google.com/compute/docs/tutorials/sending-mail/).
  </Card>

  <Card title="Major Versions & Long Term Support" href="/faq/major-versions-lts/">
    Major version release dates and end of life support for Ghost.
  </Card>

  <Card title="Missing newsletter analytics" href="/faq/missing-newsletter-analytics/">
    Open rates that are 0% may indicate that the connection between Ghost and Mailgun has stalled, which prevents Ghost from fetching your newsletter analytics.
  </Card>

  <Card title="Missing SSL protocol" href="/faq/missing-ssl-protocol/">
    After installing Ghost a url for your site is set. This is the URL people will use to access your publication.
  </Card>

  <Card title="Reverse proxying to Ghost" href="/faq/proxying-https-infinite-loops/">
    Ghost is designed to have a reverse proxy in front of it. If you use Ghost-CLI to install Ghost, this will be setup for you using nginx. If you configure your own proxy, you’ll need to make sure the proxy is configured correctly.
  </Card>

  <Card title="Root user permissions fix" href="/faq/root-user-fix/">
    A fix for root user permissions problems
  </Card>

  <Card title="Salt Incident Report: May 3rd, 2020" href="/faq/salt-incident/">
    Analysis and retrospective of the critical Salt vulnerability on Ghost(Pro)
  </Card>

  <Card title="Supported Node versions" href="/faq/node-versions/">
    Ghost’s current recommended Node version is Node v20 LTS.
  </Card>

  <Card title="Supported providers for self-hosting" href="/faq/supported-hosting-providers/">
    We recommend using Digital Ocean who provide a stable option on which Ghost can be installed and have a very active community and an official [**Ghost One-Click Application**](https://marketplace.digitalocean.com/apps/ghost).
  </Card>

  <Card title="Translation in Ghost" href="/faq/translation/">
    Creators from all over the world use Ghost. Publications abound in German, French, Spanish, Sinhalese, and Arabic—and the list keeps going!
  </Card>

  <Card title="Troubleshooting MySQL databases" href="/faq/troubleshooting-mysql-database/">
    If your MySQL database is not correctly configured for Ghost, then you may run into some issues.
  </Card>

  <Card title="Unable to open sqlite3 database file" href="/faq/unable-to-open-sqlite3-database-file/">
    If the sqlite3 database file is not readable or writable by the user running Ghost, then you’ll run into some errors.
  </Card>

  <Card title="Update from Ghost 0.x versions" href="/faq/update-0x/">
    If you’re running Ghost 0.x versions, your site must be updated to Ghost 1.0 before it can be successfully updated to Ghost 2.0 and beyond.
  </Card>

  <Card title="Updating from deprecated Ghost-CLI" href="/faq/upgrading-from-deprecated-ghost-cli/">
    When managing your self-hosted Ghost publication using the recommended `ghost-cli` tooling, you should update your CLI version. If you are using a deprecated version and need to update in order to update or manage your Ghost site, some extra steps may be required.
  </Card>

  <Card title="URL for tags and authors returns 404 errors" href="/faq/url-for-tags-and-authors-returns-404/">
    The tag and author taxonomies must be present in routes.yaml otherwise the URLs will not exist. By default, Ghost installs with the following:
  </Card>

  <Card title="Using Cloudflare with Ghost" href="/faq/using-cloudflare-with-ghost/">
    If you’ve added Cloudflare to your self-hosted Ghost publication and find that Ghost Admin doesn’t load after updates you may run into some errors in the JavaScript console:
  </Card>

  <Card title="Using nvm with local and production installs" href="/faq/using-nvm/">
    This guide explains how to use `nvm` with local and production Ghost installs.
  </Card>

  <Card title="What databases are supported in production?" href="/faq/supported-databases/">
    MySQL 8 is the only supported database in production.
  </Card>

  <Card title="Why do I have to set up Mailgun?" href="/faq/mailgun-newsletters/">
    Ghost has the ability to deliver posts as email newsletters natively. A bulk-mail provider is required to use this feature and SMTP cannot be used — read more about [mail config](/config/#mail).
  </Card>
</CardGroup>


# Ghost CLI
Source: https://docs.ghost.org/ghost-cli

A fully loaded tool to help you get Ghost installed and configured and to make it super easy to keep your Ghost install up to date.

***

Ghost-CLI is to makes it possible to install or update Ghost with a *single command*. In addition, it performs useful operations to assist with maintaining your environment, such as:

* Checking for common environment problems
* Creating a **logical folder structure**
* Providing for production or development installs
* Allowing for **upgrades and rollbacks**
* Handling **user management and permissions**
* Configuring Ghost
* Configuring **NGINX**
* Setting up **MySQL**
* Configuring **systemd**
* Accessing Ghost log files
* Managing existing Ghost installs

***

## Install & update

Ghost-CLI is an npm module that can be installed via either npm.

```bash  theme={"dark"}
# On a production server using a non-root user:
sudo npm install -g ghost-cli@latest
```

Locally, you likely don’t need sudo. Using `@latest` means this command with either install or update ghost-cli and you only have to remember the one command for both ✨

## Useful options

There are some global flags you may find useful when using `ghost-cli`:

```bash  theme={"dark"}
# Output usage information for Ghost-CLI
ghost --help, ghost -h, ghost help, ghost [command] --help

# Enables the verbose logging output for debugging
ghost --verbose, ghost -V

# Print your CLI version and Ghost version
ghost --version, ghost -v, ghost version

# Run the command in a different directory
ghost --dir path/to/directory

# Runs command without asking for any input
ghost --no-prompt

# Runs command without using colours
ghost --no-color
```

## Commands

Below are the available commands in Ghost-CLI. You can always run `ghost --help` or `ghost [command] --help` to get more detail, or inline help for available options.

### Ghost config

`ghost config` accepts two optional arguments: `key` and `value`. Here are the three different combinations and what happens on each of them:

```bash  theme={"dark"}
# Create a new config file for the particular env
ghost config

# Find and return the value in the config for the key passed
ghost config [key]

# Set a key and a value in the config file
ghost config [key] [value]

# Set the url for your site
ghost config url https://mysite.com
```

The `ghost config` command only affects the configuration files. In order for your new config to be used, run `ghost restart`.

#### Options

If you’re using `ghost config` to generate a configuration file, you can supply multiple key-value pairs in the form of options to avoid being prompted for that value.

All of these options can also be passed to `ghost install` and `ghost setup` , as these commands call `ghost config`.

See the [config guide](/config/) or run `ghost config --help` for more detailed information.

**Application options**

```bash  theme={"dark"}
# URL of the site including protocol
--url https://mysite.com

# Admin URL of the site
--admin-url https://admin.mysite.com

# Port that Ghost should listen on
--port 2368

# IP to listen on
--ip 127.0.0.1

# Transport to send log output to
--log ["file","stdout"]
```

**Database options**

```bash  theme={"dark"}
# Type of database to use (SQLite3 or MySQL)
--db

# For SQLite3 we just need a path to database file
--dbpath content/data/ghost_dev.db

# For MySQL we need full credentials:
--dbhost localhost

# Database user name
--dbuser ghost

# Database password
--dbpass ****

# Database name
--dbname ghost_dev
```

**Mail options**

```bash  theme={"dark"}
# Mail transport, E.g SMTP, Sendmail or Direct
--mail SMTP

# Mail service (used with SMTP transport), E.g. Mailgun, Sendgrid, Gmail, SES...
--mailservice Mailgun

# Mail auth user (used with SMTP transport)
--mailuser postmaster@something.mailgun.org

# Mail auth pass (used with SMTP transport)
--mailpass ****

# Mail host (used with SMTP transport)
--mailhost smtp.eu.mailgun.org

# Mail port (used with SMTP transport)
--mailport 465
```

**Service options**

```bash  theme={"dark"}
# Process manager to run with (local, systemd)
--process local
```

#### Debugging

In order for your new config to be used, run `ghost restart`.

***

### Ghost install

The `ghost install` command is your one-stop-shop to get a running production install of Ghost.

This command includes the necessary mysql, nginx and systemd configuration to get your publication online, and provides a series of setup questions to configure your new publication. The end result is a fully installed and configured instance ✨

<Note>
  Not ready for production yet? `ghost install local` installs ghost in development mode using sqlite3 and a local process manager. Read more about [local installs](/install/local/).
</Note>

#### How it works

The `ghost install` command runs a nested command structure, but you only ever have to enter a single command.

First, it will run `ghost doctor` to check your environment is compatible. If checks pass, a local folder is setup, and Ghost is then downloaded from npm and installed.

Next, `ghost setup` runs, which will provide [prompts](/install/ubuntu/#install-questions) for you to configure your new publication via the `ghost config` command, including creating a MySQL user, initialising a database, configure nginx and sets up SSL.

Finally, the CLI will prompt to see if you want to run Ghost and if you choose yes `ghost start` will run.

#### Arguments

```bash  theme={"dark"}
# Install a specific version (1.0.0 or higher)
ghost install [version]

# Install version 2.15.0
ghost install 2.15.0

# Install locally for development
ghost install local

# Install version 2.15.0, locally for development
ghost install 2.15.0 --local
```

#### Options

As `ghost install` runs nested commands, it also accepts options for the `ghost doctor`, `ghost config`, `ghost setup` and `ghost start` commands.

See the individual command docs, or run `ghost install --help` for more detailed information.

```bash  theme={"dark"}
# Get more information before running the command
ghost install --help

# Install in development mode for a staging env
ghost install --development, ghost install -D

# Select the directory to install Ghost in
ghost install --dir path/to/dir

# Install Ghost from a specific archive (useful for testing or custom builds)
ghost install --archive path/to/file.tgz

# Disable stack checks
ghost install --no-stack

# Install without running setup
ghost install --no-setup

# Install without starting Ghost
ghost install --no-start

# Tells the process manager not to restart Ghost on server reboot
ghost setup --no-enable

# Install without prompting (disable setup, or pass all required parameters as arguments)
ghost install --no-prompt
```

#### Directory structure

When you install Ghost using Ghost-CLI, the local directory will be setup with a set of folders designed to keep the various parts of your install separate. After installing Ghost, you will have a folder structure like this which should not be changed:

```bash  theme={"dark"}
.
├── .config.[env].json  # The config file for your Ghost instance
├── .ghost-cli          # Utility system file for Ghost CLI, don't modify
├── /content            # Themes/images/content, not changed during updates
├── /current            # A symlink to the currently active version of Ghost
├── /system             # NGINX/systemd/SSL files on production installs
└── /versions           # Installed versions of Ghost available roll forward/back to
```

***

### Ghost setup

`ghost setup` is the most useful feature of Ghost-CLI. In most cases you will never need to run it yourself, as it’s called automatically as a part of `ghost install`.

#### How it works

Setup configures your server ready for running Ghost in production. It assumes the [recommended stack](/install/ubuntu/#prerequisites/) and leaves your site in a production-ready state. Setup is broken down into stages:

* **mysql** - create a specific MySQL user that is used only for talking to Ghost’s database.
* **nginx** - creates an nginx configuration
* **ssl** - setup SSL with letsencrypt, using [acme.sh](https://github.com/Neilpang/acme.sh)
* **migrate** - initialises the database
* **linux-user** - creates a special low-privilege `ghost` user for running Ghost

#### What if I want to do something else?

The `Ghost-CLI` tool is designed to work with the recommended stack and is the only supported install method. However, since Ghost is a fully open-source project, and many users have different requirements, it is possible to setup and configure your site manually.

The CLI tool is flexible and each stage can be run individually by running `ghost setup <stage-name>` or skipped by passing the `--no-setup-<stage-name>` flag.

#### Arguments

```bash  theme={"dark"}
# Run ghost setup with specific stages
ghost setup [stages...]

# Creates a new mysql user with minimal privileges
ghost setup mysql

# Creates an nginx config file in `./system/files/` and adds a symlink to `/etc/nginx/sites-enabled/`
ghost setup nginx

# Creates an SSL service for Ghost
ghost setup ssl

# Create an nginx and ssl setup together
ghost setup nginx ssl

# Creates a low-privileged linux user called `ghost`
ghost setup linux-user

# Creates a systemd unit file for your site
ghost setup systemd

# Runs a database migration
ghost setup migrate
```

#### Options

As `ghost setup` runs nested commands, it also accepts options for the `ghost config`, `ghost start` and `ghost doctor` commands. Run `ghost setup --help` for more detailed information.

```bash  theme={"dark"}
# Skips a setup stage
ghost setup --no-setup-mysql
ghost setup --no-setup-nginx
ghost setup --no-setup-ssl
ghost setup --no-setup-systemd
ghost setup --no-setup-linux-user
ghost setup --no-setup-migrate

# Configure a custom process name should be (default: ghost-local)
ghost setup --pname my-process

# Disable stack checks
ghost setup --no-stack

# Setup without starting Ghost
ghost setup --no-start

# Tells the process manager not to restart Ghost on server reboot
ghost setup --no-enable

# Install without prompting (must pass all required parameters as arguments)
ghost setup --no-prompt
```

***

### Ghost start

Running `ghost start` will start your site in background using the configured process manager. The default process manager is **systemd**, or local for local installs.

The command must be executed in the directory where the Ghost instance you are trying to start lives, or passed the correct directory using the `--dir` option.

#### Options

```bash  theme={"dark"}
# Start running the Ghost instance in a specific directory
ghost start --dir /path/to/site/

# Start ghost in development mode
ghost start -D, ghost start --development

# Tells the process manager to restart Ghost on server reboot
ghost start --enable

# Tells the process manager not to restart Ghost on server reboot
ghost start --no-enable

# Disable memory availability checks in ghost doctor
ghost start --no-check-mem
```

#### Debugging

If running `ghost start` gives an error, try use `ghost run` to start Ghost without using the configured process manager. This runs Ghost directly, similar to `node index.js`. All the output from Ghost will be written directly to your terminal, showing up any uncaught errors or other output that might not appear in log files.

***

### Ghost stop

Running `ghost stop` stops the instance of Ghost running in the current directory. Alternatively it can be passed the name of a particular ghost instance or directory. You can always discover running Ghost instances using `ghost ls`.

#### Arguments

```bash  theme={"dark"}
# Stop Ghost in the current folder
ghost stop

# Stop a specific Ghost instance (use ghost ls to find the name)
ghost stop [name]

# Stop the Ghost instance called ghost-local
ghost stop ghost-local
```

#### Options

```bash  theme={"dark"}
# Stop all running Ghost instances
ghost stop --all

# Stop running the Ghost instance in a specific directory
ghost stop --dir /path/to/site/

# Tells the process manager that Ghost should not start on server reboot
ghost stop --disable
```

***

### Ghost restart

Running `ghost restart` will stop and then start your site using the configured process manager. The default process manager is systemd, or local for local installs.

The command must be executed in the directory where the Ghost instance you are trying to start lives, or passed the correct directory using the `--dir` option.

#### Options

```bash  theme={"dark"}
# Start running the Ghost instance in a specific directory
ghost restart --dir /path/to/site/
```

#### Debugging

If running `ghost restart` gives an error, try using `ghost run` to debug the error.

***

### Ghost update

Run `ghost update` to upgraded to new versions of Ghost, which are typically released every 1-2 weeks.

#### Arguments

```bash  theme={"dark"}
# Update to the latest version
ghost update

# Update to a specific version (1.0.0 or higher)
ghost update [version]

# Update to version 2.15.0
ghost update 2.15.0
```

#### Options

```bash  theme={"dark"}
# If an upgrade goes wrong, use the rollback flag
ghost update --rollback

# Install and re-download the latest version of Ghost
ghost update --force

# Force install a specific version of Ghost
ghost update [version] --force

# Updates to the latest within v1
ghost update --v1

# Don't restart after upgrading
ghost update --no-restart

# Disable the automatic rollback on failure
ghost update --no-auto-rollback

# Upgrade Ghost from a specific zip (useful for testing or custom builds)
ghost update --zip path/to/file.zip

# Disable memory availability checks in ghost doctor
ghost update --no-check-mem
```

#### Major updates

Every 12-18 months we release a [major version](/faq/major-versions-lts/) which breaks backwards compatibility and requires a more involved upgrade process, including backups and theme compatibility.

Use the [update documentation](/update/) as a guide to the necessary steps for a smooth upgrade experience.

#### Debugging

If running `ghost update` gives an error, try using `ghost run` to debug the error.

***

### Ghost backup

Run `ghost backup` to generate a zip file backup of your site data.

#### How it works

When performing manual updates it’s recommended to make frequent backups, so if anything goes wrong, you’ll still have all your data. This is especially important when [updating](/update/) to the latest major version.

This command creates a full backup of your site data, including:

* Your content in JSON format
* A full member CSV export
* All themes that have been installed including your current active theme
* Images, files, and media (video and audio)
* A copy of `routes.yaml` and `redirects.yaml` or `redirects.json`

Read more about how to [manually download your site data](/faq/manual-backup/).

***

### Ghost doctor

Running `ghost doctor` will check the system for potential hiccups when installing or updating Ghost.

This command allows you to use `ghost-cli` as a diagnostic tool to find potential issues for your Ghost install, and provides information about what needs to be resolved if any issues arise.

The CLI automatically runs this command when installing, updating, starting or setting up ghost - and you can use is manually with `ghost doctor`.

#### Arguments

```bash  theme={"dark"}
# Check is the required config file exists and validates it's values
ghost doctor startup

# Check if the setup process was successful
ghost doctor setup
```

#### Options

Run `ghost doctor --help` for more detailed information.

```bash  theme={"dark"}

# Disable the memory availability checks
ghost doctor --no-check-mem
```

***

### Ghost ls

The `ghost ls` command lists all Ghost sites and their status from the `~/.ghost/config` file. This is useful if you can’t remember where you installed a particular instance of Ghost, or are working with multiple instances (local, production, staging and so on).

#### Output

```bash  theme={"dark"}
# Development
> ghost ls

┌────────────────┬─────────────────────────────────┬─────────┬─────────────────────-─┬─────┬──────-┬─────────────────┐
│ Name           │ Location                        │ Version │ Status                │ URL │ Port  │ Process Manager │
├────────────────┼─────────────────────────────────┼─────────┼─────────────────────-─┼─────┼──────-┼─────────────────┤
│ ghost-local    │ ~/Sites/cli-test                │ 1.22.1  │ stopped               │ n/a │ n/a   │ n/a             │
├────────────────┼─────────────────────────────────┼─────────┼─────────────────────-─┼─────┼──────-┼─────────────────┤
│ ghost-local-2  │ ~/Sites/theme-dev               │ 2.12.0  │ stopped               │ n/a │ n/a   │ n/a             │
├────────────────┼─────────────────────────────────┼─────────┼─────────────────────-─┼─────┼──────-┼─────────────────┤
│ ghost-local-3  │ ~/Sites/new-theme               │ 2.20.0  │ running (development) │     │ 2368  │ local           │
└────────────────┴─────────────────────────────────┴─────────┴──────────────────────-┴─────┴─────-─┴─────────────────┘
```

```bash  theme={"dark"}
# Production
> ghost ls

+ sudo systemctl is-active ghost_my-ghost-site
┌───────────────┬────────────────┬─────────┬──────────────────────┬─────────────────────────--┬──────┬─────────────────┐
│ Name          │ Location       │ Version │ Status               │ URL                       │ Port │ Process Manager │
├───────────────┼────────────────┼─────────┼──────────────────────┼─────────────────────────--┼──────┼─────────────────┤
│ my-ghost-site │ /var/www/ghost │ 2.1.2   │ running (production) │ https://my-ghost-site.org │ 2368 │ systemd         │
└───────────────┴────────────────┴─────────┴──────────────────────┴─────────────────────────--┴──────┴─────────────────┘
```

***

### Ghost log

View the access and error logs from your Ghost site (not the CLI). By default `ghost log` outputs the last 20 lines from the access log file for the site in the current folder.

Ghost’s default log config creates log files in the `content/logs` directory, and creates two different files:

1. An **access log** that contains all log levels, named e.g. `[site_descriptor].log`
2. An **error log** that contains error-level logs *only*, named e.g. `[site_descriptor].error.log`

The site descriptor follows the pattern `[proto]__[url]__[env]` e.g. `http__localhost_2368__development` or `https__mysite_com__production`. The files are be rotated, therefore you may see many numbered files in the `content/logs` directory.

#### Arguments

```bash  theme={"dark"}
# View last 20 lines of access logs
ghost log

# View logs for a specific Ghost instance (use ghost ls to find the name)
ghost log [name]

# View logs for the Ghost instance called ghost-local
ghost log ghost-local
```

#### Options

```bash  theme={"dark"}
# Show 100 log lines
ghost log -n 100, ghost log --number 100

# Show only the error logs
ghost log -e, ghost log --error

# Show 50 lines of the error log
ghost log -n 50 -e

# Follow the logs (e.g like tail -f)
ghost log -f, ghost log --follow

# Follow the error log
ghost log -fe

# Show logs for the Ghost instance in a specific directory
ghost log --dir /path/to/site/
```

#### Debugging

There may be some output from Ghost that doesn’t appear in the log files, so for debugging purposes you may also want to try the [ghost run](/ghost-cli#ghost-run) command.

If you have a custom log configuration the `ghost log` command may not work for you. In particular the `ghost log` command requires that file logging is enabled. See the [logging configuration docs](/config/#logging) for more information.

***

### Ghost uninstall

**Use with caution** - this command completely removes a Ghost install along with all of its related data and config. There is no recovery from this if you have no backups.

The command `ghost uninstall` must be executed in the directory containing the Ghost install that you would like to remove. The following tasks are performed:

* stop ghost
* disable systemd if necessary
* remove the `content` folder
* remove any related systemd or nginx configuration
* remove the remaining files inside the install folder

<Note>
  Running `ghost uninstall --no-prompt` or `ghost uninstall --force` will skip the warning and remove Ghost without a prompt.
</Note>

***

### Ghost help

Use the help command to access a list of possible `ghost-cli` commands when required.

This command is your port of call when you want to discover a list of available commands in the Ghost-CLI. You can call it at any time ✨

#### Output

```bash  theme={"dark"}
Commands:
  ghost buster                 Who ya gonna call? (Runs `yarn cache clean`)
  ghost config [key] [value]   View or edit Ghost configuration
  ghost doctor [categories..]  Check the system for any potential hiccups when installing/updating
                               Ghost
  ghost install [version]      Install a brand new instance of Ghost
  ghost log [name]             View the logs of a Ghost instance
  ghost ls                     View running ghost processes
  ghost migrate                Run system migrations on a Ghost instance
  ghost restart                Restart the Ghost instance
  ghost run                    Run a Ghost instance directly (used by process managers and for
                               debugging)
  ghost setup [stages..]       Setup an installation of Ghost (after it is installed)
  ghost start                  Start an instance of Ghost
  ghost stop [name]            Stops an instance of Ghost
  ghost uninstall              Remove a Ghost instance and any related configuration files
  ghost update [version]       Update a Ghost instance
  ghost version                Prints out Ghost-CLI version (and Ghost version if one exists)

Global Options:
  --help             Show help                                                             [boolean]
  -d, --dir          Folder to run command in
  -D, --development  Run in development mode                                               [boolean]
  -V, --verbose      Enable verbose output                                                 [boolean]
  --prompt           [--no-prompt] Allow/Disallow UI prompting             [boolean] [default: true]
  --color            [--no-color] Allow/Disallow colorful logging          [boolean] [default: true]
  --auto             Automatically run as much as possible                [boolean] [default: false]
```

#### Options

It’s also possible to run `ghost install --help` and `ghost setup --help` to get a specific list of commands and help for the install and setup processes. Don’t worry - you got this! 💪

***

## Knowledgebase

### SSL

The CLI generates a free SSL certificate from [Let’s Encrypt](#lets-encrypt) using [acme.sh](#lets-encrypt) and a secondary NGINX config file to serve https traffic via port 443.

**SSL configuration**

After a successful ssl setup, you can find your ssl certificate in `/etc/letsencrypt`.

**SSL for additional domains**

You may wish to have multiple domains that redirect to your site, e.g. to have an extra TLD or to support [www](http://www). domains. **Ghost itself can only ever have one domain pointed at it.** This is intentional for SEO purposes, however you can always redirect extra domains to your Ghost install using nginx.

If you want to redirect an HTTPS domain, you must have a certificate for it. If you want to use Ghost-CLI to generate an extra SSL setup, follow this guide:

```bash  theme={"dark"}

# Determine your secondary URL
ghost config url https://my-second-domain.com

# Get Ghost-CLI to generate an SSL setup for you:
ghost setup nginx ssl

# Change your config back to your canonical domain
ghost config url https://my-canonical-domain.com

# Edit the nginx config files for your second domain to redirect to your canonical domain. In both files replace the content of the first location block with:
return 301 https://my-canonical-domain.com$request_uri;

# Get nginx to verify your config
sudo nginx -t

# Reload nginx with your new config
sudo nginx -s reload
```

**Let’s Encrypt**

[Let’s Encrypt](https://letsencrypt.org/) provides SSL certificates that are accepted by browsers free of charge! This is provided by the non-profit Internet Security Research Group (ISRG). The Ghost-CLI will offer you to generate a free SSL certificate as well as renew it every 60 days.

Ghost uses [acme.sh](https://github.com/Neilpang/acme.sh) for provisioning and renewing SSL certificates from Let’s Encrypt. You can call `acme.sh` manually if you need to perform extra tasks. The following command will output all available options:

```bash  theme={"dark"}
/etc/letsencrypt/acme.sh --home "/etc/letsencrypt"
```

### Systemd

`systemd` is the default way of starting and stopping applications on Ubuntu. The advantage is that if Ghost crashes, `systemd` will restart your instance. This is the default recommended process manager.

### Permissions

Ghost-CLI will create a new system user and user-group called `ghost` during the installation process. The `ghost` user will be used to run your Ghost process in `systemd`.

This means that Ghost will run with a user that has no system-wide permissions or a shell that can be used (similar to other services such as NGINX). Sudo is required to modify files in the The `<install-directory>/content/`.

To prevent accidental permissions changes, it’s advisable to execute tasks such as image upload or theme upload using Ghost admin.

#### File Permissions

The `ghost-cli` enforces default linux permissions (via `ghost doctor` hooks) for installations.

* For normal users, default directory permissions are 775, and default file permissions are 664.
* For root users, default directory permissions are 755, and default file permissions are 644.

Running ghost install as the non-root user will result in directories created with 775 (`drwxrwxr-x`) permissions and file with 664 (`-rw-rw-r--`) permissions.

These file permissions don’t need to be changed. The only change that is executed by ghost-cli is changing ownership, file permissions stay untouched.

If permissions were changed, the following two commands will revert file and directory permissions to the ones of a non-root user.

```bash  theme={"dark"}
sudo find /var/www/ghost/* -type d -exec chmod 775 {} \;
sudo find /var/www/ghost/* -type f -exec chmod 664 {} \;
```

The cli doesn’t support directory flags such as `setuid` and `setguid`). If your commands keep failing because of file permissions, ensure your directories have no flags!


# Hosting Ghost
Source: https://docs.ghost.org/hosting

A short guide to running Ghost in a production environment and setting up an independent publication to serve traffic at scale.

***

Ghost is open source software, and can be installed and maintained relatively easily on just about any VPS hosting provider. Additionally, we run an official PaaS for Ghost called [Ghost(Pro)](https://ghost.org/pricing/), where you can have a fully managed instance set up in a couple of clicks. All revenue from Ghost(Pro) goes toward funding the future development of Ghost itself, so by using our official hosting you’ll also be funding developers to continue to improve the core product for you.

## Ghost(Pro) vs self-hosting

A common question we get from developers is whether they should use our official platform, or host the codebase on their own server independently. Deciding which option is best for you comes with some nuance, so below is a breakdown of the differences to help you decide what will fit your needs best.

|                                  | **Ghost(Pro) official hosting** | **Self-hosting on your own server** |
| -------------------------------- | ------------------------------: | ----------------------------------: |
| **Product features**             |                       Identical |                           Identical |
| **Base hosting cost**            |                From **\$15**/mo |                    From **\$10**/mo |
| **Global CDN & WAF**             |                        Included |                    From **\$20**/mo |
| **Email newsletter delivery**    |                        Included |                    From **\$15**/mo |
| **Analytics platform**           |                        Included |                    From **\$10**/mo |
| **Full site backups**            |                        Included |                     From **\$5**/mo |
| **Image editor**                 |                        Included |                    From **\$12**/mo |
| **Payment processing fees**      |                              0% |                                  0% |
| **Install & setup**              |                               ✅ |                              Manual |
| **Weekly updates**               |                               ✅ |                              Manual |
| **Server maintenance & updates** |                               ✅ |                              Manual |
| **SSL certificate**              |                               ✅ |                              Manual |
| **24/7 on-call team**            |                               ✅ |                                   ❌ |
| **Enterprise-grade security**    |                               ✅ |                                   ❌ |
| **Ghost product support**        |                           Email |                               Forum |
| **Custom edge routing policies** |                               ❌ |                                   ✅ |
| **Direct SSH & DB access**       |                               ❌ |                                   ✅ |
| **Ability to modify core**       |                               ❌ |                                   ✅ |
| **Where the money goes**         |      New features<br />in Ghost |          Third-party<br />companies |

### Which option is best for me?

<Card title="Self-hosting" icon="server" color="#7db319" href="https://docs.ghost.org/install" cta="Self-hosting guide">
  Best for teams who are comfortable managing servers, and want full control over their environment. There’s more complexity involved, and you'll have to pay for your own email delivery, analytics and CDN — but ultimately there's more flexibility around exactly how the software runs.

  For heavy users of Ghost, self-hosting generally works out to be more expensive vs Ghost(Pro), but for lightweight blogs it can be cheaper.
</Card>

<Card title="Ghost(Pro)" icon="sparkles" color="#006bc2" href="https://ghost.org/pricing/" cta="See plans & pricing">
  Best for most people who are focused on using the Ghost software, and don’t want to spend time managing servers. Setting up a new Ghost site takes around 20 seconds. After that, all weekly updates, backups, security and performance are managed for you.

  If your site ever goes down, our team gets woken up while you sleep peacefully. In most cases Ghost(Pro) ends up being lower cost than self-hosting once you add up the cost of the different service providers.
</Card>

**TLDR:** If you're unsure: Ghost(Pro) is probably your best bet. If you have a technical team and you want maximum control and flexibility, you may get more out of self-hosting.

***

## Self-hosting details & configuration

Ghost has a [small team](/product/), so we optimize the software for a single, narrow, well-defined stack which is heavily tested. This is the same stack that we use on Ghost(Pro), so we can generally guarantee that it’s going to work well.

To date, we've achieved this with our custom [Ghost-CLI](/install/ubuntu) install tool and the following officially supported and recommended stack:

* Ubuntu 24
* Node.js 22 LTS
* MySQL 8.0
* NGINX
* Systemd
* A server with at least 1GB memory
* A non-root user for running `ghost` commands

Ghost *can* also run successfully with different operating systems, databases and web servers, but these are not officially supported or widely adopted, so your mileage may (will) vary.

### Social Web (ActivityPub) and Web Analytics (Tinybird)

In Ghost 6.0 we've launched two significant new features. To achieve this whilst keeping Ghost's core architecture maintainable, we've built them as separate services. These services are Open Source and can be self-hosted, however we are moving towards modern docker compose based tooling instead of updating Ghost CLI.

Anyone can use our Ghost(Pro) hosted ActivityPub service (up to the limits below), regardless of how you host Ghost. If you want to fully self-host the social web features or you want to self-host Ghost with the web analytics features you'll need to try out the [docker compose](/install/docker) based install method. This method is brand new and so we're calling it a preview.

[See self-hosting guides & instructions →](/install/)

#### Hosted ActivityPub Usage Limits

Self-hosters are free to use the hosted ActivityPub service, up to the following limits:

* 2000 max. followers
* 2000 max. following
* max. 100 interactions per day (interactions include: create a post/note, reply, like, repost)

If your usage exceeds this, you'll need to switch to self-hosting ActivityPub using [docker compose](/install/docker).

### Server hardening

After setting up a fresh Ubuntu install in production, it’s worth considering the following steps to make your new environment extra secure and resilient:

* **Use SSL** - Ghost should be configured to run over HTTPS. Ghost admin must be run over HTTPS.
* **Separate admin domain** - Configuring a separate [admin URL](/config/#admin-url) can help to guard against [privilege escalation](/security/#privilege-escalation-attacks) and reduces available attack vectors.
* **Secure MySQL** - We strongly recommend running `mysql_secure_installation` after successful setup to significantly improve the security of your database.
* **Set up a firewall** - Ubuntu servers can use the UFW firewall to make sure only connections to certain services are allowed. We recommend setting up UFW rules for `ssh`, `nginx`, `http`, and `https`. If you do use UFW, make sure you don’t use any other firewalls.
* **Disable SSH Root & password logins** - It’s a very good idea to disable SSH password based login and *only* connect to your server via proper SSH keys. It’s also a good idea to disable the root user.

### Optimizing for scale

The correct way to scale Ghost is by adding a CDN and caching layer in front of your Ghost instance. **Clustering or sharding is not supported.** Ghost easily scales to billions of requests per month as long as it has a solid cache.

### Staying up to date

Whenever running a public-facing production web server it’s critically important to keep all software up to date. If you don’t keep everything up to date, you place your site and your server at risk of numerous potential exploits and hacks.

If you can’t manage these things yourself, ensure that a systems administrator on your team is able to keep everything updated on your behalf.


# How To Install Ghost
Source: https://docs.ghost.org/install

The fastest way to get started is to set up a site on **Ghost(Pro)**. If you're running a self-hosted instance, we strongly recommend an Ubuntu server with at least 1GB of memory to run Ghost.

export const LocalInstallLogo = ({width = 40, height = 40}) => <svg version="1.0" xmlns="http://www.w3.org/2000/svg" width={width} height={height} viewBox="0 0 410 252" preserveAspectRatio="xMidYMid meet">

    <g transform="translate(0.000000,251.000000) scale(0.100000,-0.100000)" fill="currentColor" stroke="none">
      <path d="M592 2500 c-35 -8 -67 -32 -85 -65 -9 -15 -13 -312 -17 -1115 l-5
-1095 -237 -3 -238 -2 0 -63 c0 -60 2 -65 38 -99 20 -20 50 -42 66 -48 20 -7
611 -9 2060 -4 2217 7 2044 2 2109 62 24 23 27 32 27 94 l0 68 -240 0 -240 0
0 1075 c0 1189 3 1130 -64 1178 l-31 22 -1555 2 c-855 0 -1570 -2 -1588 -7z
m3088 -1150 l0 -990 -1520 0 -1520 0 0 990 0 990 1520 0 1520 0 0 -990z
m-1160 -1139 c0 -11 -7 -27 -16 -35 -13 -14 -59 -16 -348 -16 -351 0 -356 1
-356 47 l0 23 360 0 c349 0 360 -1 360 -19z" />
      <path d="M1460 1479 c-113 -71 -208 -129 -212 -129 -5 0 -8 -24 -8 -52 l0 -53
177 -110 c97 -60 194 -120 214 -133 l37 -22 23 36 c18 30 19 38 8 45 -8 5 -67
41 -132 81 -65 40 -135 83 -155 96 -20 12 -47 28 -60 34 -12 6 -21 16 -19 21
3 10 112 79 319 201 l66 39 -25 39 c-14 21 -26 38 -27 37 0 0 -93 -59 -206
-130z" fill="#3A9BFF" />
      <path d="M2620 1573 c-11 -20 -18 -38 -15 -42 4 -3 88 -56 188 -116 99 -61
182 -115 183 -120 2 -6 -27 -28 -64 -51 -37 -23 -121 -74 -187 -114 -66 -40
-122 -74 -123 -76 -2 -1 7 -18 20 -37 l24 -35 69 42 c39 24 108 67 155 96 47
29 111 69 143 88 l57 35 0 51 -1 51 -214 132 -214 131 -21 -35z" fill="#3A9BFF" />
    </g>
  </svg>;

export const GhostProLogo = ({width = 48, height = 32}) => <svg width={width} height={height} viewBox="0 0 214 114" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect width="214" height="114" rx="23" fill="url(#paint0_linear)" />
    <rect x="1.5" y="1.5" width="211" height="111" rx="21.5" stroke="black" strokeOpacity="0.06" strokeWidth="3" />
    <g filter="url(#filter0_d)">
      <path d="M42.8661 31.639C45.0221 31.2283 47.3835 30.9203 49.9501 30.715C52.5681 30.4583 55.1605 30.33 57.7271 30.33C60.3965 30.33 63.0658 30.561 65.7351 31.023C68.4558 31.4337 70.8941 32.3063 73.0501 33.641C75.2061 34.9243 76.9515 36.7467 78.2861 39.108C79.6721 41.418 80.3651 44.4467 80.3651 48.194C80.3651 51.4793 79.7748 54.3027 78.5941 56.664C77.4135 58.974 75.8478 60.899 73.8971 62.439C71.9465 63.9277 69.7135 65.0313 67.1981 65.75C64.7341 66.4173 62.1675 66.751 59.4981 66.751C59.2415 66.751 58.8308 66.751 58.2661 66.751C57.7015 66.751 57.1111 66.751 56.4951 66.751C55.8791 66.6997 55.2631 66.6483 54.6471 66.597C54.0825 66.5457 53.6718 66.4943 53.4151 66.443V85H42.8661V31.639ZM58.5741 39.416C57.5475 39.416 56.5721 39.4673 55.6481 39.57C54.7241 39.6213 53.9798 39.6983 53.4151 39.801V57.28C53.6205 57.3313 53.9285 57.3827 54.3391 57.434C54.7498 57.4853 55.1861 57.5367 55.6481 57.588C56.1101 57.588 56.5465 57.588 56.9571 57.588C57.4191 57.588 57.7528 57.588 57.9581 57.588C59.3441 57.588 60.7045 57.4597 62.0391 57.203C63.4251 56.9463 64.6571 56.4843 65.7351 55.817C66.8131 55.0983 67.6601 54.123 68.2761 52.891C68.9435 51.659 69.2771 50.042 69.2771 48.04C69.2771 46.346 68.9691 44.96 68.3531 43.882C67.7371 42.7527 66.9158 41.8543 65.8891 41.187C64.9138 40.5197 63.7845 40.0577 62.5011 39.801C61.2178 39.5443 59.9088 39.416 58.5741 39.416ZM88.189 31.639C89.3697 31.4337 90.6274 31.254 91.962 31.1C93.348 30.8947 94.7084 30.7407 96.043 30.638C97.429 30.5353 98.7637 30.4583 100.047 30.407C101.33 30.3557 102.511 30.33 103.589 30.33C106.104 30.33 108.568 30.5867 110.981 31.1C113.445 31.562 115.627 32.3833 117.526 33.564C119.477 34.7447 121.017 36.336 122.146 38.338C123.327 40.34 123.917 42.8297 123.917 45.807C123.917 48.0143 123.686 49.9393 123.224 51.582C122.813 53.1733 122.223 54.585 121.453 55.817C120.683 57.049 119.733 58.127 118.604 59.051C117.526 59.9237 116.345 60.7193 115.062 61.438L128.075 85H115.909L105.052 63.902H98.738V85H88.189V31.639ZM104.359 39.724C103.281 39.724 102.203 39.7497 101.125 39.801C100.098 39.8523 99.3027 39.955 98.738 40.109V55.74H102.896C105.822 55.74 108.209 55.0727 110.057 53.738C111.905 52.4033 112.829 50.196 112.829 47.116C112.829 44.806 112.11 43.0093 110.673 41.726C109.236 40.3913 107.131 39.724 104.359 39.724ZM132.357 58.05C132.357 53.6867 132.768 49.7597 133.589 46.269C134.41 42.7783 135.668 39.8523 137.362 37.491C139.056 35.0783 141.161 33.2303 143.676 31.947C146.243 30.6637 149.246 30.022 152.685 30.022C156.381 30.022 159.512 30.715 162.079 32.101C164.646 33.487 166.725 35.412 168.316 37.876C169.959 40.34 171.139 43.2917 171.858 46.731C172.628 50.1703 173.013 53.9433 173.013 58.05C173.013 66.828 171.319 73.7067 167.931 78.686C164.594 83.614 159.512 86.078 152.685 86.078C148.989 86.078 145.832 85.385 143.214 83.999C140.647 82.613 138.543 80.688 136.9 78.224C135.309 75.76 134.154 72.8083 133.435 69.369C132.716 65.9297 132.357 62.1567 132.357 58.05ZM143.445 58.05C143.445 60.668 143.548 63.1063 143.753 65.365C144.01 67.6237 144.446 69.6 145.062 71.294C145.729 72.9367 146.653 74.2457 147.834 75.221C149.066 76.1963 150.683 76.684 152.685 76.684C154.482 76.684 155.97 76.3247 157.151 75.606C158.332 74.836 159.281 73.681 160 72.141C160.719 70.601 161.206 68.676 161.463 66.366C161.771 64.0047 161.925 61.2327 161.925 58.05C161.925 55.5347 161.822 53.1477 161.617 50.889C161.463 48.6303 161.052 46.654 160.385 44.96C159.769 43.266 158.845 41.9313 157.613 40.956C156.381 39.9293 154.738 39.416 152.685 39.416C149.092 39.416 146.653 40.9817 145.37 44.113C144.087 47.2443 143.445 51.89 143.445 58.05Z" fill="white" />
    </g>
    <defs>
      <filter id="filter0_d" x="38.8662" y="28.022" width="138.147" height="64.056" filterUnits="userSpaceOnUse" colorInterpolationFilters="sRGB">
        <feFlood floodOpacity="0" result="BackgroundImageFix" />
        <feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0" />
        <feOffset dy="2" />
        <feGaussianBlur stdDeviation="2" />
        <feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0.1 0" />
        <feBlend mode="normal" in2="BackgroundImageFix" result="effect1_dropShadow" />
        <feBlend mode="normal" in="SourceGraphic" in2="effect1_dropShadow" result="shape" />
      </filter>
      <linearGradient id="paint0_linear" x1="151" y1="114" x2="66.3155" y2="-11.1289" gradientUnits="userSpaceOnUse">
        <stop stopColor="#009B7F" />
        <stop offset="1" stopColor="#60D20D" />
      </linearGradient>
    </defs>
  </svg>;

export const DockerLogo = ({width = 52, height = 29}) => <svg xmlns="http://www.w3.org/2000/svg" width={width} height={height} viewBox="0 0 256 145" fill="none">
    <path fill="#364548" fillRule="evenodd" d="M147.488 45.732h22.865v23.375h11.562c5.339 0 10.831-.951 15.887-2.664 2.485-.843 5.273-2.015 7.724-3.49-3.228-4.214-4.876-9.535-5.361-14.78-.659-7.135.78-16.421 5.609-22.005l2.404-2.78 2.864 2.302c7.211 5.794 13.276 13.89 14.345 23.119 8.683-2.554 18.878-1.95 26.531 2.467l3.14 1.812-1.652 3.226c-6.473 12.633-20.005 16.546-33.235 15.853-19.798 49.309-62.898 72.653-115.158 72.653-26.998 0-51.77-10.093-65.875-34.047l-.231-.391-2.055-4.181c-4.768-10.544-6.352-22.095-5.278-33.637l.323-3.457H51.45V45.732h22.865V22.866h45.733V0h27.44v45.732Z" clipRule="evenodd" />
    <path fill="#22A0C8" fillRule="evenodd" d="M221.57 54.38c1.533-11.916-7.384-21.275-12.914-25.719-6.373 7.368-7.363 26.678 2.635 34.808-5.579 4.956-17.337 9.448-29.376 9.448H35.37c-1.17 12.567 1.036 24.14 6.075 34.045l1.667 3.049a56.385 56.385 0 0 0 3.455 5.185c6.025.387 11.58.521 16.662.408h.002c9.987-.221 18.136-1.399 24.312-3.539.92-.32 1.921.168 2.24 1.086a1.762 1.762 0 0 1-1.088 2.24c-.82.285-1.677.551-2.561.804l-.003.001c-4.863 1.388-10.078 2.322-16.806 2.737.4.007-.416.06-.418.061-.229.014-.517.047-.747.059-2.648.149-5.506.18-8.428.18-3.196 0-6.343-.061-9.862-.239l-.09.059c12.21 13.724 31.302 21.955 55.234 21.955 50.648 0 93.608-22.452 112.631-72.857 13.497 1.385 26.468-2.057 32.368-13.575-9.398-5.423-21.484-3.694-28.443-.196Z" clipRule="evenodd" />
    <path fill="#37B1D9" fillRule="evenodd" d="M221.57 54.38c1.533-11.916-7.384-21.275-12.914-25.719-6.373 7.368-7.363 26.678 2.635 34.808-5.58 4.956-17.337 9.448-29.376 9.448H44.048c-.598 19.246 6.544 33.855 19.18 42.687h.003c9.987-.221 18.136-1.399 24.312-3.539.92-.32 1.921.168 2.24 1.086a1.762 1.762 0 0 1-1.088 2.24 48.61 48.61 0 0 1-2.561.804l-.004.001c-4.862 1.388-10.525 2.442-17.253 2.857-.002 0-.163-.155-.165-.155 17.236 8.842 42.23 8.81 70.885-2.197 32.131-12.344 62.029-35.86 82.89-62.757a25.44 25.44 0 0 0-.917.436Z" clipRule="evenodd" />
    <path fill="#1B81A5" fillRule="evenodd" d="M35.645 88.186c.91 6.732 2.88 13.035 5.8 18.777l1.667 3.048a56.289 56.289 0 0 0 3.455 5.185c6.026.387 11.581.521 16.664.408 9.987-.221 18.136-1.399 24.312-3.539a1.76 1.76 0 0 1 1.153 3.326 48.552 48.552 0 0 1-2.565.805c-4.863 1.388-10.496 2.382-17.224 2.798-.231.014-.634.017-.867.029-2.647.149-5.475.24-8.398.24-3.195 0-6.463-.061-9.98-.24 12.21 13.724 31.42 21.985 55.352 21.985 43.359 0 81.084-16.458 102.979-52.822H35.644Z" clipRule="evenodd" />
    <path fill="#1D91B4" fillRule="evenodd" d="M45.367 88.186c2.592 11.82 8.822 21.099 17.864 27.418 9.987-.221 18.136-1.399 24.312-3.539a1.76 1.76 0 0 1 1.153 3.326 48.61 48.61 0 0 1-2.562.804l-.003.001c-4.863 1.388-10.615 2.382-17.344 2.798 17.236 8.84 42.157 8.713 70.81-2.293 17.334-6.66 34.017-16.574 48.985-28.515H45.367Z" clipRule="evenodd" />
    <path fill="#23A3C2" fillRule="evenodd" d="M55.26 49.543h19.818v19.818H55.26V49.543Zm1.651 1.652h1.564V67.71h-1.564V51.195Zm2.94 0h1.627V67.71h-1.626V51.195Zm3.002 0h1.627V67.71h-1.627V51.195Zm3.004 0h1.626V67.71h-1.626V51.195Zm3.003 0h1.626V67.71H68.86V51.195Zm3.002 0h1.565V67.71h-1.565V51.195ZM78.126 26.677h19.819v19.817h-19.82V26.677Zm1.652 1.652h1.563v16.514h-1.563V28.329Zm2.94 0h1.626v16.514h-1.625V28.329Zm3.002 0h1.626v16.514H85.72V28.329Zm3.003 0h1.626v16.514h-1.626V28.329Zm3.003 0h1.627v16.514h-1.627V28.329Zm3.002 0h1.566v16.514h-1.566V28.329Z" clipRule="evenodd" />
    <path fill="#34BBDE" fillRule="evenodd" d="M78.126 49.543h19.819v19.818h-19.82V49.543Zm1.652 1.652h1.563V67.71h-1.563V51.195Zm2.94 0h1.626V67.71h-1.625V51.195Zm3.002 0h1.626V67.71H85.72V51.195Zm3.003 0h1.626V67.71h-1.626V51.195Zm3.003 0h1.627V67.71h-1.627V51.195Zm3.002 0h1.566V67.71h-1.566V51.195Z" clipRule="evenodd" />
    <path fill="#23A3C2" fillRule="evenodd" d="M100.992 49.543h19.818v19.818h-19.818V49.543Zm1.652 1.652h1.563V67.71h-1.563V51.195Zm2.94 0h1.626V67.71h-1.626V51.195Zm3.003 0h1.626V67.71h-1.626V51.195Zm3.003 0h1.626V67.71h-1.626V51.195Zm3.002 0h1.628V67.71h-1.628V51.195Zm3.003 0h1.564V67.71h-1.564V51.195Z" clipRule="evenodd" />
    <path fill="#34BBDE" fillRule="evenodd" d="M100.992 26.677h19.818v19.817h-19.818V26.677Zm1.652 1.652h1.563v16.514h-1.563V28.329Zm2.94 0h1.626v16.514h-1.626V28.329Zm3.003 0h1.626v16.514h-1.626V28.329Zm3.003 0h1.626v16.514h-1.626V28.329Zm3.002 0h1.628v16.514h-1.628V28.329Zm3.003 0h1.564v16.514h-1.564V28.329ZM123.859 49.543h19.818v19.818h-19.818V49.543Zm1.652 1.652h1.563V67.71h-1.563V51.195Zm2.94 0h1.627V67.71h-1.627V51.195Zm3.002 0h1.626V67.71h-1.626V51.195Zm3.003 0h1.627V67.71h-1.627V51.195Zm3.003 0h1.627V67.71h-1.627V51.195Zm3.003 0h1.564V67.71h-1.564V51.195Z" clipRule="evenodd" />
    <path fill="#23A3C2" fillRule="evenodd" d="M123.859 26.677h19.818v19.817h-19.818V26.677Zm1.652 1.652h1.563v16.514h-1.563V28.329Zm2.94 0h1.627v16.514h-1.627V28.329Zm3.002 0h1.626v16.514h-1.626V28.329Zm3.003 0h1.627v16.514h-1.627V28.329Zm3.003 0h1.627v16.514h-1.627V28.329Zm3.003 0h1.564v16.514h-1.564V28.329Z" clipRule="evenodd" />
    <path fill="#34BBDE" fillRule="evenodd" d="M123.859 3.81h19.818V23.63h-19.818V3.81Zm1.652 1.651h1.563v16.516h-1.563V5.46Zm2.94 0h1.627v16.516h-1.627V5.46Zm3.002 0h1.626v16.516h-1.626V5.46Zm3.003 0h1.627v16.516h-1.627V5.46Zm3.003 0h1.627v16.516h-1.627V5.46Zm3.003 0h1.564v16.516h-1.564V5.46Z" clipRule="evenodd" />
    <path fill="#23A3C2" fillRule="evenodd" d="M146.725 49.543h19.818v19.818h-19.818V49.543Zm1.65 1.652h1.565V67.71h-1.565V51.195Zm2.941 0h1.626V67.71h-1.626V51.195Zm3.003 0h1.627V67.71h-1.627V51.195Zm3.002 0h1.627V67.71h-1.627V51.195Zm3.004 0h1.626V67.71h-1.626V51.195Zm3.002 0h1.564V67.71h-1.564V51.195Z" clipRule="evenodd" />
    <path fill="#D3ECEC" fillRule="evenodd" d="M96.704 101.492a5.467 5.467 0 1 1-.002 10.934 5.467 5.467 0 0 1 .002-10.934Z" clipRule="evenodd" />
    <path fill="#364548" fillRule="evenodd" d="M96.704 103.043c.5 0 .977.094 1.417.265a1.598 1.598 0 1 0 2.2 2.149 3.915 3.915 0 1 1-3.617-2.414ZM0 90.162h254.327c-5.537-1.404-17.521-3.302-15.544-10.56-10.07 11.652-34.353 8.175-40.482 2.43-6.824 9.898-46.554 6.135-49.325-1.576-8.556 10.041-35.067 10.041-43.623 0-2.773 7.711-42.502 11.474-49.327 1.575-6.129 5.746-30.41 9.223-40.48-2.428C17.522 86.86 5.539 88.758 0 90.163Z" clipRule="evenodd" />
    <path fill="#BDD9D7" fillRule="evenodd" d="M111.237 140.89c-13.54-6.425-20.971-15.159-25.106-24.694-5.03 1.435-11.075 2.353-18.1 2.747-2.646.148-5.43.224-8.35.224-3.368 0-6.917-.099-10.642-.297 12.416 12.409 27.692 21.964 55.975 22.138 2.088 0 4.161-.04 6.223-.118Z" clipRule="evenodd" />
    <path fill="#D3ECEC" fillRule="evenodd" d="M91.16 124.994c-1.873-2.543-3.69-5.739-5.026-8.799-5.03 1.436-11.077 2.354-18.103 2.748 4.826 2.62 11.727 5.047 23.13 6.051Z" clipRule="evenodd" />
  </svg>;

export const LinodeLogo = ({width = 32, height = 32}) => <svg height={height} viewBox="0 0 32 32" width={width} xmlns="http://www.w3.org/2000/svg">
    <path d="m9.545 14.42-1.2-8.258-4.975-3.088 1.612 7.8 4.562 3.556zm1.38 9.443-.852-5.823-4.356-3.63 1.17 5.648 4.038 3.804zm-3.383-.64.862 4.165 3.596 3.817-.614-4.205-3.842-3.78zm11.644-1.806-1.837-1.402.014.33a.19.19 0 0 1 -.084.166l-1.386.934 1.507 1.23c.02.02.03.027.035.036l.022.042c.008.027.01.037.01.048l.064 1.45 1.7 1.423-.036-4.26zm6.3-4.507-.36 4.153-1.2-.828.13-2.118c0-.024-.002-.033-.003-.04-.006-.032-.012-.046-.02-.06s-.02-.028-.032-.04a.23.23 0 0 0 -.032-.028l-2.56-1.69.037-1.856 4.03 2.51" fill="#123d10" />
    <path d="m16.59 11.116-.335-7.84-7.53 2.894 1.23 8.4 6.635-3.453zm.4 9.135-.246-5.78-6.27 3.57.88 6.01 5.638-3.798zm.127 2.93-5.333 3.816.648 4.422 4.872-3.88-.186-4.357zm2.465-1.762.036 4.275 3.8-3.032.253-4.17-4.1 2.926zm9.48-6.782-.534 3.955-2.998 2.4.352-4.068 3.18-2.276" fill="#33b652" />
    <path d="m17.472 22.812-.008-.042a.21.21 0 0 0 -.019-.044c-.015-.024-.023-.032-.03-.04l-1.52-1.24 1.386-.934a.19.19 0 0 0 .084-.166l-.014-.33 1.837 1.402.036 4.26-1.7-1.423-.062-1.44zm-7.398-4.772.852 5.823-4.038-3.804-1.17-5.648 4.356 3.63zm6.904 2.212-5.638 3.798-.88-6.01 6.27-3.57.246 5.78zm-.725-16.975.335 7.84-6.635 3.453-1.23-8.4 7.53-2.894zm-7.918 2.883 1.2 8.258-4.562-3.556-1.612-7.8zm.07 21.225-.862-4.165 3.843 3.78.615 4.203-3.596-3.817zm8.885.152-4.872 3.88-.648-4.422 5.333-3.816.186 4.357zm6.116-4.876-3.8 3.032-.036-4.275 4.1-2.926-.253 4.17zm.53-2.428.13-2.118c0-.024-.002-.033-.003-.04-.006-.032-.012-.046-.02-.06s-.02-.028-.032-.04a.23.23 0 0 0 -.032-.028l-2.56-1.69.037-1.856 4.03 2.51-.36 4.153-1.2-.828zm1.58.747.352-4.068 3.18-2.276-.534 3.955-2.998 2.4zm3.97-6.77-.006-.03c-.002-.01-.006-.02-.01-.03a.23.23 0 0 0 -.027-.045c-.02-.023-.03-.03-.04-.038l-4.368-2.42c-.06-.033-.133-.032-.192.008l-3.674 2.246c-.006 0-.01.01-.016.013s-.013.01-.02.015l-.016.02c-.005.008-.01.01-.014.018s-.008.017-.01.026-.006.013-.008.02-.003.02-.004.03l-.042 1.97-1.494-.987c-.062-.04-.142-.042-.205 0l-2.15 1.314-.093-2.186-.007-.042c-.002-.008-.004-.013-.007-.02a.19.19 0 0 0 -.011-.024c-.004-.008-.008-.013-.013-.02s-.01-.013-.015-.02-.012-.01-.02-.016l-2.25-1.514 2.094-1.1c.066-.034.106-.104.103-.178l-.352-8.228c-.001-.01-.003-.02-.005-.03-.006-.03-.013-.045-.022-.06s-.022-.03-.032-.04c-.017-.017-.022-.02-.028-.024-.017-.008-.02-.008-.022-.015l-5.637-2.708a.19.19 0 0 0 -.14-.011l-7.697 2.398-.05.028-.04.037c-.006.008-.01.015-.014.023s-.01.015-.013.024-.006.02-.01.03c-.006.03-.005.04-.005.05s0 .018.001.027l1.718 8.302c.01.044.034.084.07.112l2.33 1.817-1.685.802c-.02.008-.022.015-.026.016l-.027.023c-.022.024-.028.036-.034.047-.014.028-.02.045-.02.062a.24.24 0 0 0 .002.055l1.292 6.25a.19.19 0 0 0 .056.1l1.622 1.528-1.075.658c-.014.008-.026.02-.038.03-.017.02-.025.033-.032.045a.22.22 0 0 0 -.021.065c-.002.018-.001.036.003.055l1 4.842c.007.034.024.066.048.092l4.048 4.298c.006.008.013.01.02.017.02.017.033.024.047.03.027.008.05.013.072.013s.038 0 .056-.01.022-.008.027-.015c.008 0 .014-.01.02-.014l5.223-4.157c.048-.04.074-.097.072-.157l-.122-2.85 1.74 1.464c.02.015.03.023.04.028s.02.008.025.015c.02.008.038.01.057.01s.037-.008.056-.01c.017-.008.022-.008.026-.015.01-.008.017-.01.026-.017l4.186-3.337c.043-.034.068-.084.072-.138l.127-2.09 1.27.884c.012.008.015.015.02.015.007.008.015.008.023.01.033.015.05.015.067.015s.038 0 .056-.01.02-.008.026-.015c.01-.008.02-.012.03-.018l3.415-2.722c.04-.03.064-.076.07-.124l.604-4.47.001-.037" fill="#231f20" />
  </svg>;

export const DigitalOceanLogo = ({width = 32, height = 32}) => <svg xmlns="http://www.w3.org/2000/svg" height={height} width={width} viewBox="0 0 512 512">
    <rect width="512" height="512" rx="15%" fill="#0080ff" />
    <path fill="#fff" d="M78 373v-47h47v104h57V300h74v147A191 191 0 1 0 65 256h74a117 117 0 1 1 117 117" />
  </svg>;

export const SourceLogo = ({width = 32, height = 32}) => <svg viewBox="0 0 52 52" xmlns="http://www.w3.org/2000/svg" width={width} height={height}>
    <path d="m170.5 21c3.03 0 5.5 2.467 5.5 5.5v41c0 3.03-2.468 5.5-5.5 5.5h-41c-3.03 0-5.5-2.467-5.5-5.5v-41c0-3.03 2.468-5.5 5.5-5.5h41m2.5 46.5v-41c0-1.378-1.121-2.5-2.5-2.5h-41c-1.379 0-2.5 1.122-2.5 2.5v41c0 1.378 1.121 2.5 2.5 2.5h41c1.379 0 2.5-1.122 2.5-2.5m-30.76-29.4l7.84 7.84c.586.585.586 1.535 0 2.121l-7.84 7.84c-.293.293-.677.439-1.061.439-.383 0-.767-.146-1.06-.439-.586-.586-.586-1.536 0-2.121l6.779-6.78-6.779-6.779c-.586-.585-.586-1.536 0-2.121.586-.586 1.535-.586 2.121 0m16.58 15.24c.828 0 1.5.671 1.5 1.5 0 .829-.672 1.5-1.5 1.5h-5.88c-.828 0-1.5-.671-1.5-1.5 0-.829.672-1.5 1.5-1.5h5.88" transform="translate(-124-21)" />
  </svg>;

export const UbuntuLogo = ({width = 32, height = 32}) => <svg width={width} height={height} viewBox="0 0 285 285" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M284.331 142.595C284.331 220.874 220.881 284.33 142.602 284.33C64.323 284.33 0.866943 220.874 0.866943 142.595C0.866943 64.321 64.324 0.867004 142.602 0.867004C220.881 0.867004 284.331 64.32 284.331 142.595Z" fill="#E95420" />
    <path d="M69.043 142.595C69.043 152.659 60.884 160.82 50.813 160.82C40.754 160.82 32.595 152.66 32.595 142.595C32.595 132.535 40.754 124.376 50.813 124.376C60.884 124.376 69.043 132.535 69.043 142.595ZM172.717 231.201C177.75 239.91 188.89 242.897 197.606 237.871C206.321 232.838 209.307 221.692 204.275 212.976C199.243 204.261 188.102 201.281 179.387 206.313C170.671 211.346 167.685 222.486 172.717 231.201ZM204.274 72.219C209.306 63.502 206.326 52.359 197.605 47.332C188.895 42.3 177.75 45.286 172.716 53.999C167.684 62.714 170.67 73.856 179.386 78.888C188.102 83.92 199.248 80.934 204.274 72.219ZM142.602 90.632C169.755 90.632 192.036 111.446 194.363 137.996L220.735 137.58C219.483 117.853 210.926 100.111 197.74 87.029C190.76 89.722 182.661 89.356 175.674 85.319C168.682 81.282 164.315 74.448 163.16 67.044C156.606 65.264 149.712 64.311 142.602 64.311C130.131 64.311 118.343 67.227 107.875 72.414L120.707 95.457C127.357 92.367 134.784 90.632 142.602 90.632ZM90.633 142.595C90.633 125.018 99.367 109.474 112.73 100.075L99.19 77.441C83.506 87.915 71.823 103.892 66.894 122.624C72.727 127.321 76.464 134.521 76.464 142.596C76.464 150.676 72.726 157.876 66.894 162.574C71.823 181.305 83.506 197.282 99.19 207.762L112.73 185.128C99.367 175.722 90.633 160.184 90.633 142.595ZM142.602 194.568C134.785 194.568 127.358 192.834 120.707 189.738L107.875 212.781C118.343 217.972 130.13 220.885 142.602 220.885C149.711 220.885 156.606 219.939 163.16 218.156C164.314 210.747 168.681 203.913 175.674 199.883C182.661 195.846 190.76 195.479 197.74 198.172C210.927 185.084 219.483 167.342 220.735 147.615L194.363 147.206C192.035 173.749 169.755 194.568 142.602 194.568Z" fill="white" />
  </svg>;

***

<CardGroup cols={2}>
  <Card title="Ubuntu" href="/install/ubuntu/" icon={<UbuntuLogo />}>
    Ghost CLI
  </Card>

  <Card title="Docker (preview)" href="/install/docker/" icon={<DockerLogo />}>
    Docker compose
  </Card>

  <Card title="Local install" href="/install/local/" icon={<LocalInstallLogo />}>
    MacOS, Windows & Linux
  </Card>

  <Card title="Install from source" href="/install/source/" icon={<SourceLogo />}>
    For working on Ghost Core
  </Card>
</CardGroup>

## Cloud hosting

<CardGroup cols={3}>
  <Card title="Ghost(Pro)" href="https://ghost.org/pricing/" icon={<GhostProLogo />}>
    Official managed hosting
  </Card>

  <Card title="Digital Ocean" href="/install/digitalocean/" icon={<DigitalOceanLogo />}>
    Pre-built VPS image
  </Card>

  <Card title="Linode" href="/install/linode/" icon={<LinodeLogo />}>
    Virtual private servers
  </Card>
</CardGroup>


# Introduction
Source: https://docs.ghost.org/introduction

Ghost is an open source, professional publishing platform built on a modern Node.js technology stack — designed for teams who need power, flexibility and performance.

Hitting the right balance of needs has led Ghost to be used in production by organisations including Apple, Sky News, DuckDuckGo, Mozilla, Kickstarter, Square, Cloudflare, Tinder, the Bitcoin Foundation and [many more](https://ghost.org/explore/).

Every day Ghost powers some of the most-read stories on the internet, serving hundreds of millions of requests across tens of thousands of sites.

## How is Ghost different?

The first question most people have is, of course, how is Ghost different from everything else out there? Here’s a table to give you a quick summary:

|                                                              | Ghost <br />(That's us!) | Open platforms <br />(eg. WordPress) | Closed platforms <br />(eg. Substack) |
| ------------------------------------------------------------ | ------------------------ | ------------------------------------ | ------------------------------------- |
| 🏎 Exceptionally fast                                        | ✅                        | ❌                                    | ✅                                     |
| 🔒 Reliably secure                                           | ✅                        | ❌                                    | ✅                                     |
| 🎨 Great design                                              | ✅                        | ❌                                    | ✅                                     |
| 🚀 Modern technology                                         | ✅                        | ❌                                    | ✅                                     |
| 💌 Newsletters built-in                                      | ✅                        | ❌                                    | ✅                                     |
| 🛒 Memberships & paid subscriptions                          | ✅                        | ❌                                    | ✅                                     |
| ♻️ Open Source                                               | ✅                        | ✅                                    | ❌                                     |
| 🏰 Own your brand+data                                       | ✅                        | ✅                                    | ❌                                     |
| 🌍 Use a custom domain                                       | ✅                        | ✅                                    | ❌                                     |
| 🖼 Control your site design                                  | ✅                        | ✅                                    | ❌                                     |
| 💸 0% transaction fees on payments                           | ✅                        | ❌                                    | ❌                                     |
| ⭐️ Built-in SEO features                                     | ✅                        | ❌                                    | ❌                                     |
| 🚀 Native REST API                                           | ✅                        | ❌                                    | ❌                                     |
| ❤️ Non-profit organisation with a sustainable business model | ✅                        | ❌                                    | ❌                                     |

**In short:** Other open platforms are generally old, slow and bloated, while other closed platforms give you absolutely no control or ownership of your content. Ghost provides the best of both worlds, and more.

## Background

Ghost was created by [John O’Nolan](https://twitter.com/johnonolan) and [Hannah Wolfe](https://twitter.com/erisds) in 2013 following a runaway Kickstarter campaign to create a new, modern publishing platform to serve professional publishers.

Previously, John was a core contributor of WordPress and watched as the platform grew more complicated and less focused over time. Ghost started out as a little idea to be the antidote to that pain, and quickly grew in popularity as the demand for a modern open source solution became evident.

Today, Ghost is one of the most popular open source projects in the world - the **#1** CMS [on GitHub](https://github.com/tryghost/ghost) - and is used in production by millions of people.

More than anything, we approach building Ghost to create the product we’ve always wanted to use, the company we’ve always wanted to do business with, and the environment we’ve always wanted to work in.

So, we do things a little differently to most others:

#### Independent structure

Ghost is structured as a [non-profit organisation](https://ghost.org/about/) to ensure it can legally never be sold and will always remain independent, building products based on the needs of its users - *not* the whims of investors looking for 💰 returns.

#### Sustainable business

While the software we release is free, we also sell [premium managed hosting](https://ghost.org/pricing/) for it, which gives the non-profit organisation a sustainable business model and allows it to be 100% self-funded.

#### Distributed team

Having a sustainable business allows us to hire open source contributors to work on Ghost full-time, and we do this [entirely remotely](https://ghost.org/about/#careers). The core Ghost team is fully distributed and live wherever they choose.

#### Transparent by default

We share [our revenue](https://ghost.org/about/) transparently and [our code](https://github.com/tryghost) openly so anyone can verify what we do and how we do it. No cloaks or daggers.

#### Unconditional open source

All our projects are released under the permissive open source [MIT licence](https://en.wikipedia.org/wiki/MIT_License), so that even if the company were to fail, our code could still be picked up and carried on by anyone in the world without restriction.

## Features

Ghost comes with powerful features built directly into the core software which can be customised and configured based on the needs of each individual site.

Here’s a quick overview of the main features you’ll probably be interested in as you’re getting started. This isn’t an exhaustive list, just some highlights.

### Built-in memberships & subscriptions

Don’t just create content for anonymous visitors, Ghost lets you turn your audience into a business with native support for member signups and paid subscription commerce. It’s the only platform with memberships built in by default, and deeply integrated.

Check out our [membership guide](/members/) for more details.

### Developer-friendly API

At its core Ghost is a self-consuming, RESTful JSON API with decoupled admin client and front-end. We provide lots of tooling to get a site running as quickly as possible, but at the end of the day it’s **Just JSON** ™️, so if you want to use Ghost completely headless and write your own frontend or backend… you can!

Equally, Ghost is heavily designed for performance. There are 2-5 frontpage stories on HackerNews at any given time that are served by Ghost. It handles scale with ease and doesn’t fall over as a result of traffic spikes.

### A serious editor

Ghost has the rich editor that every writer wants, but under the hood it delivers far more power than you would expect. All content is stored in a standardised JSON-based document storage format called Lexical, which includes support for extensible rich media objects called Cards.

In simple terms you can think of it like having Slack integrations inside Medium’s editor, stored sanely and fully accessible via API.

### Custom site structures

Routing in Ghost is completely configurable based on your needs. Out of the box Ghost comes with a standard reverse chronological feed of posts with clean permalinks and basic pages, but that’s easy to change.

Whether you need a full **multi-language site** with `/en/` and `/de/` base URLs, or you want to build out specific directory structures for hierarchical data like `/europe/uk/london/` — Ghost’s routing layer can be manipulated in any number of ways to achieve your use case.

### Roles & permissions

Set up your site with sensible user roles and permissions built-in from the start.

* **Contributors:** Can log in and write posts, but cannot publish.
* **Authors:** Can create and publish new posts and tags.
* **Editors:** Can invite, manage and edit authors and contributors.
* **Administrators:** Have full permissions to edit all data and settings.
* **Owner:** An admin who cannot be deleted + has access to billing details.

### Custom themes

Ghost ships with a simple Handlebars.js front-end theme layer which is very straightforward to work with and surprisingly powerful. Many people stick with the default theme ([live demo](https://demo.ghost.io) / [source code](https://github.com/tryghost/casper)), which provides a clean magazine design - but this can be modified or entirely replaced.

The Ghost [Theme Marketplace](https://ghost.org/marketplace/) provides a selection of pre-made third-party themes which can be installed with ease. Of course you can also build your own [Handlebars Theme](/themes/) or use a [different front-end](/content-api/) altogether.

### Apps & integrations

Because Ghost is completely open source, built as a JSON API, has webhooks, and gives you full control over the front-end: It essentially integrates with absolutely everything. Some things are easier than others, but almost anything is possible with a little elbow grease. Or a metaphor more recent than 1803.

You can browse our large [directory of integrations](https://ghost.org/integrations/) with instructions, or build any manner of custom integration yourself by writing a little JavaScript and Markup to do whatever you want.

You don’t need janky broken plugins which slow your site down. Integrations are the modern way to achieve extended functionality with ease.

### Search engine optimisation

Ghost comes with world-class SEO and everything you need to ensure that your content shows up in search indexes quickly and consistently.

**No plugins needed**

Ghost has all the fundamental technical SEO optimisations built directly into core, without any need to rely on third party plugins. It also has a far superior speed and pageload performance thanks to Node.js.

**Automatic google XML sitemaps**

Ghost will automatically generate and link to a complete Google sitemap including every page on your site, to make sure search engines are able to index every URL.

**Automatic structured data + JSON-LD**

Ghost generates [JSON-LD](https://developers.google.com/search/docs/guides/intro-structured-data) based structured metadata about your pages so that you don’t have to rely on messy microformats in your markup to provide semantic context. Even if you change theme or front-end, your SEO remains perfectly intact. Ghost also adds automatic code for Facebook OpenGraph and Twitter Cards.

**Canonical tags**

Ghost automatically generates the correct `rel="canonical"` tag for each post and page so that search engines always prioritise one true link.


# Ghost On The JAMstack
Source: https://docs.ghost.org/jamstack

How to use Ghost as a headless CMS with popular static site generators

export const EleventyLogo = ({width = 32, height = 32}) => <svg viewBox="0 0 1569.4 2186" xmlns="http://www.w3.org/2000/svg" width={width} height={height}>
    <rect x="-5%" width="110%" height="100%" fill="#222" />
    <g fill="#fff" stroke="#fff" strokeMiterlimit="10" strokeWidth="28">
      <path d="m562.2 1410.1c-9 0-13.5-12-13.5-36.1v-595.1c0-11.5-2.3-16.9-7-16.2-28.4 7.2-42.7 10.8-43.1 10.8-7.9.7-11.8-7.2-11.8-23.7v-51.7c0-14.3 4.3-22.4 12.9-24.2l142.2-36.6c1.1-.3 2.7-.5 4.8-.5 7.9 0 11.8 8.4 11.8 25.3v712c0 24.1-4.7 36.1-14 36.1zm368.3 1.1c-14.4 0-26.8-1-37.4-3s-21.6-6.5-33.1-13.5-20.9-16.6-28.3-28.8-13.4-29.3-18-51.2-7-47.9-7-78.1v-276.2c0-7.2-2-10.8-5.9-10.8h-33.4c-9 0-13.5-8.6-13.5-25.8v-29.1c0-17.6 4.5-26.4 13.5-26.4h33.4c3.9 0 5.9-4.8 5.9-14.5l9.7-209.5c1.1-19 5.7-28.5 14-28.5h53.9c9 0 13.5 9.5 13.5 28.5v209.5c0 9.7 2.1 14.5 6.5 14.5h68.7c9 0 13.5 8.8 13.5 26.4v29.1c0 17.2-4.5 25.8-13.5 25.8h-68.9c-2.5 0-4.2.6-5.1 1.9-.9 1.2-1.3 4.2-1.3 8.9v277.9c0 20.8 1.3 38.2 4 52s6.6 24 11.8 30.4 10.4 10.8 15.6 12.9c5.2 2.2 11.6 3.2 19.1 3.2h38.2c9.7 0 14.5 6.7 14.5 19.9v32.3c0 14.7-5.2 22.1-15.6 22.1zm206.7 64.6c8.2 0 15.4-6.7 21.5-20.2s9.2-32.6 9.2-57.4c0-5.8-3.6-25.7-10.8-59.8l-105.6-438.9c-.7-5-1.1-9-1.1-11.9 0-12.9 2.7-19.4 8.1-19.4h65.2c5 0 9.1 1.7 12.4 5.1s5.8 10.3 7.5 20.7l70 370.5c1.4 4.3 2.3 6.5 2.7 6.5 1.4 0 2.2-2 2.2-5.9l54.9-369.5c1.4-10.8 3.7-18 6.7-21.8s6.9-5.7 11.6-5.7h45.2c6.1 0 9.2 7 9.2 21 0 3.2-.4 7.4-1.1 12.4l-95.9 499.3c-7.5 41.3-15.8 72.9-24.8 94.8s-19 36.8-30.2 44.7c-11.1 7.9-25.8 12-44.2 12.4h-5.4c-29.1 0-48.8-7.7-59.2-23.2-2.9-3.2-4.3-11.5-4.3-24.8 0-26.6 4.3-39.9 12.9-39.9.7 0 7.2 1.8 19.4 5.4 12.4 3.8 20.3 5.6 23.9 5.6z"></path>
      <path d="m291.2 1411.1c-9 0-13.5-12-13.5-36.1v-595.1c0-11.5-2.3-16.9-7-16.2-28.4 7.2-42.7 10.8-43.1 10.8-7.9.7-11.8-7.2-11.8-23.7v-51.7c0-14.3 4.3-22.4 12.9-24.2l142.3-36.7c1.1-.3 2.7-.5 4.8-.5 7.9 0 11.8 8.4 11.8 25.3v712c0 24.1-4.7 36.1-14 36.1z"></path>
    </g>
  </svg>;

export const GridsomeLogo = ({width = 144, height = 28}) => <svg alt="Gridsome.org" fill="none" width={width} height={height} viewBox="0 0 1289 245" xmlns="http://www.w3.org/2000/svg"><path d="M221.494 101.381c11.78-.566 22.207 8.572 23.224 20.362 4.406 57.037-47.793 120.931-121.352 122.974C61.377 246.247.068 196.619.068 121.58c0-11.826 9.773-21.413 21.566-21.413s21.353 9.587 21.353 21.413c0 49.359 39.688 81.303 79.329 80.325 48.799-1.356 80.523-43.61 78.873-78.11-.566-11.812 8.526-21.847 20.305-22.414z" fill="url(#gridsome-logo_svg__paint0_linear)"></path><path d="M168.15 123.24c0-12.107 9.876-21.922 22.058-21.922h32.146c12.183 0 22.364 9.815 22.364 21.922 0 12.108-10.181 21.923-22.364 21.923h-32.146c-12.182 0-22.058-9.815-22.058-21.923zM100.7 123.272c0-12.125 9.813-21.954 21.904-21.954 12.092 0 21.905 9.829 21.905 21.954s-9.813 21.955-21.905 21.955c-12.091 0-21.904-9.83-21.904-21.955z" fill="#00A672"></path><path clip-rule="evenodd" d="M143.902 20.696c.49 11.816-8.666 21.792-20.449 22.283-50.865 2.118-81.918 42.097-80.407 80.057.47 11.816-8.51 21.778-20.293 22.25-11.784.472-22.147-9.065-22.617-20.881C-2.327 62.545 49.18 1.391 121.68.19c11.783-.49 21.732 8.69 22.221 20.506z" fill="#00A672" fill-rule="evenodd"></path><g clip-path="url(#gridsome-logo_svg__clip0)" fill="var(--body-color)"><path d="M408.102 137.495h41.203c-2.086 7.726-5.376 14.729-9.869 21.007-4.333 6.116-10.031 11.026-17.092 14.729-7.061 3.702-15.647 5.553-25.757 5.553-11.074 0-21.104-2.575-30.091-7.727-8.826-5.151-15.808-12.314-20.943-21.489-5.135-9.337-7.703-20.122-7.703-32.356 0-12.395 2.568-23.1 7.703-32.114 5.296-9.176 12.357-16.258 21.184-21.249 8.987-4.99 18.937-7.485 29.85-7.485 11.715 0 21.665 2.415 29.85 7.244 8.345 4.829 14.844 11.268 19.498 19.317l23.11-15.695c-7.382-11.751-17.252-20.927-29.609-27.527-12.197-6.6-26.48-9.9-42.849-9.9-12.678 0-24.474 2.174-35.387 6.52-10.752 4.185-20.14 10.141-28.165 17.868-7.863 7.727-14.042 16.983-18.535 27.768-4.333 10.624-6.5 22.375-6.5 35.253s2.167 24.709 6.5 35.494c4.333 10.786 10.431 20.122 18.295 28.01 8.024 7.888 17.412 14.004 28.164 18.351 10.753 4.185 22.468 6.278 35.146 6.278 13.481 0 25.437-2.415 35.868-7.244 10.432-4.99 19.178-11.751 26.239-20.283 7.061-8.531 12.357-18.27 15.888-29.216 3.531-11.107 5.135-22.859 4.814-35.253h-67.375l-3.437 24.146zM557.159 118.661l12.759-22.215c-2.568-2.897-5.617-4.99-9.148-6.278-3.53-1.287-7.302-1.931-11.314-1.931-4.654 0-9.228 1.449-13.721 4.346-4.494 2.737-8.345 6.6-11.555 11.59V90.651h-25.757v111.072h25.757v-62.538c0-8.049 1.444-14.488 4.333-19.317 2.889-4.829 7.543-7.244 13.962-7.244 3.21 0 5.858.564 7.944 1.69 2.086.966 4.333 2.415 6.74 4.347zM582.945 90.651v111.072h25.517V90.651h-25.517zm-3.611-40.74c0 4.507 1.605 8.29 4.815 11.348 3.209 3.059 7.061 4.588 11.555 4.588 4.654 0 8.585-1.53 11.795-4.588 3.21-3.058 4.815-6.841 4.815-11.349 0-4.507-1.605-8.29-4.815-11.348-3.21-3.059-7.141-4.588-11.795-4.588-4.494 0-8.346 1.53-11.555 4.588-3.21 3.058-4.815 6.841-4.815 11.349zM652.116 146.187c0-11.107 3.29-19.719 9.87-25.836 6.58-6.278 14.363-9.417 23.35-9.417 4.975 0 9.87 1.368 14.685 4.105 4.814 2.736 8.826 6.761 12.036 12.073 3.209 5.151 4.814 11.509 4.814 19.075 0 7.566-1.605 14.005-4.814 19.317-3.21 5.151-7.222 9.095-12.036 11.831-4.815 2.737-9.71 4.105-14.685 4.105-8.987 0-16.77-3.058-23.35-9.175-6.58-6.278-9.87-14.971-9.87-26.078zm-26.961 0c0 12.234 2.488 22.697 7.463 31.39 4.975 8.531 11.554 15.131 19.739 19.8 8.185 4.507 17.092 6.76 26.721 6.76 8.024 0 15.245-1.77 21.665-5.312 6.58-3.702 11.956-8.853 16.128-15.453v18.351h26.239V21.311h-26.239v87.691c-4.172-6.6-9.548-11.67-16.128-15.212-6.42-3.702-13.641-5.553-21.665-5.553-9.629 0-18.536 2.334-26.721 7.002-8.185 4.507-14.764 11.107-19.739 19.8-4.975 8.531-7.463 18.914-7.463 31.148zM772.658 161.641l-15.165 14.729c5.135 8.209 11.956 15.051 20.461 20.524 8.666 5.473 18.376 8.209 29.128 8.209 11.715 0 21.264-2.817 28.646-8.451 7.543-5.795 11.314-14.568 11.314-26.319 0-6.6-1.444-11.992-4.333-16.178-2.888-4.185-6.66-7.646-11.314-10.383-4.654-2.897-9.629-5.392-14.925-7.485a173.715 173.715 0 00-12.758-4.829c-4.173-1.449-7.623-3.139-10.351-5.071-2.729-1.931-4.093-4.426-4.093-7.485 0-3.38 1.284-5.795 3.852-7.244 2.728-1.609 6.339-2.414 10.833-2.414 4.493 0 9.147 1.288 13.962 3.863 4.975 2.576 9.308 5.876 12.999 9.9l14.443-14.971c-4.172-5.634-10.11-10.302-17.813-14.004-7.543-3.864-15.808-5.795-24.795-5.795-6.58 0-12.758 1.207-18.536 3.622-5.777 2.414-10.431 5.875-13.962 10.382-3.53 4.508-5.296 9.981-5.296 16.42 0 6.922 1.525 12.556 4.574 16.902 3.21 4.185 7.222 7.566 12.036 10.141 4.815 2.576 9.79 4.91 14.925 7.002 6.419 2.415 12.036 4.991 16.851 7.727 4.975 2.737 7.462 6.52 7.462 11.349 0 3.702-1.364 6.519-4.092 8.451-2.568 1.771-6.179 2.656-10.833 2.656-4.814 0-10.271-1.932-16.369-5.795-5.938-4.024-11.555-9.176-16.851-15.453zM884.632 146.187c0-10.463 3.13-18.914 9.389-25.353 6.419-6.439 14.283-9.659 23.591-9.659 9.468 0 17.332 3.22 23.591 9.659s9.388 14.89 9.388 25.353c0 10.302-3.129 18.753-9.388 25.353-6.259 6.439-14.123 9.659-23.591 9.659-9.308 0-17.172-3.22-23.591-9.659-6.259-6.6-9.389-15.051-9.389-25.353zm-26.72 0c0 11.429 2.568 21.49 7.703 30.183 5.296 8.692 12.438 15.533 21.425 20.524 9.147 4.829 19.338 7.243 30.572 7.243 11.394 0 21.585-2.414 30.572-7.243 8.987-4.991 16.048-11.832 21.183-20.524 5.296-8.693 7.944-18.754 7.944-30.183 0-11.429-2.648-21.49-7.944-30.182-5.135-8.693-12.196-15.454-21.183-20.283-8.987-4.99-19.178-7.485-30.572-7.485-11.234 0-21.425 2.495-30.572 7.485-8.987 4.829-16.129 11.59-21.425 20.283-5.135 8.692-7.703 18.753-7.703 30.182zM1150.99 131.217c0-14.005-2.89-24.629-8.67-31.873-5.77-7.405-14.68-11.107-26.72-11.107-7.38 0-14.12 1.77-20.22 5.312-6.1 3.38-10.99 8.129-14.68 14.246-4.98-13.039-15.57-19.558-31.78-19.558-7.22 0-13.48 1.69-18.77 5.07-5.14 3.38-9.23 7.888-12.28 13.522V90.651h-25.518v111.072h25.518v-67.609c0-7.405 1.84-13.361 5.54-17.868 3.85-4.668 9.3-7.002 16.36-7.002 6.75 0 11.48 2.173 14.21 6.519 2.73 4.185 4.09 10.302 4.09 18.351v67.609h26.24v-67.609c0-7.405 1.84-13.361 5.54-17.868 3.85-4.668 9.3-7.002 16.36-7.002 6.75 0 11.48 2.173 14.21 6.519 2.89 4.185 4.33 10.302 4.33 18.351v67.609h26.24v-70.506zM1193.64 152.224h88.35c.16-1.288.24-2.576.24-3.864.16-1.288.24-2.414.24-3.38 0-17.546-7.38-31.39-17.33-41.531-9.79-10.142-23.27-15.212-40.44-15.212-15.89 0-28.81 4.266-38.76 12.797-9.79 8.532-15.81 19.639-18.05 33.322a67.402 67.402 0 00-.73 5.795 73.142 73.142 0 00-.24 6.036c0 11.107 2.33 21.088 6.98 29.941 4.66 8.693 11.24 15.534 19.74 20.524 8.51 4.99 18.46 7.485 29.85 7.485 13.8 0 25.12-2.736 33.94-8.209 8.99-5.473 18.62-12.717 24.08-21.732l-25.04-9.175c-3.21 5.473-7.46 9.819-12.76 13.039-5.13 3.058-11.47 4.587-19.01 4.587-8.51 0-15.57-2.495-21.19-7.485-5.61-5.151-8.9-12.797-9.87-22.938zm.48-18.11c1.13-8.21 4.5-14.568 10.11-19.075 5.62-4.668 12.36-7.003 20.23-7.003 8.34 0 14.76 2.335 19.25 7.003 4.5 4.668 7.23 11.026 8.19 19.075h-57.78z"></path></g><defs><linearGradient gradientUnits="userSpaceOnUse" id="gridsome-logo_svg__paint0_linear" x1="122.523" x2="122.523" y1="100.167" y2="244.752"><stop stop-color="#00583E"></stop><stop offset="1" stop-color="#00835C"></stop></linearGradient><clipPath id="gridsome-logo_svg__clip0"><path d="M0 0h981v183H0z" fill="#fff" transform="translate(308 22)"></path></clipPath></defs></svg>;

export const NuxtLogo = ({width = 32, height = 32}) => <svg width={width} height={height} viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M281.44 397.667H438.32C443.326 397.667 448.118 395.908 452.453 393.427C456.789 390.946 461.258 387.831 463.76 383.533C466.262 379.236 468.002 374.36 468 369.399C467.998 364.437 466.266 359.563 463.76 355.268L357.76 172.947C355.258 168.65 352.201 165.534 347.867 163.053C343.532 160.573 337.325 158.813 332.32 158.813C327.315 158.813 322.521 160.573 318.187 163.053C313.852 165.534 310.795 168.65 308.293 172.947L281.44 219.587L227.733 129.13C225.229 124.834 222.176 120.307 217.84 117.827C213.504 115.346 208.713 115 203.707 115C198.701 115 193.909 115.346 189.573 117.827C185.238 120.307 180.771 124.834 178.267 129.13L46.8267 355.268C44.3208 359.563 44.0022 364.437 44 369.399C43.9978 374.36 44.3246 379.235 46.8267 383.533C49.3288 387.83 53.7979 390.946 58.1333 393.427C62.4688 395.908 67.2603 397.667 72.2667 397.667H171.2C210.401 397.667 238.934 380.082 258.827 346.787L306.88 263.4L332.32 219.587L410.053 352.44H306.88L281.44 397.667ZM169.787 352.44H100.533L203.707 174.36L256 263.4L221.361 323.784C208.151 345.387 193.089 352.44 169.787 352.44Z" fill="#00DC82" />
  </svg>;

export const HexoLogo = ({width = 32, height = 32}) => <svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" width={width} height={height} viewBox="0 0 512 512" enable-background="new 0 0 512 512" xml:space="preserve">
    <path fill="#0E83CD" d="M256.4,25.8l-200,115.5L56,371.5l199.6,114.7l200-115.5l0.4-230.2L256.4,25.8z M349,354.6l-18.4,10.7
	l-18.6-11V275H200v79.6l-18.4,10.7l-18.6-11v-197l18.5-10.6l18.5,10.8V237h112v-79.6l18.5-10.6l18.5,10.8V354.6z" />
  </svg>;

export const NextLogo = ({width = 32, height = 32}) => <svg xmlns="http://www.w3.org/2000/svg" height={height} width={width} viewBox="0 0 16 16" strokeLinejoin="round" style={{
  color: 'currentColor'
}}>
    <g clipPath="url(#clip0_53_108)">
      <circle cx="8" cy="8" r="7.375" fill="black" stroke="var(--ds-gray-1000)" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M10.63 11V5" stroke="url(#paint0_linear_53_108vsxrmxu21)" strokeWidth="1.25" strokeMiterlimit="1.41421" />
      <path fillRule="evenodd" clipRule="evenodd" d="M5.995 5.00087V5H4.745V11H5.995V6.96798L12.3615 14.7076C12.712 14.4793 13.0434 14.2242 13.353 13.9453L5.99527 5.00065L5.995 5.00087Z" fill="url(#paint1_linear_53_108vsxrmxu21)" />
    </g>
    <defs>
      <linearGradient id="paint0_linear_53_108vsxrmxu21" x1="11.13" y1="5" x2="11.13" y2="11" gradientUnits="userSpaceOnUse">
        <stop stopColor="white" />
        <stop offset="0.609375" stopColor="white" stopOpacity="0.57" />
        <stop offset="0.796875" stopColor="white" stopOpacity="0" />
        <stop offset="1" stopColor="white" stopOpacity="0" />
      </linearGradient>
      <linearGradient id="paint1_linear_53_108vsxrmxu21" x1="9.9375" y1="9.0625" x2="13.5574" y2="13.3992" gradientUnits="userSpaceOnUse">
        <stop stopColor="white" />
        <stop offset="1" stopColor="white" stopOpacity="0" />
      </linearGradient>
      <clipPath id="clip0_53_108">
        <rect width="16" height="16" fill="red" />
      </clipPath>
    </defs>
  </svg>;

export const GatsbyLogo = ({width = 32, height = 32}) => {
  return <svg xmlns="http://www.w3.org/2000/svg" width={width} height={height} viewBox="0 0 28 28" focusable="false">
      <title>
        Gatsby
      </title>
      <circle cx="14" cy="14" r="14" fill="#639" />
      <path fill="#fff" d="M6.2 21.8C4.1 19.7 3 16.9 3 14.2L13.9 25c-2.8-.1-5.6-1.1-7.7-3.2zm10.2 2.9L3.3 11.6C4.4 6.7 8.8 3 14 3c3.7 0 6.9 1.8 8.9 4.5l-1.5 1.3C19.7 6.5 17 5 14 5c-3.9 0-7.2 2.5-8.5 6L17 22.5c2.9-1 5.1-3.5 5.8-6.5H18v-2h7c0 5.2-3.7 9.6-8.6 10.7z" />
    </svg>;
};

***

Ghost ships with a default front-end theme layer built with Handlebars, but based on its flexible [architecture](/architecture/) it can also be used as a headless CMS with third party front-end frameworks. We have setup guides for most of the most popular frameworks and how to use Ghost with them.

<CardGroup cols={3}>
  <Card title="Next.js" href="/jamstack/next/" icon={<NextLogo />} />

  <Card title="Gatsby" href="/jamstack/gatsby/" icon={<GatsbyLogo />} />

  <Card title="Hexo" href="/jamstack/hexo/" icon={<HexoLogo />} />

  <Card title="Nuxt" href="/jamstack/nuxt/" icon={<NuxtLogo />} />

  <Card title="VuePress" href="/jamstack/vuepress/" icon="https://mintlify.s3.us-west-1.amazonaws.com/ghost/images/vuepress-logo.png" />

  <Card title="Gridsome" href="/jamstack/gridsome/" icon={<GridsomeLogo />} />

  <Card title="Eleventy" href="/jamstack/eleventy/" icon={<EleventyLogo />} />

  <Card title="Custom Frontend" href="/jamstack/custom/" icon="sparkles" />
</CardGroup>

## Tips for using Ghost headless

Something to keep in mind is that Ghost’s default front-end is not just a theme layer, but also contains a large subset of functionality that is commonly required by most publishers, including:

* Tag archives, routes and templates
* Author archives, routes and templates
* Generated sitemap.xml for SEO
* Intelligent output and fallbacks for SEO meta data
* Automatic Open Graph structured data
* Automatic support for Twitter Cards
* Custom routes and automatic pagination
* Front-end code injection from admin

When using a statically generated front-end, all of this functionality must be re-implemented. Getting a list of posts from the API is usually the easy part, while taking care of the long tail of extra features is the bulk of the work needed to make this work well.

### Memberships

Ghost’s membership functionality is **not** compatible with headless setups. To use features like our Stripe integration for paid subscriptions, content gating, comments, analytics, offers, complimentary plans, trials, and more — Ghost must be used with its frontend layer.

### Working with images

The Ghost API returns content HTML including image tags with absolute URLs, pointing at the origin of the Ghost install. This is intentional, because Ghost itself is designed (primarily) to be source of truth for serving optimised assets, and may also be installed in a subdirectory.

When using a static front-end, you can either treat the Ghost install as a CDN origin for uploaded assets, or you can write additional logic in your front-end build to download embedded images locally, and rewrite the returned HTML to point to the local references instead.

### Disabling Ghost’s default front-end

When using a headless front-end with Ghost, you’ll want to disable Ghost’s default front-end to prevent duplicate content issues where search engines would see the same content on two different domains. The easiest way to do this is to enable ‘Private Site Mode’ under `Settings > General` - which will put a password on your Ghost install’s front-end, disable all SEO features, and serve a `noindex` meta tag.

You can also use dynamic redirects, locally or at a DNS level, to forward traffic automatically from the Ghost front-end to your new headless front-end - but this is a more fragile setup. If you use Ghost’s built-in newsletter functionality, unsubscribe links in emails will point to the Ghost origin - and these URLs will break if redirected. Preview URLs and other dynamically generated paths may also behave unexpectedly when blanket redirects are used.

Usually ‘Private Site Mode’ is the better option.

### Pagination for building static sites

Support for `?limit=all` when fetching data was removed in [Ghost 6.0](/changes#ghost-6-0), and all endpoints now have a max page size of 100.

This means any front-end frameworks that relied on `?limit=all` for building static pages, such as with `getStaticPaths()` in Next.js, should instead use pagination to fetch all of the needed data.

For example:

```js  theme={"dark"}
// api.js
const api = new GhostContentAPI({
  url: 'https://demo.ghost.io',
  key: '22444f78447824223cefc48062',
  version: "v6.0"
});

// lib/posts.js
export async function getAllPostSlugs() {
  try {
    const allPostSlugs = [];
    let page = 1;

    while (page) {
      const posts = await api.posts.browse({
        limit: 100,
        page,
        fields: "slug", // Only the slug field is needed for getStaticPaths()
      });

      if (!posts?.length) break;

      allPostSlugs.push(...posts.map((post) => post.slug));
      // Use the meta pagination info to determine if there are more pages
      page = posts.meta.pagination.next || null;
    }

    return allPostSlugs;
  } catch (err) {
    console.error(err);
    return [];
  }
}

// pages/posts/[slug].js
export async function getStaticPaths() {
  const slugs = await getAllPostSlugs();

  // Get the paths we want to create based on slugs
  const paths = slugs.map((slug) => ({
    params: { slug: slug },
  }));

  return { paths, fallback: false };
}
```

In addition, consider building in small delays so as not to trigger any rate limits or fair usage policies of your hosts.


# Building A Custom Front End For Ghost
Source: https://docs.ghost.org/jamstack/custom

Build a completely custom front-end for your Ghost site with our Content API and [JavaScript Client](/content-api/javascript/)

***

## Prerequisites

You’ll need basic understanding of JavaScript and a running Ghost installation, which can either be self-hosted or using [Ghost(Pro)](https://ghost.org/pricing/).

## Getting started

Ghost’s [Content API](/content-api/) provides complete access to any public data on your Ghost site including posts, pages, tags, authors and settings.

The [JavaScript Client](/content-api/javascript/) provides an easy, consistent way to get data from the Content API in JavaScript. It works server-side, in the browser or even in a build pipeline.

The [JavaScript SDK](/content-api/javascript/#javascript-sdk) provides further tools for working with the data returned from the Content API.

These three tools give you total flexibility to build any custom frontend you can imagine with minimal coding required. Some examples of what can be achieved include generating static files, building a browser-based application or creating a latest posts widget on an external site.

### Further reading

Read more about how to [install and use](/content-api/javascript) these tools in your environment. Learn more about the Ghost API and specific endpoints in our [API documentation](/content-api/).


# Working With Eleventy
Source: https://docs.ghost.org/jamstack/eleventy

Build a completely custom front-end for your Ghost site with the flexibility of Static Site Generator [Eleventy](http://11ty.io).

***

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0ed9faae-admin-api-eleventy-diagram_hu5ba97386724b594b90daeca2cbf04049_20855_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ca5944fe39bf652a5804958f955e8b35" data-og-width="1000" width="1000" data-og-height="523" height="523" data-path="images/0ed9faae-admin-api-eleventy-diagram_hu5ba97386724b594b90daeca2cbf04049_20855_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0ed9faae-admin-api-eleventy-diagram_hu5ba97386724b594b90daeca2cbf04049_20855_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=58f3bbd8753aec19ad00e3845381df1d 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0ed9faae-admin-api-eleventy-diagram_hu5ba97386724b594b90daeca2cbf04049_20855_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=96d60f6706652f34357619528762b612 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0ed9faae-admin-api-eleventy-diagram_hu5ba97386724b594b90daeca2cbf04049_20855_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=67370b83f1fe3c99fe43202b026f97ca 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0ed9faae-admin-api-eleventy-diagram_hu5ba97386724b594b90daeca2cbf04049_20855_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=12d72b7402fe7e5a7cca2bce65f5e3b9 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0ed9faae-admin-api-eleventy-diagram_hu5ba97386724b594b90daeca2cbf04049_20855_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=9e85b9415e6a9742c623c003739d9f7c 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0ed9faae-admin-api-eleventy-diagram_hu5ba97386724b594b90daeca2cbf04049_20855_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8768b9892fc6714ad425043fffbcd2c5 2500w" />
</Frame>

## Eleventy Starter Ghost

Eleventy is a “zero configuration” static site generator, meaning it works without any initial setup. That said, having some boilerplate code can really fast track the development process. **That’s why we’ve created an [Eleventy Starter for Ghost](https://github.com/TryGhost/eleventy-starter-ghost) on GitHub.**

### Prerequisites

A Ghost account is needed in order to source the content, a self hosted version or a [Ghost (Pro) Account](https://ghost.org/pricing/).

### Getting started

To begin, create a new project by either cloning the [Eleventy Starter Ghost repo](https://github.com/TryGhost/eleventy-starter-ghost) or forking the repo and then cloning the fork with the following CLI command:

```bash  theme={"dark"}
git clone git@github.com:TryGhost/eleventy-starter-ghost.git
```

Navigate into the newly created project and use the command `yarn` to install the dependencies. Check out the official documentation on how to install [Yarn](https://yarnpkg.com/en/docs/install#mac-stable).

To test everything installed correctly, use the following command to run your project:

```bash  theme={"dark"}
yarn start
```

Then navigate to `http://localhost:8080/` in a browser and view the newly created Eleventy static site.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c8f5e69c-11ty-demo-screenshot_hu790d07d965c54347e81f228a6b805163_953696_1426x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=10976e1645e29ab9e9c8be9bb701c8e0" data-og-width="1426" width="1426" data-og-height="878" height="878" data-path="images/c8f5e69c-11ty-demo-screenshot_hu790d07d965c54347e81f228a6b805163_953696_1426x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c8f5e69c-11ty-demo-screenshot_hu790d07d965c54347e81f228a6b805163_953696_1426x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=37b5a2f4306c16dc883f86b460930f3f 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c8f5e69c-11ty-demo-screenshot_hu790d07d965c54347e81f228a6b805163_953696_1426x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=6249c915dfc68c702eded8539747683c 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c8f5e69c-11ty-demo-screenshot_hu790d07d965c54347e81f228a6b805163_953696_1426x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=b44f4d8da30330728e79ba7040e00f23 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c8f5e69c-11ty-demo-screenshot_hu790d07d965c54347e81f228a6b805163_953696_1426x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=84d709dc7c3ef0ab66cab2f7c57c24df 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c8f5e69c-11ty-demo-screenshot_hu790d07d965c54347e81f228a6b805163_953696_1426x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=d7f53fa4c5c8153149089fe902d275b6 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c8f5e69c-11ty-demo-screenshot_hu790d07d965c54347e81f228a6b805163_953696_1426x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2b1a73877d159f68371ea49abbca797a 2500w" />
</Frame>

***

### Customisation

The Eleventy Starter for Ghost is configured to source content from [https://eleventy.ghost.io](https://eleventy.ghost.io). This can be changed in the `.env` file that comes with the starter.

```yaml  theme={"dark"}
GHOST_API_URL=https://eleventy.ghost.io
GHOST_CONTENT_API_KEY=5a562eebab8528c44e856a3e0a
SITE_URL=http://localhost:8080
```

Change the `GHOST_API_URL` value to the URL of the site. For Ghost(Pro) customers, this is the Ghost URL ending in .ghost.io, and for people using the self-hosted version of Ghost, it’s the same URL used to view the admin panel.

Change the `GHOST_CONTENT_API_KEY` value to a key associated with the Ghost site. A key can be provided by creating an integration within the Ghost Admin. Navigate to Integrations and click “Add new integration”. Name the integration, something related like “Eleventy”, click create.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2d99d7b0b3f46681cdf28d78919637d6" data-og-width="2920" width="2920" data-og-height="1200" height="1200" data-path="images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4eb5d3f87c7433c845273edbb3bf7c76 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f731f4b897bd5965c8c6372c5b4829ab 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=57ea451e943a4db99dd840d4c482bfea 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=99770f82771ad1ad5f4743b9ed20e18b 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7e94d2342b13fb4e50b66f34fd6d5f68 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3dafebd40f6b58424c1c7e1a3fb1f9c0 2500w" />
</Frame>

More information can be found on the [Content API documentation](/content-api/#key).

**Using [Netlify](https://www.netlify.com/) to host your site? If so, the `netlify.toml` file that comes with the starter template provides the deployment configuration straight out of the box.**

***

## Next steps

[The official Eleventy docs](https://www.11ty.io/docs) is a great place to learn more about how Eleventy works and how it can be used to build static sites.

There’s also a guide for setting up a new static site, such as Eleventy, [with the hosting platform Netlify](https://ghost.org/integrations/netlify/) so Netlify can listen for updates on a Ghost site and rebuild the static site.

For community led support about linking and building a Ghost site with Eleventy, [visit the forum](https://forum.ghost.org/c/themes/).

## Examples

*Here are a few common examples of using the Ghost Content API within an Eleventy project.*\*

Retrieving data from the Content API within an Eleventy project is pretty similar to using the API in a JavaScript application. However there are a couple of conventions and techniques that will make the data easier to access when creating template files. The majority of these examples are intended to be placed in the `.eleventy.js` file in the root of the project, to find out more on configuring Eleventy refer to [their official documentation](https://www.11ty.io/docs/config/).

## Initialising the Content API

More information on setting up and using the Content API using the JavaScript Client Library can be found in [our API documentation](/content-api/javascript/)

```js  theme={"dark"}
const ghostContentAPI = require("@tryghost/content-api");

const api = new ghostContentAPI({
  url: process.env.GHOST_API_URL,
  key: process.env.GHOST_CONTENT_API_KEY,
  version: "v6.0"
});
```

## Retrieving posts

This example retrieves posts from the API and adds them as a new [collection to Eleventy](https://www.11ty.io/docs/collections/). The example also performs some sanitisation and extra meta information to each post:

* Adding tag and author meta information to each post
* Converting post date to a [JavaScript date object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date) for easier manipulation in templates
* Bring featured posts to the top of the list

The maximum amount of items that can be fetched from a resource at once is 100, so use pagination to make sure all of the items are fetched:

```js  theme={"dark"}
config.addCollection("posts", async function(collection) {
  try {
    let page = 1;
    let hasMore = true;

    while (hasMore) {
      const posts = await api.posts.browse({
        include: "tags,authors",
        limit: 100,
        page,
      });

      if (posts && posts.length > 0) {
        collection.push(...posts.map((post) => ({
          ...post,
          url: stripDomain(post.url),
          primary_author: {
            ...post.primary_author,
            url: stripDomain(post.primary_author.url)
          },
          tags: post.tags.map(tag => ({
            ...tag,
            url: stripDomain(tag.url)
          })),
          // Convert publish date into a Date object
          published_at: new Date(post.published_at)
        })));
        // Use the meta pagination info to determine if there are more pages
        page = posts.meta.pagination.next;
        hasMore = page !== null;
      } else {
        hasMore = false;
      }
    }

  // Bring featured post to the top of the list
  collection.sort((post, nextPost) => nextPost.featured - post.featured);
  
  return collection
  } catch (error) {
    console.error(error);
    return [];
  }
});
```

This code fetches **all** posts because Eleventy creates the HTML files when the site is built and needs access to all the content at this step.

## Retrieving posts by tag

You’ll often want a page that shows all the posts that are marked with a particular tag. This example creates an [Eleventy collection](https://www.11ty.io/docs/collections/) for the tags within a Ghost site, as well as attaching all the posts that are related to that tag:

```js  theme={"dark"}
config.addCollection("tags", async function(collection) {
  collection = await api.tags
    .browse({
      include: "count.posts", // Get the number of posts within a tag
      limit: 100 // default is 15, max is 100 - use pagination for more
    })
    .catch(err => {
      console.error(err);
    });

  // Get up to 100 posts with their tags attached
  const posts = await api.posts
    .browse({
      include: "tags,authors",
      limit: 100 // default is 15, max is 100 - use pagination for more
    })
    .catch(err => {
      console.error(err);
    });

  // Attach posts to their respective tags
  collection.map(async tag => {
    const taggedPosts = posts.filter(post => {
      return post.primary_tag && post.primary_tag.slug === tag.slug;
    });

    // Only attach the tagged posts if there are any
    if (taggedPosts.length) tag.posts = taggedPosts;
    return tag;
  });

  return collection;
});
```

## Retrieving site settings

We used this example within our [Eleventy Starter](https://github.com/TryGhost/eleventy-starter-ghost), but rather than putting this in the main configuration file it’s better to add it to a [Data file](https://www.11ty.io/docs/data/), which partitions it from other code and allows it to be attached to a global variable like `site`.

```js  theme={"dark"}
module.exports = async function() {
  const siteData = await api.settings
    .browse({
      include: "icon,url" // Get the site icon and site url
    })
    .catch(err => {
      console.error(err);
    });

  return siteData;
};
```

## Asynchronous data retrieval

All the examples above use asynchronous functions when getting data from the Content API. This is so Eleventy intentionally awaits until the content has come back completely before it starts building out static files.

## Next steps

Check out our documentation on the [Content API Client Library](/content-api/javascript/) to see what else is possible, many of the examples there overlap with the examples above. [The official Eleventy docs site](https://www.11ty.io/docs)is very extensive as well if you wish to delve deeper into the API.


# Working With Gatsby
Source: https://docs.ghost.org/jamstack/gatsby

Build a custom front-end for your Ghost site with the power of Gatsby.js

***

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1f725078-admin-api-gatsby-diagram_hu088f0fec0d83414e79d90f8ae3457e19_21185_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=df59ba48dcd77324ff50d7bd69c9257c" data-og-width="1000" width="1000" data-og-height="523" height="523" data-path="images/1f725078-admin-api-gatsby-diagram_hu088f0fec0d83414e79d90f8ae3457e19_21185_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1f725078-admin-api-gatsby-diagram_hu088f0fec0d83414e79d90f8ae3457e19_21185_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=27418bbb8c083e96c6289a6426bda77b 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1f725078-admin-api-gatsby-diagram_hu088f0fec0d83414e79d90f8ae3457e19_21185_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a0103d20c12bb4c0ec037b00cc1ae3bb 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1f725078-admin-api-gatsby-diagram_hu088f0fec0d83414e79d90f8ae3457e19_21185_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8a39cffab5076e5fa9a99141594fa1cc 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1f725078-admin-api-gatsby-diagram_hu088f0fec0d83414e79d90f8ae3457e19_21185_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f626ddf9303c4614ce5a4d19c1051cee 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1f725078-admin-api-gatsby-diagram_hu088f0fec0d83414e79d90f8ae3457e19_21185_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d1ba8f9923f647d95f28c0dcb831080f 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1f725078-admin-api-gatsby-diagram_hu088f0fec0d83414e79d90f8ae3457e19_21185_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=36591d15f85d4a26c6d093a696af8256 2500w" />
</Frame>

## Gatsby Starter Ghost

One of the best ways to start a new Gatsby site is with a Gatsby Starter, and in this case, it’s no different.

#### Prerequisites

To use Gatsby Starters, and indeed Gatsby itself, the [Gatsby CLI](https://www.gatsbyjs.com/docs/quick-start/) tool is required. Additionally, a [Ghost account](https://ghost.org/pricing/) is needed to source content and get site related credentials.

#### Getting started

To begin, generate a new project using the [Gatsby Starter Ghost](https://github.com/TryGhost/gatsby-starter-ghost) template with the following CLI command:

```bash  theme={"dark"}
gatsby new my-gatsby-site https://github.com/TryGhost/gatsby-starter-ghost.git
```

Navigate into the newly created project and use either npm install or yarn to install the dependencies. The Ghost team prefer to use [Yarn](https://yarnpkg.com/en/docs/install#mac-stable).

Before customising and developing in this new Gatsby site, it’s wise to give it a test run to ensure everything is installed correctly. Use the following command to run the project:

```bash  theme={"dark"}
gatsby develop
```

Then navigate to `http://localhost:8000/` in a browser and view the newly created Gatsby site.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/218dae99-gatsby-demo-screenshot_huf503a446e74501027d0049b3b70cf420_364260_1280x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=47c549a6a4545cea999f9eb979608600" data-og-width="1280" width="1280" data-og-height="840" height="840" data-path="images/218dae99-gatsby-demo-screenshot_huf503a446e74501027d0049b3b70cf420_364260_1280x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/218dae99-gatsby-demo-screenshot_huf503a446e74501027d0049b3b70cf420_364260_1280x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=68f68e1899ded178ff6ef120db6714ad 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/218dae99-gatsby-demo-screenshot_huf503a446e74501027d0049b3b70cf420_364260_1280x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=2d0c27dec79789759dde9700037ab7bd 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/218dae99-gatsby-demo-screenshot_huf503a446e74501027d0049b3b70cf420_364260_1280x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=4650a5cf68a73216bc846e3d322d4259 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/218dae99-gatsby-demo-screenshot_huf503a446e74501027d0049b3b70cf420_364260_1280x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=6b09fd58b7c2ec8de43746ebebbf1751 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/218dae99-gatsby-demo-screenshot_huf503a446e74501027d0049b3b70cf420_364260_1280x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=b8858ebc55797080b5f25f35cf4eeb10 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/218dae99-gatsby-demo-screenshot_huf503a446e74501027d0049b3b70cf420_364260_1280x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=492b700b70176ffdfc79d81b8f32e0a1 2500w" />
</Frame>

## Making it your own

So, you’ve set up a Gatsby site, but it’s not showing the right content. This is where content sourcing comes into play. Gatsby uses [GraphQL](https://graphql.org/) as a method of pulling content from a number of APIs, including Ghost. Sourcing content from Ghost in the Gatsby Starter Ghost template is made possible with the [Gatsby Source Ghost](https://github.com/TryGhost/gatsby-source-ghost) plugin.

Configuring the plugin can be done within the template files. Within the project, navigate to and open the file named `.ghost.json`, which is found at root level:

```json  theme={"dark"}
// .ghost.json
{
 "development": {
  "apiUrl": "https://gatsby.ghost.io",
  "contentApiKey": "9cc5c67c358edfdd81455149d0"
 },
 "production": {
  "apiUrl": "https://gatsby.ghost.io",
  "contentApiKey": "9cc5c67c358edfdd81455149d0"
 }
}
```

This json file is set up to make environment variables a bit easier to control and edit. Change the apiUrl value to the URL of the site. For Ghost(Pro) customers, this is the Ghost URL ending in .ghost.io, and for people using the self-hosted version of Ghost, it’s the same URL used to view the admin panel.

In most cases, it’s best to change both the development and production to the same site details. Use the respective environment objects when using production and development content; this is ideal if you’re working with clients and test content. After saving these changes, restart the local server.

Using [Netlify](https://www.netlify.com/) to host your site? If so, the `netlify.toml` file that comes with the starter template provides the deployment configuration straight out of the box.

## Next steps

[The official Gatsby docs](https://www.gatsbyjs.com/docs/gatsby-project-structure/) is a great place to learn more about how typical Gatsby projects are structured and how it can be extended.

Gaining a greater understanding of how data and content can be sourced from the Ghost API with GraphQL will help with extending aforementioned starter project for more specific use cases.

There’s also a guide for setting up a new static site, such as Gatsby, [with the hosting platform Netlify](https://ghost.org/integrations/netlify/).

For community led support about linking and building a Ghost site with Gatsby, [visit the forum](https://forum.ghost.org/c/themes/).

As with all content sources for Gatsby, content is fed in by [GraphQL](https://www.gatsbyjs.com/tutorial/part-four/), and it’s no different with Ghost. The official [Gatsby Source Ghost](https://github.com/TryGhost/gatsby-source-ghost) plugin allows you to pull content from your existing Ghost site.

## Getting started

Installing the plugin is the same as any other Gatsby plugin. Use your CLI tool of choice to navigate to your Gatsby project and a package manager to install it:

```bash  theme={"dark"}
# yarn users
yarn add gatsby-source-ghost
# npm users
npm install --save gatsby-source-ghost
```

After that, the next step is to get the API URL and Content API Key of the Ghost site. The API URL is domain used to access the Ghost Admin. For Ghost(Pro) customers, this is the `.ghost.io`, for example: `mysite.ghost.io`. For self-hosted versions of Ghost, use the admin panel access URL and ensure that the self-hosted version is served over a https connection. The Content API Key can be found on the Integrations screen of the Ghost Admin.

Open the `gatsby-config.js` file and add the following to the `plugins` section:

```js  theme={"dark"}
// gatsby-config.js
{
  resolve: `gatsby-source-ghost`,
  options: {
    apiUrl: `https://<your-site-subdomain>.ghost.io`,
    contentApiKey: `<your content api key>`
  }
}
```

Restart the local server to apply these configuration changes.

## Querying Graph with GraphQL

The Ghost API provides 5 types of nodes:

* Post
* Page
* Author
* Tag
* Settings

These nodes match with the endpoints shown in the [API endpoints documentation](/content-api/#endpoints). Querying these node with GraphQL can be done like so:

```gql  theme={"dark"}
{
  allGhostPost(sort: { order: DESC, fields: [published_at] }) {
    edges {
      node {
        id
        slug
        title
        html
        published_at
      }
    }
  }
}
```

The above example is retrieving all posts in descending order of the ‘published at’ field. The posts will each come back with an id, slug, title, the content (html) and the ‘published at’ date.

## Next steps

GraphQL is a very powerful tool to query the Ghost API with. This is why we’ve documented a few recipes that will get you started.

To learn more about the plugin itself, check out the [documentation within the repo on GitHub](https://github.com/TryGhost/gatsby-source-ghost#how-to-query). There’s also plenty of documentation on what the Ghost API has to offer when making queries. To learn more about GraphQL as a language, head over to the [official GraphQL docs](https://graphql.org/learn/queries/).

## Use-cases

There are many additional aspects to switching from a typical Ghost front-end to a standalone API driven front-end like Gatsby. The following sections explain some slightly ‘grey area’ topics that have been commonly asked or may be of use when making this transition.

## Switching over

Switching to a new front-end means handling the old front-end in a different way.

One option is to make the old pages canonical, meaning that these pages will remain online, but will reference the new counterparts on the API driven site. Check out the documentation on [using canonical URLs in Ghost](https://ghost.org/help/publishing-options/#add-custom-canonical-urls).

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/bef9adef-admin-private-option_hub2336ad8c44cf39926a93b72f74de9cd_10436_800x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=a6b3969d9af6e6dc9fa6994294595894" data-og-width="800" width="800" data-og-height="168" height="168" data-path="images/bef9adef-admin-private-option_hub2336ad8c44cf39926a93b72f74de9cd_10436_800x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/bef9adef-admin-private-option_hub2336ad8c44cf39926a93b72f74de9cd_10436_800x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=a6f32ffbf81ea471e9a96fd492d0e84e 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/bef9adef-admin-private-option_hub2336ad8c44cf39926a93b72f74de9cd_10436_800x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=8b3b52c93be1d011c2651b849803eb36 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/bef9adef-admin-private-option_hub2336ad8c44cf39926a93b72f74de9cd_10436_800x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=90e81a10648cfcc96290f6f0bb60040f 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/bef9adef-admin-private-option_hub2336ad8c44cf39926a93b72f74de9cd_10436_800x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f9753dae02b624e6c80def1c2865736c 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/bef9adef-admin-private-option_hub2336ad8c44cf39926a93b72f74de9cd_10436_800x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=8ae41e3bdebff2360efc7708fc8079a2 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/bef9adef-admin-private-option_hub2336ad8c44cf39926a93b72f74de9cd_10436_800x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7b729a0cac1a1fd8f026eaa8f21aecca 2500w" />
</Frame>

Another way is to turn off the old site entirely and begin directing people to the new site. Ghosts’ front-end can be hidden using the ‘Private Mode’ found in the Ghost Admin under General Settings.

## Generating a sitemap

Providing a well made sitemap for search indexing bots is one of the most important aspects of good SEO. However, creating and maintaining a series of complex ‘for loops’ can be a costly exercise.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/14a1eed4-xml-sitemap-before-and-after_huaa7504f9f8a1eda4d36a79fb085bcdc6_679990_2068x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1c35e25346eb6afc3e2190d2f9a80b5e" data-og-width="2068" width="2068" data-og-height="737" height="737" data-path="images/14a1eed4-xml-sitemap-before-and-after_huaa7504f9f8a1eda4d36a79fb085bcdc6_679990_2068x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/14a1eed4-xml-sitemap-before-and-after_huaa7504f9f8a1eda4d36a79fb085bcdc6_679990_2068x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=9c16d30985161c994499294414539aae 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/14a1eed4-xml-sitemap-before-and-after_huaa7504f9f8a1eda4d36a79fb085bcdc6_679990_2068x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d2526296ff01ed034a275970a41b2ecf 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/14a1eed4-xml-sitemap-before-and-after_huaa7504f9f8a1eda4d36a79fb085bcdc6_679990_2068x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7e257fe43d64048d82a3b5ebf277c87a 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/14a1eed4-xml-sitemap-before-and-after_huaa7504f9f8a1eda4d36a79fb085bcdc6_679990_2068x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=2debe47833f49a43b3765c1e9435f6f6 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/14a1eed4-xml-sitemap-before-and-after_huaa7504f9f8a1eda4d36a79fb085bcdc6_679990_2068x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=5890760b20c6a3264b9038d03a94ba4b 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/14a1eed4-xml-sitemap-before-and-after_huaa7504f9f8a1eda4d36a79fb085bcdc6_679990_2068x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=9563818b23874efa5945ad7b176d23e4 2500w" />
</Frame>

The Ghost team have provided an open source plugin for Gatsby to construct an ideal format for generated sitemap XML pages, called [Gatsby Advanced Sitemap plugin](https://github.com/TryGhost/gatsby-plugin-advanced-sitemap). By default, the plugin will generate a single sitemap, but it can be [configured with GraphQL](https://github.com/TryGhost/gatsby-plugin-advanced-sitemap#options) to hook into various data points. Further information can be found in the [sitemap plugin documentation](https://github.com/TryGhost/gatsby-plugin-advanced-sitemap#gatsby-plugin-advanced-sitemap).

The plugin doesn’t just work with Ghost - it’s compatible with an assortment of APIs and content sources. To learn more about using GraphQL and the Ghost API for plugins, such as the Gatsby sitemap plugin, check out our GraphQL Recipes for Ghost.

## Using Gatsby plugins with Ghost content

With the ever expanding list of plugins available for Gatsby, it’s hard to understand which plugins are needed to make a high quality and well functioning site running on the Ghost API.

[Gatsby Source Filesystem](https://www.gatsbyjs.com/plugins/gatsby-source-filesystem/) is a plugin for creating additional directories inside a Gatsby site. This is ideal for storing static files (e.g. error pages), site-wide images, such as logos, and site configuration files like robots.txt.

[Gatsby React Helmet plugin](https://www.gatsbyjs.com/plugins/gatsby-plugin-react-helmet/) is very useful for constructing metadata in the head of any rendered page. The plugin requires minimum configuration, but can be modified to suit the need.

## Further reading

There is plenty of reference material and resources on the [official Gatsby site](https://www.gatsbyjs.com/tutorial/), along with a long list of [available plugins](https://www.gatsbyjs.com/plugins/). It may also be worth understanding the underlying concepts of [static sites](https://jamstack.org/) and how they work differently to other sites.

To get an even more boarder view of performant site development check out web.dev from Google, which explores many topics on creating site for the modern web.

## Examples

Here are a few common examples of using GraphQL to query the Ghost API.

Gatsby uses [GraphQL](https://www.gatsbyjs.com/docs/graphql/) to retrieve content, retrieving content from the Ghost API is no different thanks to the Gatsby Source Ghost plugin. Below are some recipes to retrieve chunks of data from the API that you can use and manipulate for your own needs. More extensive learning can be found in the official [GraphQL documentation](https://graphql.org/graphql-js/passing-arguments/).

## Retrieving posts

This example takes into account a limited amount of posts per page and a ‘skip’ to paginate through those pages of posts:

```gql  theme={"dark"}
query GhostPostQuery($limit: Int!, $skip: Int!) {
 allGhostPost(
   sort: { order: DESC, fields: [published_at] },
   limit: $limit,
   skip: $skip
 ) {
  edges {
   node {
    ...GhostPostFields
   }
  }
 }
}
```

## Filtering Posts by tag

Filtering posts by tag is a common pattern, but can be tricky with how the query filter is formulated:

```gql  theme={"dark"}
{
 allGhostPost(filter: {tags: {elemMatch: {slug: {eq: $slug}}}}) {
  edges {
   node {
    slug
    ...
   }
  }
 }
}
```

## Retrieving settings

The Ghost settings node is different to other nodes as it’s a single object - this can be queried like so:

```gql  theme={"dark"}
{
 allGhostSettings {
  edges {
   node {
    title
    description
    lang
    ...
    navigation {
      label
      url
    }
   }
  }
 }
}
```

More information can be found in the [Ghost API documentation](/content-api/#settings).

## Retrieving all tags

Getting all tags from a Ghost site could be used to produce a tag cloud or keyword list:

```gql  theme={"dark"}
{
 allGhostTag(sort: {order: ASC, fields: name}) {
   edges {
     node {
       slug
       url
       postCount
     }
   }
 }
}
```

## Further reading

Many of the GraphQL queries shown above are used within the [Gatsby Starter Ghost](https://github.com/tryghost/gatsby-starter-ghost) template. With a better understanding of how to use queries, customising the starter will become more straightforward.

Additionally, the [Gatsby Source Ghost plugin](https://github.com/TryGhost/gatsby-source-ghost) allows the use of these queries in any existing Gatsby project you may be working on.


# Working With Gridsome
Source: https://docs.ghost.org/jamstack/gridsome

Learn how to spin up a site using Ghost as a headless CMS and build a completely custom front-end with the static site generator Gridsome.

***

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9f48d204-admin-api-gridsome-diagram_hu2f9fbd0b2508e3836ffbb62d9fe4416e_24283_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a61be1fbf35a87b72fdd0803fea1f55c" data-og-width="1000" width="1000" data-og-height="523" height="523" data-path="images/9f48d204-admin-api-gridsome-diagram_hu2f9fbd0b2508e3836ffbb62d9fe4416e_24283_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9f48d204-admin-api-gridsome-diagram_hu2f9fbd0b2508e3836ffbb62d9fe4416e_24283_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=48018183960331f011df3bd9d6c9c7d3 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9f48d204-admin-api-gridsome-diagram_hu2f9fbd0b2508e3836ffbb62d9fe4416e_24283_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=974260c31f243c1e637fbf7b387596ae 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9f48d204-admin-api-gridsome-diagram_hu2f9fbd0b2508e3836ffbb62d9fe4416e_24283_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=fd885b273b6f31a9030eaf5cabf9da90 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9f48d204-admin-api-gridsome-diagram_hu2f9fbd0b2508e3836ffbb62d9fe4416e_24283_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=3f9d135da23a47fc493e322c4d146224 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9f48d204-admin-api-gridsome-diagram_hu2f9fbd0b2508e3836ffbb62d9fe4416e_24283_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=0068cc21c202eeeb4713a9bbff1ab678 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9f48d204-admin-api-gridsome-diagram_hu2f9fbd0b2508e3836ffbb62d9fe4416e_24283_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=43c0761e5e0f2a142121b824b4d5917e 2500w" />
</Frame>

## Prerequisites

This configuration of a Ghost publication requires existing moderate knowledge of JavaScript as well as Vue.js. You’ll need an active Ghost account to get started, which can either be self-hosted or using a [Ghost(Pro) account](https://ghost.org/pricing/).

Finally, you’ll need to install Gridsome globally via the command line in your terminal using the following:

```bash  theme={"dark"}
npm install -g @gridsome/cli
```

Since the [Gridsome Blog Starter](https://gridsome.org/starters/gridsome-blog-starter) works with Markdown files, we’ll cover the adjustments required to swap Markdown files for content coming from your Ghost site.

Creating a new project with the Blog Starter can be done with this command:

```bash  theme={"dark"}
gridsome create gridsome-ghost https://github.com/gridsome/gridsome-starter-blog.git
```

Navigate into the new project:

```bash  theme={"dark"}
cd gridsome-ghost
```

To test everything installed correctly, use the following command to run your project:

```bash  theme={"dark"}
gridsome develop
```

Then navigate to `http://localhost:8080/` in a browser and view the newly created Gridsome site.

### Minimum required version

To make sure that Ghost works with Gridsome, you’ll need to update the dependencies and run **Gridsome version > 0.6.9** (the version used for this documentation).

## Getting started

To get started fetching the content from Ghost, install the official [Ghost source plugin](https://gridsome.org/plugins/@gridsome/source-ghost):

```bash  theme={"dark"}
yarn add @gridsome/source-ghost
```

Once installed, you’ll need to add the plugin to the `gridsome.config.js` file:

```js  theme={"dark"}
  plugins: [
    {
      use: '@gridsome/source-ghost',
      options: {
        baseUrl: 'https://demo.ghost.io',
        contentKey: '22444f78447824223cefc48062',
        routes: {
          post: '/:slug',
          page: '/:slug'
        }
      }
    }
  ]
```

Change the `baseUrl` value to the URL of your Ghost site. For Ghost(Pro) customers, this is the Ghost URL ending in `.ghost.io`, and for people using the self-hosted version of Ghost, it’s the same URL used to access your site.

Next, update the `contentKey` value to a key associated with the Ghost site. A key can be provided by creating an integration within the Ghost Admin. Navigate to Integrations and click “Add new integration”. Name the integration, something related like “Gridsome”, click create.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2d99d7b0b3f46681cdf28d78919637d6" data-og-width="2920" width="2920" data-og-height="1200" height="1200" data-path="images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4eb5d3f87c7433c845273edbb3bf7c76 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f731f4b897bd5965c8c6372c5b4829ab 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=57ea451e943a4db99dd840d4c482bfea 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=99770f82771ad1ad5f4743b9ed20e18b 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7e94d2342b13fb4e50b66f34fd6d5f68 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3dafebd40f6b58424c1c7e1a3fb1f9c0 2500w" />
</Frame>

For more detailed steps on setting up Integrations check out [our documentation on the Content API](/content-api/#authentication).

You can remove the `@gridsome/source-filesystem` plugin if you’re not planning on using Markdown files for your content.

### Post index page

The Gridsome Blog Starter comes with pages and templates which allows you to use Ghost as a headless CMS. To create an index page that loads all of your posts, start by updating the main index page. Find the `Index.vue` file in `/src/pages` of your project and replace the `<page-query>` section with the following:

```vue  theme={"dark"}
<page-query>
{
  posts: allGhostPost(
      sortBy: "published_at",
      order: DESC,
  ) {
    edges {
      node {
        title
        description: excerpt
        date: published_at (format: "D. MMMM YYYY")
        path
        slug
        id
        coverImage: feature_image
      }
    }
  }
}
</page-query>
```

This code renames the GraphQL identifiers in the Gridsome starter of `description` and `coverImage` to `excerpt` and `feature_image`, which matches the data coming from the Ghost API.

### Single post page

Templates in Gridsome follow a [specific naming convention](https://gridsome.org/docs/templates) which uses the type names as defined in the GraphQL schema, so the existing `Post.vue` file in `/src/templates/` needs to be renamed to `GhostPost.vue`.

Once this is done, replace the `<page-query>` section in the template with the following:

```vue  theme={"dark"}
<page-query>
query Post ($path: String!) {
  post: ghostPost (path: $path) {
    title
    path
    date: published_at (format: "D. MMMM YYYY")
    tags {
      id
      title: name
      path
    }
    description: excerpt
    content: html
    coverImage: feature_image
  }
}
</page-query>
```

Gridsome automatically reloads when changes are made in the code and rebuilds the GraphQL schema. Navigate to `http://localhost:8080/` in a web browser to see the result.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d133b440-gridsome-demo-screenshot_hudd87c1a2cfb727c4b441755b186baa41_127706_1200x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=c01735f5d35a1297c7df12fe0be13cd1" data-og-width="1200" width="1200" data-og-height="846" height="846" data-path="images/d133b440-gridsome-demo-screenshot_hudd87c1a2cfb727c4b441755b186baa41_127706_1200x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d133b440-gridsome-demo-screenshot_hudd87c1a2cfb727c4b441755b186baa41_127706_1200x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=612d5ac4a26debdbd092f9ee304a1dc5 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d133b440-gridsome-demo-screenshot_hudd87c1a2cfb727c4b441755b186baa41_127706_1200x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=a5a10aab692b777c249b4b28a2f73ac4 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d133b440-gridsome-demo-screenshot_hudd87c1a2cfb727c4b441755b186baa41_127706_1200x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=24bcfc14859f81d0bc16ea185eaef7bb 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d133b440-gridsome-demo-screenshot_hudd87c1a2cfb727c4b441755b186baa41_127706_1200x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7f4ee68ca16bea163158b15a3437ba48 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d133b440-gridsome-demo-screenshot_hudd87c1a2cfb727c4b441755b186baa41_127706_1200x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4e550d21a98723e6d2b0926dddfd4924 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d133b440-gridsome-demo-screenshot_hudd87c1a2cfb727c4b441755b186baa41_127706_1200x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=01cd854862d93b04ff74a24e8d4b376f 2500w" />
</Frame>

That’s it! Your site now loads posts from your Ghost site, lists them on the home page and renders them in a single view 👏🏼

## Next steps

Discover how to create tag and author archive pages or use other content from Ghost in your Gridsome site in our recipes on the next page. For further information, check out the [Ghost Content API documentation](/content-api/) and the [official Gridsome documentation](https://gridsome.org/docs).

## Examples

The flexibility of the Ghost Content API allows you to feed posts, pages and any other pieces of content from your Ghost site into a Gridsome front-end. Below are a few code examples of how to do this.

If you just landed here, see the [getting started](/jamstack/gridsome/) with Gridsome page for more context!

### Create tag archive pages

Using the [Gridsome Blog Starter](https://gridsome.org/starters/gridsome-blog-starter) as a starting point, rename the current `Tag.vue` template to `GhostTag.vue` and replace the `<page-query>` section with the following:

```vue  theme={"dark"}
<page-query>
query Tag ($path: String!) {
  tag:ghostTag (path: $path) {
    title: name
    slug
    path
    belongsTo {
      edges {
        node {
          ...on GhostPost {
            title
            path
            date: published_at (format: "D. MMMM YYYY")
            description: excerpt
            coverImage: feature_image
            content: html
            slug
          }
        }
      }
    }
  }
}
</page-query>
```

You can now access the tag archive page on `/tag/:slug` which will show all the posts filed under that tag.

### Create author archive pages

To add an author archive page to your site, create a new file in `/src/templates` called `GhostAuthor.vue`. Use the following code within `GhostAuthor.vue`:

```vue  theme={"dark"}
<template>
  <Layout>
    <g-image alt="Author image" class="author__image" v-if="$page.author.profile_image" :src="$page.author.profile_image"/>
    <h1>
      {{ $page.author.name }}
    </h1>

    <div class="posts">
      <PostCard v-for="edge in $page.author.belongsTo.edges" :key="edge.node.id" :post="edge.node"/>
    </div>
  </Layout>
</template>

<page-query>
query Author ($path: String!) {
  author:ghostAuthor (path: $path) {
    name
    path
    profile_image
    belongsTo {
      edges {
        node {
          ...on GhostPost {
            title
            path
            date: published_at (format: "D. MMMM YYYY")
            description: excerpt
            coverImage: feature_image
            content: html
            slug
          }
        }
      }
    }
  }
}
</page-query>

<script>
import PostCard from '~/components/PostCard.vue'

export default {
  components: {
    PostCard
  }
}
</script>
```

This will create an author page, which is available under `/author/:slug` rendering all posts written by this author, along with their unmodified author image (if available) and name.

### Retrieve Ghost settings

The [Gridsome Ghost Source Plugin](https://gridsome.org/plugins/@gridsome/source-ghost) adds site settings to `metaData` within the GraphQL schema. To retrieve that data use the following query:

```js  theme={"dark"}
{
  metaData {
    ghost {
      title
      description
      logo
      icon
      cover_image
      facebook
      twitter
      lang
      timezone
      navigation {
        label
        url
      }
      url
    }
  }
}
```

## Further reading

Learn more about the Ghost API and specific endpoints in our [API documentation](/content-api/). Otherwise check out our Integrations and how you can deploy your Gridsome site to platforms such as [Netlify](https://ghost.org/integrations/netlify/).


# Working With Hexo
Source: https://docs.ghost.org/jamstack/hexo

Learn how to spin up a site using Ghost as a headless CMS and build a completely custom front-end with the static site generator [Hexo](https://hexo.io/).

***

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/475ff02f-admin-api-hexo-diagram_hu3b9f840b657d987f18be8e33ee5f1379_19974_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d5530f107a74188c8b6960d4a9b20893" data-og-width="1000" width="1000" data-og-height="523" height="523" data-path="images/475ff02f-admin-api-hexo-diagram_hu3b9f840b657d987f18be8e33ee5f1379_19974_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/475ff02f-admin-api-hexo-diagram_hu3b9f840b657d987f18be8e33ee5f1379_19974_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d05bbf37102e6ce84b917add539fd0dc 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/475ff02f-admin-api-hexo-diagram_hu3b9f840b657d987f18be8e33ee5f1379_19974_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=809ed0ce24b64dde0c02a4e37e658002 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/475ff02f-admin-api-hexo-diagram_hu3b9f840b657d987f18be8e33ee5f1379_19974_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=aa4c25f8c5bddec7ac98acddaf1c43c6 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/475ff02f-admin-api-hexo-diagram_hu3b9f840b657d987f18be8e33ee5f1379_19974_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a4a8e85f86ba558d4eb937df6873524f 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/475ff02f-admin-api-hexo-diagram_hu3b9f840b657d987f18be8e33ee5f1379_19974_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=75821bb95c3d55d8e5b30f02117c5de3 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/475ff02f-admin-api-hexo-diagram_hu3b9f840b657d987f18be8e33ee5f1379_19974_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7d5f5c9904398287f7589da413f92c32 2500w" />
</Frame>

## Prerequisites

This configuration of a Ghost publication requires existing moderate knowledge of JavaScript. You’ll need an active Ghost account to get started, which can either be self-hosted or using a [Ghost(Pro) account](https://ghost.org/pricing/).

Additionally, you’ll need to install Hexo via the command line:

```bash  theme={"dark"}
npm install -g hexo-cli
```

This documentation also assumes Ghost will be added to an existing Hexo site. creating a new Hexo site can be done with the following command:

```bash  theme={"dark"}
hexo init my-hexo-site
```

Running the Hexo site locally can be done by running `hexo server` and navigating to `http://localhost:4000/` in a web browser.

More information on setting up and creating a Hexo site can be found on [the official Hexo site](https://hexo.io/docs/setup).

## Getting started

Firstly, create a new JavaScript file within a `scripts` folder at the root of the project directory, for example `./scripts/ghost.js` . Any script placed in the scripts folder acts like a Hexo script plugin, you can find out more about the [Plugins API in the Hexo documentation](https://hexo.io/docs/plugins).

Next, install the official [JavaScript Ghost Content API](/content-api/javascript/#installation) helper using:

```bash  theme={"dark"}
yarn add @tryghost/content-api
```

Once the Content API helper is installed it can be used within the newly created `ghost.js` Hexo script:

```js  theme={"dark"}
const ghostContentAPI = require("@tryghost/content-api");

const api = new ghostContentAPI({
  url: 'https://demo.ghost.io',
  key: '22444f78447824223cefc48062',
  version: "v6.0"
});
```

Change the `url` value to the URL of the Ghost site. For Ghost(Pro) customers, this is the Ghost URL ending in .ghost.io, and for people using the self-hosted version of Ghost, it’s the same URL used to view the admin panel.

Create a custom integration within Ghost Admin to generate a key and change the `key` value.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2d99d7b0b3f46681cdf28d78919637d6" data-og-width="2920" width="2920" data-og-height="1200" height="1200" data-path="images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4eb5d3f87c7433c845273edbb3bf7c76 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f731f4b897bd5965c8c6372c5b4829ab 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=57ea451e943a4db99dd840d4c482bfea 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=99770f82771ad1ad5f4743b9ed20e18b 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7e94d2342b13fb4e50b66f34fd6d5f68 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3dafebd40f6b58424c1c7e1a3fb1f9c0 2500w" />
</Frame>

For more detailed steps on setting up Integrations check out [our documentation on the Content API](/content-api/#authentication).

### The code

Once the API integration has been setup, content can be pulled from your Ghost site. To get all posts, use the [`api.posts.browse()`](/content-api/javascript/#endpoints) endpoint:

```js  theme={"dark"}
// Store Ghost posts in a 'data' variable
const data = await api.posts
  .browse({
    limit: 100
  })
  .catch(err => {
    console.error(err);
  });
```

This post data can then be used to create posts within Hexo. Creating posts can be done with the `hexo.post.create()` function. The instance of `hexo` is already globally available inside of Hexo script files.

```js  theme={"dark"}
data.forEach(post => {

  // Create a 'Hexo friendly' post object
  const postData = {
    title: post.title,
    slug: post.slug,
    path: post.slug,
    date: post.published_at,
    content: post.html
  };

  // Use post data to create a post
  hexo.post.create(postData, true);
});
```

### Promise based API

The Ghost Content API is ‘Promised based’ meaning the JavaScript library will wait for all the content to be retrieved before it fully completes. Due to this the whole script needs to be wrapped in an `async` function. Here’s a full example:

```js  theme={"dark"}
const ghostContentAPI = require("@tryghost/content-api");

const api = new ghostContentAPI({
  url: "https://demo.ghost.io",
  key: "22444f78447824223cefc48062",
  version: "v6.0"
});

const ghostPostData = async () => {
  const data = await api.posts
    .browse({
      limit: 100
    })
    .catch(err => {
      console.error(err);
    });

  data.forEach(post => {
    const postData = {
      title: post.title,
      slug: post.slug,
      path: post.slug,
      date: post.published_at,
      content: post.html
    }

    hexo.post.create(postData, true);
  });
};

ghostPostData();
```

For the changes to take affect the Hexo site needs to be restarted using `hexo server` in the command line and navigate to `http://localhost:4000/` in a web browser.

## Next steps

The example code above is the most straightforward approach to using Ghost with Hexo. To use other content such as pages, authors and site data check out the [JavaScript Content API documentation](/content-api/javascript/#endpoints). As well as our documentation there’s the [official Hexo documentation](https://hexo.io/) which explains other ways Hexo can accept data.

## Examples

The flexibility of the [Ghost Content API](/content-api/javascript/) allows you to generate posts, pages and any other pieces of content from a Ghost site and send it to a front-end built with the Node.js based static site generator, Hexo.

Below are a few examples of how various types of content can be sent to your Hexo front-end. All examples assume that the API has already been setup, see the [Working with Hexo](/jamstack/hexo/) page for more information.

## Generate pages

Pages require a slightly different approach to generating posts as they need to be placed at root level. Use the following code in conjunction with the JavaScript Ghost Content API:

```js  theme={"dark"}
const ghostPages = async () => {

  // Get all pages
  const data = await api.pages
    .browse({
      limit: 100
    })
    .catch(err => {
      console.error(err);
    });

  data.forEach(page => {
    hexo.extend.generator.register(page.slug, function(locals) {
      return {
        path: `${page.slug}/index.html`,
        data: { title: page.title, content: page.html },
        layout: ["page", "index"]
      };
    });
  });
};

ghostPages();
```

Note the use of `hexo.extend.generator.register`, which is how scripts inside of a Hexo can generate files alongside the build process.

## Generate author pages

Author pages can also be generated using the following method. This also uses the `generator` extension in Hexo that was used in the pages example above. To prevent URL collisions these author pages are being created under an `/authors/` path.

```js  theme={"dark"}
const ghostAuthors = async () => {

  // Get all post authors
  const data = await api.authors
    .browse({
      limit: 100
    })
    .catch(err => {
      console.error(err);
    });

  data.forEach(author => {
    hexo.extend.generator.register(author.slug, function(locals) {
      return {

        // Set an author path to prevent URL collisions
        path: `/author/${author.slug}/index.html`,
        data: {
          title: author.name,
          content: `<p>${author.bio}</p>`
        },
        layout: ["author", "index"]
      };
    });
  });
};

ghostAuthors();
```

## Adding post meta

All the metadata that is exposed by the [Ghost Content API](/content-api/#endpoints) is available to use inside of a Hexo site. That includes post meta like authors and tags.

In the example below the `posts.browse()` API options have been changed to include tags and authors which will be attached to each post object when it is returned. More information on the `include` API option can be found in our [Content API Endpoints](/content-api/#include) documentation.

```js  theme={"dark"}
const data = await api.posts
  .browse({
    // Ensure tags and authors is included in post objects
    include: "tags,authors",
    limit: 100
  })
  .catch(err => {
    console.error(err);
  });

  data.forEach(post => {
  const postData = {
    title: post.title,
    slug: post.slug,
    path: post.slug,
    date: post.published_at,
    content: post.html,

    // Set author meta
    author: {
      name: post.primary_author.name,
      slug: `/author/${post.primary_author.slug}`,
    },

    // Set tag meta
    tags: post.tags
      .map(tag => {
        return tag.name;
      })
      .join(", ")
  };
  hexo.post.create(postData, true);
});
```

The `author.slug` includes `/authors/` in the string so it correlates with [the previous author pages example](#generate-author-pages). Note as well that some manipulation has been performed on tags so it matches the expected format for Hexo (comma separated tags).

## Further reading

We highly recommend reading into the [official Hexo documentation](https://hexo.io/docs) for more info on how pages are generated. There’s also a handy [Troubleshooting page](https://hexo.io/docs/troubleshooting.html) for any common issues encountered.

Additionally there’s [plenty of themes for Hexo](https://hexo.io/themes/) that might be a good place to start when creating a custom Hexo site.


# Working With Next.Js
Source: https://docs.ghost.org/jamstack/next

Learn how to spin up a JavaScript app using Ghost as a headless CMS and build a completely custom front-end with the [Next.js](https://nextjs.org/) React framework.

***

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6b2669d8-admin-api-nextjs-diagram_hu6b6862f95924f13ac7cefb7109ba7c36_20338_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=ccb06c2d8bba4c0a654cd287b17ca205" data-og-width="1000" width="1000" data-og-height="523" height="523" data-path="images/6b2669d8-admin-api-nextjs-diagram_hu6b6862f95924f13ac7cefb7109ba7c36_20338_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6b2669d8-admin-api-nextjs-diagram_hu6b6862f95924f13ac7cefb7109ba7c36_20338_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=b3a889a537132cb37f42b769656d3abf 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6b2669d8-admin-api-nextjs-diagram_hu6b6862f95924f13ac7cefb7109ba7c36_20338_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=3fbafbd5032c763d52f6f5ed7e15054f 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6b2669d8-admin-api-nextjs-diagram_hu6b6862f95924f13ac7cefb7109ba7c36_20338_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=acbbfc99266c647cdf57e30c878a2a90 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6b2669d8-admin-api-nextjs-diagram_hu6b6862f95924f13ac7cefb7109ba7c36_20338_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=18abdcba014f9fd165f7ebee2d331a90 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6b2669d8-admin-api-nextjs-diagram_hu6b6862f95924f13ac7cefb7109ba7c36_20338_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=cf8947a0473a5c2c91a39199c0afdbc2 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6b2669d8-admin-api-nextjs-diagram_hu6b6862f95924f13ac7cefb7109ba7c36_20338_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=31aa5065e0009dae399962f78088c9b9 2500w" />
</Frame>

<Note>
  Hey, I finally have a new website 👋\
  \
  I’m a founder, designer, and filmmaker — and I’m trying to capture a bit more of all of this with my new site.\
  \
  Had a lot of fun making this in Next.js, with [@TryGhost](https://twitter.com/TryGhost?ref_src=twsrc%5Etfw) as backend, deployed on [@vercel](https://twitter.com/vercel?ref_src=twsrc%5Etfw).\
  \
  Check it out → [https://t.co/iawYNTuB8y](https://t.co/iawYNTuB8y) [pic.twitter.com/o1i81y5uL6](https://t.co/o1i81y5uL6)

  — Fabrizio Rinaldi (@linuz90) [August 3, 2021](https://twitter.com/linuz90/status/1422574429754822661?ref_src=twsrc%5Etfw)
</Note>

## Prerequisites

This configuration of a Ghost publication requires existing moderate knowledge of JavaScript and [React](https://reactjs.org/). You’ll need an active Ghost account to get started, which can either be self-hosted or using [Ghost(Pro)](https://ghost.org/pricing/).

Additionally, you’ll need to setup a React & Next.js application via the command line:

```bash  theme={"dark"}
yarn create next-app
```

Then answer the prompts. The examples in these docs answer "No" to all for simplicity:
<Warning>**Note this uses the [pages router](https://nextjs.org/docs/pages), not the [app router](https://nextjs.org/docs/app/getting-started).**</Warning>

```bash  theme={"dark"}
✔ What is your project named? … my-next-app
✔ Would you like to use TypeScript? … **No** / Yes
✔ Would you like to use ESLint? … **No** / Yes
✔ Would you like to use Tailwind CSS? … **No** / Yes
✔ Would you like your code inside a src/ directory? … **No** / Yes
✔ Would you like to use App Router? … **No** / Yes
✔ Would you like to use Turbopack for next dev? … **No** / Yes
✔ Would you like to customize the import alias? … **No** / Yes
```

Finally, start the app:

```bash  theme={"dark"}
cd my-next-app
yarn dev
```

Next.js can also be setup manually – refer to the [official Next.js documentation](https://nextjs.org/docs) for more information.

## Getting started

Thanks to the [JavaScript Content API Client Library](/content-api/javascript/), it’s possible for content from a Ghost site can be directly accessed within a Next.js application.

Create a new file called `posts.js` within an `lib/` directory. This file will contain all the functions needed to request Ghost post content, as well as an instance of the Ghost Content API.

Install the official [JavaScript Ghost Content API](/content-api/javascript/#installation) helper using:

```bash  theme={"dark"}
yarn add @tryghost/content-api
```

Once the helper is installed it can be added to the `posts.js` file using a [static `import` statement](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import):

```js  theme={"dark"}
import GhostContentAPI from "@tryghost/content-api";
```

Now an instance of the Ghost Content API can be created using Ghost site credentials:

```js  theme={"dark"}
// lib/posts.js - or make a separate file to reuse for other resources
import GhostContentAPI from "@tryghost/content-api";

// Create API instance with site credentials
const api = new GhostContentAPI({
  url: 'https://demo.ghost.io',
  key: '22444f78447824223cefc48062',
  version: "v6.0"
});
```

Change the `url` value to the URL of the Ghost site. For Ghost(Pro) customers, this is the Ghost URL ending in `.ghost.io`, and for people using the self-hosted version of Ghost, it’s the same URL used to view the admin panel.

Create a custom integration within Ghost Admin to generate a key and change the `key` value.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2d99d7b0b3f46681cdf28d78919637d6" data-og-width="2920" width="2920" data-og-height="1200" height="1200" data-path="images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4eb5d3f87c7433c845273edbb3bf7c76 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f731f4b897bd5965c8c6372c5b4829ab 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=57ea451e943a4db99dd840d4c482bfea 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=99770f82771ad1ad5f4743b9ed20e18b 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7e94d2342b13fb4e50b66f34fd6d5f68 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3dafebd40f6b58424c1c7e1a3fb1f9c0 2500w" />
</Frame>

For more detailed steps on setting up Integrations check out [our documentation on the Content API](/content-api/#authentication).

### Exposing content

The [`posts.browse()`](/content-api/javascript/#endpoints) endpoint can be used to get all the posts from a Ghost site. This can be done with the following code as an asynchronous function:

```js  theme={"dark"}
export async function getPosts() {
  return await api.posts
    .browse({
      limit: 15 // default is 15, max is 100
    })
    .catch(err => {
      console.error(err);
    });
}
```

Using an asynchronous function means Next.js will wait until all the content has been retrieved from Ghost before loading the page. The `export` function means your content will be available throughout the application.

### Rendering posts

Since you’re sending content from Ghost to a React application, data is passed to pages and components with [`props`](https://react.dev/learn/passing-props-to-a-component). Next.js extends upon that concept with [`getStaticProps`](https://nextjs.org/docs/pages/building-your-application/data-fetching/get-static-props). This function will load the Ghost site content into the page before it’s rendered in the browser.

Use the following to import the `getPosts` function created in previous steps within a page you want to render Ghost posts, like `pages/index.js`:

```js  theme={"dark"}
import { getPosts } from '../lib/posts';
```

The posts can be fetched from within `getStaticProps` for the given page:

```js  theme={"dark"}
export async function getStaticProps() {
  const posts = await getPosts()

  if (!posts) {
    return {
      notFound: true,
    }
  }

  return {
    props: { posts }
  }
}
```

Now the posts can be used within the `Home` page in `pages/index.js` via the component `props`:

```js  theme={"dark"}
export default function Home(props) {
  return (
      <ul>
        {props.posts.map((post) => (
          <li key={post.id}>{post.title}</li>
        ))}
      </ul>
  );
}
```

Pages in Next.js are stored in a `pages/` directory. To find out more about how pages work [check out the official documentation](https://nextjs.org/docs/pages/building-your-application/routing/pages-and-layouts).

### Rendering a single post

Retrieving Ghost content from a single post can be done in a similar fashion to retrieving all posts. By using [`posts.read()`](/content-api/javascript/#endpoints) it’s possible to query the Ghost Content API for a particular post using a [post `id` or `slug`](/content-api/posts).

Reopen the `lib/posts.js` file and add the following async function:

```js  theme={"dark"}
export async function getSinglePost(postSlug) {
  return await api.posts
    .read({
      slug: postSlug
    })
    .catch(err => {
      console.error(err);
    });
}
```

This function accepts a single `postSlug` parameter, which will be passed down by the template file using it. The page slug can then be used to query the Ghost Content API and get the associated post data back.

Next.js provides [dynamic routes](https://nextjs.org/docs/pages/building-your-application/routing/dynamic-routes) for pages that don’t have a fixed URL / slug. The name of the js file will be the variable, in this case the post `slug`, wrapped in square brackets – `[slug].js`.

In order to generate these routes, Next.js needs to know the slug for each post. This is accomplished by using `getStaticPaths` in `posts/[slug].js`.

Create another function in `lib/posts.js` called `getAllPostSlugs`. The maximum amount of items that can be fetched from a resource at once is 100, so use pagination to make sure all the slugs are fetched:

```js  theme={"dark"}
export async function getAllPostSlugs() {
  try {
    const allPostSlugs = [];
    let page = 1;
    let hasMore = true;

    while (hasMore) {
      const posts = await api.posts.browse({
        limit: 100,
        page,
        fields: "slug", // Only the slug field is needed
      });

      if (posts && posts.length > 0) {
        allPostSlugs.push(...posts.map((item) => item.slug));
        // Use the meta pagination info to determine if there are more pages
        page = posts.meta.pagination.next;
        hasMore = page !== null;
      } else {
        hasMore = false;
      }
    }

    return allPostSlugs;
  } catch (err) {
    console.error(err);
    return [];
  }
}
```

Now  `getSinglePost()` and `getAllPostSlugs()` can be used within the `pages/posts/[slug].js` file like so:

```js  theme={"dark"}
// pages/posts/[slug].js

import { getSinglePost, getAllPostSlugs } from '../../lib/posts';

// PostPage page component
export default function PostPage(props) {
  // Render post title and content in the page from props
  // note the html field only populates for public posts in this example
  return (
    <div>
      <h1>{props.post.title}</h1>
      <div dangerouslySetInnerHTML={{ __html: props.post.html }} />
    </div>
  )
}

export async function getStaticPaths() {
  const slugs = await getAllPostSlugs()

  // Get the paths we want to create based on slugs
  const paths = slugs.map((slug) => ({
    params: { slug: slug },
  }))

  // { fallback: false } means posts not found should 404.
  return { paths, fallback: false }
}


// Pass the page slug over to the "getSinglePost" function
// In turn passing it to the posts.read() to query the Ghost Content API
export async function getStaticProps(context) {
  const post = await getSinglePost(context.params.slug)

  if (!post) {
    return {
      notFound: true,
    }
  }

  return {
    props: { post }
  }
}
```

Pages can be linked to with the Next.js `<Link/>` component. Calling it can be done with:

```js  theme={"dark"}
import Link from 'next/link';
```

The `Link` component is used like so:

```js  theme={"dark"}
// pages/index.js
export default function Home(props) {
  return (
    <ul>
      {props.posts.map((post) => (
        <li key={post.id}>
          <Link href={`posts/${post.slug}`}>{post.title}</Link>
        </li>
      ))}
    </ul>
  );
}
```

Pages are linked in this fashion within Next.js applications to make full use of client-side rendering as well as server-side rendering. To read more about how the `Link` component works and it’s use within Next.js apps [check out their documentation](https://nextjs.org/docs/pages/api-reference/components/link).

## Examples

The flexibility of the [Ghost Content API](/content-api/javascript/) allows you to feed posts, pages and any other pieces of content from Ghost site into a Next.js JavaScript app.

Below are a few examples of how content from Ghost can be passed into a Next.js project.

### Getting pages

Pages can be generated in the [same fashion as posts](/jamstack/next/#exposing-content), and can even use the same dynamic route file.

```js  theme={"dark"}
export async function getPages() {
  return await api.pages
    .browse({
      limit: 15 // default is 15, max is 100
    })
    .catch(err => {
      console.error(err);
    });
}
```

### Adding post attribute data

Using the `include` option within the Ghost Content API means that attribute data, such as tags and authors, will be included in the post object data:

```js  theme={"dark"}
export async function getPosts() {
  return await api.posts
    .browse({
      include: "tags,authors",
      limit: 15 // default is 15, max is 100
    })
    .catch(err => {
      console.error(err);
    });
}
```

### Rendering author pages

An author can be requested using the [`authors.read()`](/content-api/javascript/#endpoints) endpoint.

```js  theme={"dark"}
export async function getAuthor(authorSlug) {
  return await api.authors
    .read({
      slug: authorSlug
    })
    .catch(err => {
      console.error(err);
    });
}
```

A custom author template file can be created at `pages/authors/[slug].js`, which will also prevent author URLs colliding with post and page URLs:

```js  theme={"dark"}
// pages/authors/[slug].js
import { getSingleAuthor, getAllAuthorSlugs } from "../../lib/authors";

export default function AuthorPage(props) {
  return (
    <div>
      <h1>{props.author.name}</h1>
      <div dangerouslySetInnerHTML={{ __html: props.author.bio }} />
    </div>
  );
}

export async function getStaticPaths() {
  const slugs = await getAllAuthorSlugs();
  const paths = slugs.map((slug) => ({
    params: { slug },
  }));

  return { paths, fallback: false };
}

export async function getStaticProps(context) {
  const author = await getSingleAuthor(context.params.slug);

  if (!author) {
    return {
      notFound: true,
    };
  }

  return {
    props: { author },
  };
}
```

### Formatting post dates

The published date of a post, `post.published_at`, is returned as a date timestamp. Modern JavaScript methods can convert this date into a selection of humanly readable formats. To output the published date as “Aug 28, 1963”:

```js  theme={"dark"}
const posts = await getPosts();

posts.map(post => {
  const options = {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  };

  post.dateFormatted = new Intl.DateTimeFormat('en-US', options)
    .format(new Date(post.published_at));
});
```

The date can then be added to the template using `{post.dateFormatted}`.

## Further reading

Check out the extensive [Next.js documentation](https://nextjs.org/docs/pages) and [learning courses](https://nextjs.org/learn/pages-router) for more information and to get more familiar when working with Next.js.


# Working With Nuxt
Source: https://docs.ghost.org/jamstack/nuxt

Learn how to spin up a JavaScript app using Ghost as a headless CMS and build a completely custom front-end with [Vue](https://vuejs.org/) and [Nuxt](https://nuxt.com/).

***

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/42d1fa48-admin-api-nuxtjs-diagram_hu375cbbfa1a94894673da10397be553a4_21624_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=252223cb50cc70d4598ece4de6857ffc" data-og-width="1000" width="1000" data-og-height="523" height="523" data-path="images/42d1fa48-admin-api-nuxtjs-diagram_hu375cbbfa1a94894673da10397be553a4_21624_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/42d1fa48-admin-api-nuxtjs-diagram_hu375cbbfa1a94894673da10397be553a4_21624_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8bcf90307d5a75e65ab052490ff049ce 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/42d1fa48-admin-api-nuxtjs-diagram_hu375cbbfa1a94894673da10397be553a4_21624_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=42e056a5bec6c8f9e78e2d3089aa4d33 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/42d1fa48-admin-api-nuxtjs-diagram_hu375cbbfa1a94894673da10397be553a4_21624_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f2e4c34d7ca35daf67f62f927c0af941 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/42d1fa48-admin-api-nuxtjs-diagram_hu375cbbfa1a94894673da10397be553a4_21624_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=c85a7e6290f8428e708e8541ced42689 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/42d1fa48-admin-api-nuxtjs-diagram_hu375cbbfa1a94894673da10397be553a4_21624_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8e56ee065c0c09a223d02122ee904ed0 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/42d1fa48-admin-api-nuxtjs-diagram_hu375cbbfa1a94894673da10397be553a4_21624_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=85a3ed2a40e40c042fc103b11e07e443 2500w" />
</Frame>

## Prerequisites

This configuration of a Ghost publication requires existing moderate knowledge of JavaScript as well as Vue.js. You’ll need an active Ghost account to get started, which can either be self-hosted or using [Ghost(Pro)](https://ghost.org/pricing/).

Additionally, you’ll need to setup a Nuxt application via the command line:

```bash  theme={"dark"}
yarn create nuxt-app my-nuxt-app
cd my-nuxt-app
yarn dev
```

To install Nuxt manually refer to the [official documentation](https://nuxt.com/docs/4.x/getting-started/installation) for more information.

## Getting started

Thanks to the [JavaScript Content API Client Library](/content-api/javascript/), content from a Ghost site can be directly accessed within a Nuxt application.

Create a new file called `posts.js` within an `api/` directory. This file will contain all the functions needed to request Ghost post content, as well as an instance of the Ghost Content API.

Install the official JavaScript Ghost Content API helper using:

```bash  theme={"dark"}
yarn add @tryghost/content-api
```

Once the helper is installed it can be added to the `posts.js` file using a static `import` statement:

```js  theme={"dark"}
import GhostContentAPI from "@tryghost/content-api";
```

Now an instance of the Ghost Content API can be created using Ghost site credentials:

```js  theme={"dark"}
import GhostContentAPI from "@tryghost/content-api";

// Create API instance with site credentials
const api = new GhostContentAPI({
  url: 'https://demo.ghost.io',
  key: '22444f78447824223cefc48062',
  version: "v6.0"
});
```

Change the `url` value to the URL of the Ghost site. For Ghost(Pro) customers, this is the Ghost URL ending in .ghost.io, and for people using the self-hosted version of Ghost, it’s the same URL used to view the admin panel.

Create a custom integration within Ghost Admin to generate a key and change the `key` value.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2d99d7b0b3f46681cdf28d78919637d6" data-og-width="2920" width="2920" data-og-height="1200" height="1200" data-path="images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4eb5d3f87c7433c845273edbb3bf7c76 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f731f4b897bd5965c8c6372c5b4829ab 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=57ea451e943a4db99dd840d4c482bfea 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=99770f82771ad1ad5f4743b9ed20e18b 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7e94d2342b13fb4e50b66f34fd6d5f68 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3dafebd40f6b58424c1c7e1a3fb1f9c0 2500w" />
</Frame>

For more detailed steps on setting up Integrations check out [our documentation on the Content API](/content-api/#authentication).

### Exposing content

The [`posts.browse()`](/content-api/javascript/#endpoints) endpoint can be used to get all the posts from a Ghost site. This can be done with the following code as an asynchronous function:

```js  theme={"dark"}
export async function getPosts() {
  return await api.posts
    .browse({
      limit: 100
    })
    .catch(err => {
      console.error(err);
    });
}
```

Using an `async` function means the Nuxt application will wait until all the content has been retrieved before loading the page. Since this function is being exported using the `export` notation, it will be available throughout the application.

### Rendering posts

Since Nuxt is based on `.vue`, files can contain HTML, CSS and JavaScript to create a neatly packaged up component. For more information check out the [official Vue.js documentation](https://vuejs.org/guide/scaling-up/sfc.html).

To render out a list of posts from a Ghost site, create a new `index.vue` file within a `pages/` directory of your Nuxt project. Use the following code to expose the `getPosts` function within the `index.vue` file:

```vue  theme={"dark"}
<script>
  import { getPosts } from '../api/posts';

  ...
</script>
```

The posts are provided as data to the rest of the `.vue` file using a [`asyncData` function](https://nuxtjs.org/api/) within the Nuxt framework:

```vue  theme={"dark"}
<script>
  import { getPosts } from '../api/posts';

  export default {
    async asyncData () {
      const posts = await getPosts();
      return { posts: posts }
    }
  }
</script>
```

Posts will now be available to use within that file and can be generated as a list using [Vue.js list rendering](https://vuejs.org/guide/essentials/list.html):

```vue  theme={"dark"}
<template>
  <ul>
    <li v-for="post in posts">{{ post.title }}</li>
  </ul>
</template>

<script>
  import { getPosts } from '../api/posts';

  export default {
    async asyncData () {
      const posts = await getPosts();
      return { posts: posts }
    }
  }
</script>
```

For more information about how pages work, check out the [Nuxt pages documentation](https://nuxt.com/docs/4.x/getting-started/views#pages).

### Rendering a single post

Retrieving Ghost content from a single post can be done in a similar fashion to retrieving all posts. By using [`posts.read()`](/content-api/javascript/#endpoints) it’s possible to query the Ghost Content API for a particular post using a post id or slug.

Reopen the `api/posts.js` file and add the following async function:

```js  theme={"dark"}
export async function getSinglePost(postSlug) {
  return await api.posts
    .read({
      slug: postSlug
    })
    .catch(err => {
      console.error(err);
    });
}
```

This function accepts a single `postSlug` parameter, which will be passed down by the template file using it. The page slug can then be used to query the Ghost Content API and get the associated post data back.

Nuxt provides [dynamic routes](https://nuxt.com/docs/4.x/guide/directory-structure/app/pages#dynamic-routes) for pages that don’t have a fixed URL/slug. The name of the js file will be the variable, in this case the post slug, prefixed with an underscore – `_slug.vue`.

The `getSinglePost()` function can be used within the `_slug.vue` file like so:

```vue  theme={"dark"}
<template>
  <div>
    <h1>{{ post.title }}</h1>
    <div v-html="post.html"/>
  </div>
</template>

<script>
  import { getSinglePost } from '../api/posts';

  export default {
    async asyncData ({ params }) {
      const post = await getSinglePost(params.slug);
      return { post: post }
    }
  }
</script>
```

The `<nuxt-link/>` component can be used with the `post.slug` to link to posts from the listed posts in `pages/index.vue`:

```vue  theme={"dark"}
<template>
  <ul>
    <li v-for="post in posts">
      <nuxt-link :to="{ path: post.slug }">{{ post.title }}</nuxt-link>
    </li>
  </ul>
</template>
```

Pages are linked in this fashion to make full use of client-side rendering as well as server-side rendering. To read more about how the `<nuxt-link/>` component works, [check out the official documentation](https://nuxt.com/docs/4.x/api/components/nuxt-link).

## Next steps

Well done! You should have now retrieved posts from the Ghost Content API and sent them to your Nuxt site. For examples of how to extend this further by generating content pages, author pages or exposing post attributes, read our useful recipes.

Don’t forget to refer to the [official Nuxt guides](https://nuxt.com/docs/4.x/guide) and [API documentation](https://nuxt.com/docs/4.x/api) to get a greater understanding of the framework.

## Examples

The flexibility of the [Ghost Content API](/content-api/javascript/) allows you to feed posts, pages and any other pieces of content from any Ghost site into a Nuxt JavaScript app.

Below are a few examples of how content from Ghost can be passed into a Nuxt project. If you just landed here, see the [Nuxt](/jamstack/nuxt/) page for more context!

## Getting pages

Pages can be generated in the [same fashion as posts](/jamstack/nuxt/#exposing-content), and can even use the same dynamic route file.

```js  theme={"dark"}
export async function getPages() {
  return await api.pages
    .browse({
      limit: 100
    })
    .catch(err => {
      console.error(err);
    });
}
```

## Adding post attribute data

Using the `include` option within the Ghost Content API means that attribute data, such as tags and authors, will be included in the post object data:

```js  theme={"dark"}
export async function getPosts() {
  return await api.posts
    .browse({
      include: "tags,authors",
      limit: 100
    })
    .catch(err => {
      console.error(err);
    });
}
```

### Rendering author pages

An author can be requested using the [`authors.read()`](/content-api/javascript/#endpoints) endpoint.

```js  theme={"dark"}
export async function getAuthor(authorSlug) {
  return await api.authors
    .read({
      slug: authorSlug
    })
    .catch(err => {
      console.error(err);
    });
}
```

A custom author template file can be created at `pages/authors/_slug.vue`, which will also prevent author URLs colliding with post and page URLs:

```vue  theme={"dark"}
<template>
  <div>
    <h1>{{ author.title }}</h1>
    <p>{{ author.bio }}</p>
  </div>
</template>

<script>
  import { getAuthor } from '../api/authors';

  export default {
    async asyncData ({ params }) {
      const author = await getAuthor(params.query.slug);
      return { author: author }
    }
  }
</script>
```

### Formatting post dates

The published date of a post, `post.published_at`, is returned as a date timestamp. Modern JavaScript methods can convert this date into a selection of human-readable formats. To output the published date as “Aug 28, 1963”:

```js  theme={"dark"}
const posts = await getPosts();

posts.map(post => {
  const options = {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  };

  post.dateFormatted = new Intl.DateTimeFormat('en-US', options)
    .format(new Date(post.published_at));
});
```

The date can then be added to the Vue template using `{{post.dateFormatted}}`.

## Further reading

Check out the extensive [Nuxt API documentation](https://nuxt.com/docs/4.x/api) and [guide](https://nuxt.com/docs/4.x/guide). Additionally the Nuxt site [lists a few examples](https://nuxt.com/docs/4.x/examples/hello-world) that can provide a great starting point.


# Working With VuePress
Source: https://docs.ghost.org/jamstack/vuepress

Learn how to spin up a site using Ghost as a headless CMS and build a completely custom front-end with the static site generator VuePress.

***

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d5e8cf23-admin-api-vuepress-diagram_hu479ca4e1d45fe16dac7e97dee4f908aa_21038_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=1d996e04bc4a428b189c124ed5abcc77" data-og-width="1000" width="1000" data-og-height="523" height="523" data-path="images/d5e8cf23-admin-api-vuepress-diagram_hu479ca4e1d45fe16dac7e97dee4f908aa_21038_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d5e8cf23-admin-api-vuepress-diagram_hu479ca4e1d45fe16dac7e97dee4f908aa_21038_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2fb5f482f350ab6c110300bca2b6cf7b 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d5e8cf23-admin-api-vuepress-diagram_hu479ca4e1d45fe16dac7e97dee4f908aa_21038_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=52121a41ab786b25cc90d49627b50f7e 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d5e8cf23-admin-api-vuepress-diagram_hu479ca4e1d45fe16dac7e97dee4f908aa_21038_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=1a188e0f7b05d466b648ef8d5feb0a79 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d5e8cf23-admin-api-vuepress-diagram_hu479ca4e1d45fe16dac7e97dee4f908aa_21038_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=798bcb5b068f047303ec2724994cb0e6 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d5e8cf23-admin-api-vuepress-diagram_hu479ca4e1d45fe16dac7e97dee4f908aa_21038_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=1998ef9b0abdf66d84b48538e85031f5 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d5e8cf23-admin-api-vuepress-diagram_hu479ca4e1d45fe16dac7e97dee4f908aa_21038_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4e6ce23319699320b26e171681ec74ff 2500w" />
</Frame>

## Prerequisites

You’ll need basic understanding of JavaScript and a running Ghost installation, which can either be self-hosted or using [Ghost(Pro)](https://ghost.org/pricing/). In this documentation we’re going to start with a new project from scratch. Skip these initial setup steps if you have an existing VuePress project.

Firstly, create a new project:

```bash  theme={"dark"}
# create the new project folder
mkdir vuepress-ghost

# navigate to the newly created folder
cd vuepress-ghost
```

Now that the project is created, you can add VuePress as a dependency:

```bash  theme={"dark"}
yarn add vuepress
```

Finally, add the VuePress build and serve commands to the scripts in your `package.json`:

```json  theme={"dark"}
// package.json

{
  "scripts": {
    "dev": "vuepress dev",
    "build": "vuepress build"
  }
}
```

## Getting started

Since VuePress uses Markdown files, you’ll need to create a script that uses the Ghost Content API and creates Markdown files from your content.

### Exposing and converting content

The following script gives you a good starting point as well as an idea of what’s possible. This is a minimal working version and does not cover:

* removing deleted/unpublished posts.
* renaming or skipping frontmatter properties.

Install the Ghost Content API package and additional dependencies that we’re going to use in this script:

```bash  theme={"dark"}
yarn add @tryghost/content-api js-yaml fs-extra
```

`js-yaml` will create yaml frontmatter and `fs-extra` will place the Markdown files in the right directories.

To start, create a new file in the root directory of your project:

```js  theme={"dark"}
// createMdFilesFromGhost.js

const GhostContentAPI = require('@tryghost/content-api');
const yaml = require('js-yaml');
const fs = require('fs-extra');
const path = require('path');

const api = new GhostContentAPI({
    url: 'https://demo.ghost.io', // replace with your Ghost API URL
    key: '22444f78447824223cefc48062', // replace with your API key
    version: "v6.0" // minimum Ghost version
});

const createMdFilesFromGhost = async () => {

    console.time('All posts converted to Markdown in');

    try {
        // fetch the posts from the Ghost Content API
        const posts = await api.posts.browse({include: 'tags,authors'});

        await Promise.all(posts.map(async (post) => {
            // Save the content separate and delete it from our post object, as we'll create
            // the frontmatter properties for every property that is left
            const content = post.html;
            delete post.html;

            const frontmatter = post;

            // Create frontmatter properties from all keys in our post object
            const yamlPost = await yaml.dump(frontmatter);

            // Super simple concatenating of the frontmatter and our content
            const fileString = `---\n${yamlPost}\n---\n${content}\n`;

            // Save the final string of our file as a Markdown file
            await fs.writeFile(path.join('', `${post.slug}.md`), fileString);
        }));

    console.timeEnd('All posts converted to Markdown in');

    } catch (error) {
        console.error(error);
    }
};

module.exports = createMdFilesFromGhost();
```

Change the `url` value to the URL of your Ghost site. For Ghost(Pro) customers, this is the Ghost URL ending in `.ghost.io`, and for people using the self-hosted version of Ghost, it’s the same URL used to access your site.

Next, update the `key` value to a key associated with the Ghost site. A key can be provided by creating an integration within the Ghost Admin. Navigate to Integrations and click “Add new integration”. Name the integration appropriately and click create.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2d99d7b0b3f46681cdf28d78919637d6" data-og-width="2920" width="2920" data-og-height="1200" height="1200" data-path="images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4eb5d3f87c7433c845273edbb3bf7c76 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f731f4b897bd5965c8c6372c5b4829ab 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=57ea451e943a4db99dd840d4c482bfea 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=99770f82771ad1ad5f4743b9ed20e18b 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7e94d2342b13fb4e50b66f34fd6d5f68 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d3673af2-apikey_huc23d3a1fbe859434094a9db94f574d9a_265920_2920x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3dafebd40f6b58424c1c7e1a3fb1f9c0 2500w" />
</Frame>

For more detailed steps on setting up Integrations check out [our documentation on the Content API](/content-api/#authentication).

Let’s execute the script to fetch the Ghost content:

```bash  theme={"dark"}
node createMdFilesFromGhost.js
```

The project should now contain your posts as Markdown files! 🎉

The Markdown files will automatically be saved according to their slug, which will not only determine the URL under which they are going to be rendered, but also the order.

If you prefer to have the files sorted by their published date, you can add use `moment.js` to include a formatted date in the filename like so:

```js  theme={"dark"}
// createMdFilesFromGhost.js

const moment = require('moment');

...

    // Save the final string of our file as a Markdown file
    await fs.writeFile(path.join(destinationPath, `${moment(post.published_at).format('YYYY-MM-DD')}-${post.slug}.md`), fileString);

...
```

### Caveats

In some rare cases posts containing code blocks can be parsed incorrectly. A workaround for that is to convert the HTML into Markdown by using a transformer, such as [Turndown](https://github.com/domchristie/turndown).

Transforming the content will result in the loss of some formatting, especially when you’re using a lot of custom HTML in your content, but gives you plenty of customizing options to render the code blocks correctly.

To use Turndown, add it as a dependency:

```bash  theme={"dark"}
yarn add turndown
```

Then update the script like this:

```js  theme={"dark"}
// createMdFilesFromGhost.js

const TurndownService = require('turndown');

...

    await Promise.all(posts.map(async (post) => {
        const turndownService = new TurndownService({codeBlockStyle: 'fenced', headingStyle: 'atx', hr: '---'});

        const content = turndownService.turndown(post.html);

        ...

    }));

...
```

This helps with the code blocks, but when you have inline code in your content that contains mustache expressions or Vue-specific syntax, the renderer will still break. One workaround for that is to properly escape those inline code snippets and code blocks with the [recommended VuePress escaping](https://v1.vuepress.vuejs.org/guide/using-vue.html#escaping):

```vue  theme={"dark"}
::: v-pre
    `{{content}}`
::::
```

To achieve this with Turndown, add a custom rule:

```js  theme={"dark"}
turndownService.addRule('inlineCode', {
    filter: ['code'],
    replacement: function (content) {
        if (content.indexOf(`{{`) >= 0) {
            // Escape mustache expressions properly
            return '\n' + '::: v-pre' + '\n`' + content + '`\n' + '::::' + '\n'
        }
        return '`' + content + '`'
    }
});
```

The plugin is very flexible and can be customized to suit your requirements.

***

### Programmatically create a sidebar

VuePress comes with a powerful default theme that supports a lot of things “out of the box"™️, such as integrated search and sidebars. In this section we’re going to add a sidebar to the home page by reading the filenames of the saved Markdown files.

As a first step, we need to create an index page in the root of the project:

```md  theme={"dark"}
<!-- index.md -->

---
sidebarDepth: 2
---

# Howdie 🤠

Ghost ❤️ VuePress
```

The `sidebarDepth` property tells VuePress that we want to render subheadings from `h1` and `h2` headings from our Ghost content. You can find more information about the default theme config [here](https://vuepress.vuejs.org/theme/default-theme-config.html).

The next step is to create a VuePress `config.js` file in a directory called `.vuepress/`:

```js  theme={"dark"}
// .vuepress/config.js

module.exports = {
    title: 'VuePress + Ghost',
    description: 'Power your VuePress site with Ghost',
    themeConfig: {
        sidebar: []
    }
}
```

In order to generate the sidebar items we’ll need to read all the Markdown files in the project and pass an array with the title (=slug) to our config.

In your config file, require the `fs` and `path` modules from VuePress’ shared utils and add a new `getSidebar()` function as shown below:

```js  theme={"dark"}
// .vuepress/config.js

const { fs, path } = require('@vuepress/shared-utils')

module.exports = {
    title: 'VuePress + Ghost',
    description: 'Power your VuePress site with Ghost',
    themeConfig: {
        sidebar: getSidebar()
    }
}

function getSidebar() {
    return fs
        .readdirSync(path.resolve(__dirname, '../'))
        // make sure we only include Markdown files
        .filter(filename => filename.indexOf('.md') >= 0)
        .map(filename => {
            // remove the file extension
            filename = filename.slice(0, -3)

            if (filename.indexOf('index') >= 0) {
                // Files called 'index' will be rendered
                // as the root page of the folder
                filename = '/'
            }
            return filename
        })
        .sort()
}
```

Run the development server with:

```bash  theme={"dark"}
yarn dev
```

Then head to http\://localhost:8080/ to see the result which looks like this:

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b23cae89-vuepress-demo-screenshot-sidebar_huc534a9cca703dd3b576c73fcfb85e726_85205_1280x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=6c330fdc9efd24c22d09042b09d134cd" data-og-width="1280" width="1280" data-og-height="870" height="870" data-path="images/b23cae89-vuepress-demo-screenshot-sidebar_huc534a9cca703dd3b576c73fcfb85e726_85205_1280x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b23cae89-vuepress-demo-screenshot-sidebar_huc534a9cca703dd3b576c73fcfb85e726_85205_1280x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=fe73f9673f1c73c29e93fa5cc247ba6f 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b23cae89-vuepress-demo-screenshot-sidebar_huc534a9cca703dd3b576c73fcfb85e726_85205_1280x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=5f1f8510e88ec47b59d5cef929cc3b39 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b23cae89-vuepress-demo-screenshot-sidebar_huc534a9cca703dd3b576c73fcfb85e726_85205_1280x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=bd47e1f93a5d7595fc388b348a8518fb 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b23cae89-vuepress-demo-screenshot-sidebar_huc534a9cca703dd3b576c73fcfb85e726_85205_1280x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=b5a182b77da9e4a745bbd016f643757d 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b23cae89-vuepress-demo-screenshot-sidebar_huc534a9cca703dd3b576c73fcfb85e726_85205_1280x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=6a5e02a7ac4687467db1b244e0cc705c 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b23cae89-vuepress-demo-screenshot-sidebar_huc534a9cca703dd3b576c73fcfb85e726_85205_1280x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=db6ba5940310fb5ac7bb0c0b6d3cd85b 2500w" />
</Frame>

***

## Next steps

Discover how to create a component to list all posts on the index page of your VuePress site, or how to create files for tags and authors in our recipes on the next page. For further information, check out the [Ghost Content API documentation](/content-api/) and the [official VuePress documentation](https://vuepress.vuejs.org/).

## Examples

The flexibility of the Ghost Content API allows you to feed posts, pages and any other pieces of content from your Ghost site into a VuePress front-end. Below are a few popular examples of how to customise your site.

If you just landed here, check out [Working With VuePress](/jamstack/vuepress/) for more context!

### Post list component

Components live in a `.vuepress/components/` folder. Create this folder structure and make a new file in `components` called `PostList.vue`. In that file add a `<template>` element add the following to list all of the posts:

```vue  theme={"dark"}
// PostList.vue

<template>
<div>
    <div v-for="post in posts">
        <h2>
            <router-link :to="post.path">
                <div v-if="typeof post.frontmatter.feature_image !== 'undefined'" style="max-width: 250px;">
                    <img :src="post.frontmatter.feature_image" alt="" />
                </div>
                {{ post.frontmatter.title }}
            </router-link>
        </h2>

        <p>{{ post.frontmatter.excerpt }}</p>
        <p>Published: {{ formateDate(post.frontmatter.published_at) }}</p>

        <p><router-link :to="post.path">Read more</router-link></p>
    </div>
</div>
</template>
```

In the same file, just below the `<template>` element, add a `<script>` element, which will contain queries that will in turn pass data to the `<template>` above:

```vue  theme={"dark"}
// PostList.vue

<script>
import moment from "moment"

export default {
    methods: {
        formateDate(date, format = 'D MMM, YY') {
            return moment(date).format(format)
        }
    },
    computed: {
        posts() {
            return this.$site.pages
                .filter(x => x.path.startsWith('/') && !x.frontmatter.index)
                .sort((a, b) => new Date(b.frontmatter.published_at) - new Date(a.frontmatter.published_at));
        },
    }
}
</script>
```

The last step is to reference the component in the `index.md` file like this:

```md  theme={"dark"}
<!-- index.md -->

---
index: true
sidebarDepth: 2
---

# Howdie 🤠

Ghost ❤️ VuePress

<PostList />
```

Restart your server and head to http\://localhost:8080/ to see the posts being rendered:

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a499941d-vuepress-demo-screenshot-index_hu8addf519bf1190ff43ed7c1e8f8b8fe3_81003_1280x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=4770b318ea22779270642692dd73edea" data-og-width="1280" width="1280" data-og-height="840" height="840" data-path="images/a499941d-vuepress-demo-screenshot-index_hu8addf519bf1190ff43ed7c1e8f8b8fe3_81003_1280x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a499941d-vuepress-demo-screenshot-index_hu8addf519bf1190ff43ed7c1e8f8b8fe3_81003_1280x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3095710790e9708939c44867eb69e724 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a499941d-vuepress-demo-screenshot-index_hu8addf519bf1190ff43ed7c1e8f8b8fe3_81003_1280x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=a9077351aa91d86a99e6860a356b0a20 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a499941d-vuepress-demo-screenshot-index_hu8addf519bf1190ff43ed7c1e8f8b8fe3_81003_1280x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e09c4e04fb46607c8acc6bedbf44201a 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a499941d-vuepress-demo-screenshot-index_hu8addf519bf1190ff43ed7c1e8f8b8fe3_81003_1280x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=6bd595e5e548c8a4f8c3a62881210a6e 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a499941d-vuepress-demo-screenshot-index_hu8addf519bf1190ff43ed7c1e8f8b8fe3_81003_1280x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=ec49fab3fbf0812b2b50e90ab287a7aa 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a499941d-vuepress-demo-screenshot-index_hu8addf519bf1190ff43ed7c1e8f8b8fe3_81003_1280x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=27d599dcd53dc5ba9a922ba3e8823266 2500w" />
</Frame>

### Further reading

Learn more about the Ghost API and specific endpoints in our [API documentation](/content-api/) or check out the VuePress docs to find out [how to customize the default theme](https://vuepress.vuejs.org/guide/theme.html).


# LLM
Source: https://docs.ghost.org/llm

Industry-standard files that help AI tools efficiently index and understand Ghost documentation structure and content

***

## llms.txt

The [llms.txt](https://docs.ghost.org/llms.txt) file is an industry standard that helps general-purpose LLMs index more efficiently, similar to how a sitemap helps search engines.

AI tools can use this file to understand the Ghost documentation structure and find relevant content to your prompts.

## llms-full.txt

The [llms-full.txt](https://docs.ghost.org/llms-full.txt) file combines all of the Ghost docs into a single file as context for AI tools.


# Logos
Source: https://docs.ghost.org/logos

The Ghost brand is our pride and joy. We’ve gone to great lengths to make it as beautiful as possible, so we care a great deal about keeping it that way! These guidelines provide all of our official assets and styles, along with details of how to correctly use them.

***

<Frame>
  <div className="dark:bg-white w-full flex items-center justify-center">
    <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ed2eeb2c-ghost-logo-dark.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9045aa78b010f791537912e4a0eb7d64" alt="Dark Ghost logo" data-og-width="800" width="800" data-og-height="294" height="294" data-path="images/ed2eeb2c-ghost-logo-dark.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ed2eeb2c-ghost-logo-dark.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=27aa0152b0f2af77d8006490a54fc7a9 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ed2eeb2c-ghost-logo-dark.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=4a27bf7dddd04925f420fbc297a5921f 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ed2eeb2c-ghost-logo-dark.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=c6dc617b8e2ebecd3b7daeab94cb061f 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ed2eeb2c-ghost-logo-dark.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=530dcfdc5abacf804a1d6ef2d0b2772b 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ed2eeb2c-ghost-logo-dark.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ec9bf54cab91b585dd4aef4861352695 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/ed2eeb2c-ghost-logo-dark.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=86ec9b480338b41d3ab063d3e9aeb4f9 2500w" />
  </div>
</Frame>

<div className="mt-2 mb-8">
  <a href="/images/ed2eeb2c-ghost-logo-dark.png" download="ghost-logo-dark.png">Download</a>
</div>

<Frame>
  <div className="dark:bg-white w-full flex items-center justify-center">
    <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/74e0ffae-ghost-logo-orb.png?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=1b845bd4aaea878d8d0ec1150a641d6f" alt="Ghost orb logo" data-og-width="400" width="400" data-og-height="400" height="400" data-path="images/74e0ffae-ghost-logo-orb.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/74e0ffae-ghost-logo-orb.png?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=520324daa2950fe36f3f504622aeefc6 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/74e0ffae-ghost-logo-orb.png?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=2957e3f325fa0d1ed147714e3d9732b7 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/74e0ffae-ghost-logo-orb.png?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=1fb426fd9c5c88d6360f9bcc82b8d0ba 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/74e0ffae-ghost-logo-orb.png?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=f87b5362af63285ac6da6bd261bc3981 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/74e0ffae-ghost-logo-orb.png?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=d6fa91e29a7c28be7645bcd4efb89ac9 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/74e0ffae-ghost-logo-orb.png?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=2c0459d102a408d8db90bbeba6167909 2500w" />
  </div>
</Frame>

<div className="mt-2 mb-8">
  <a href="/images/74e0ffae-ghost-logo-orb.png" download="ghost-logo-orb.png">Download</a>
</div>

<Frame>
  <div className="bg-primary dark:bg-transparent w-full flex items-center justify-center">
    <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3715a5ca-ghost-logo-light.png?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f30c86c70fb4bd7192b93c82ba66bba7" alt="White Ghost logo" data-og-width="800" width="800" data-og-height="294" height="294" data-path="images/3715a5ca-ghost-logo-light.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3715a5ca-ghost-logo-light.png?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=bb4c04941312b838373896e84fe11292 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3715a5ca-ghost-logo-light.png?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=831297c309b30f992c744a6a5f7674ae 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3715a5ca-ghost-logo-light.png?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=bc91ff677b4954197e959dea5cb9cc18 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3715a5ca-ghost-logo-light.png?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=02cd3d095e93413aef1f203afb1faaea 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3715a5ca-ghost-logo-light.png?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7fe0a88c29673b6d224f6e35087a1354 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3715a5ca-ghost-logo-light.png?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=635efa74712825530a3c4dacb8deb5cb 2500w" />
  </div>
</Frame>

<div className="mt-2 mb-8">
  <a href="/images/3715a5ca-ghost-logo-light.png" download="ghost-logo-light.png">Download</a>
</div>

### Ghost colours

Light backgrounds and tinted greys, accented with Ghost Green.

<div className="grid gap-4 sm:grid-cols-2 md:grid-cols-3">
  <div className="bg-[#30cf43] rounded-xl p-4 text-white flex flex-col gap-20">
    <div className="grow">Ghost Green</div>

    <ul className="not-prose text-sm space-y-1">
      <li>\$green</li>
      <li>RGB 48, 207, 67</li>
      <li>#30cf43</li>
    </ul>
  </div>

  <div className="bg-white rounded-xl p-4 text-black border border-gray-200 flex flex-col gap-20">
    <div className="grow">White</div>

    <ul className="not-prose text-sm space-y-1">
      <li>RGB 255, 255, 255</li>
      <li>#ffffff</li>
    </ul>
  </div>

  <div className="bg-[#CED4D9] rounded-xl p-4 text-black flex flex-col gap-20">
    <div className="grow">Light Grey</div>

    <ul className="not-prose text-sm space-y-1">
      <li>\$lightgrey</li>
      <li>RGB 206, 212, 217</li>
      <li>#CED4D9</li>
    </ul>
  </div>

  <div className="bg-[#7C8B9A] rounded-xl p-4 text-white flex flex-col gap-20">
    <div className="grow">Mid Grey</div>

    <ul className="not-prose text-sm space-y-1">
      <li>\$midgrey</li>
      <li>RGB 124, 139, 154</li>
      <li>#7C8B9A</li>
    </ul>
  </div>

  <div className="bg-[#15171A] rounded-xl p-4 text-white flex flex-col gap-20">
    <div className="grow">Dark Grey</div>

    <ul className="not-prose text-sm space-y-1">
      <li>\$darkgrey</li>
      <li>RGB 21, 33, 42</li>
      <li>#15171A</li>
    </ul>
  </div>
</div>

***

<Card horizontal icon="file-lines">
  Any use of Ghost brand materials constitutes acceptance of the Ghost [Terms of Service](https://ghost.org/terms/), [Trademark Policy](/trademark/) and these Brand Guidelines, which may be updated from time to time. You fully acknowledge that Ghost Foundation is the sole owner of Ghost trademarks, promise not to interfere with Ghost's rights, and acknowledge that goodwill derived from their use accrues only to Ghost. Ghost may review or terminate use of brand materials at any time.
</Card>


# Memberships
Source: https://docs.ghost.org/members

The native Members feature in Ghost makes it possible to launch a membership business from any Ghost publication, with member signup, paid subscriptions and email newsletters built-in.

***

## Overview

Any publisher who wants to offer a way for their audience to support their work can use the Members feature to share content, build an audience, and generate an income from a membership business.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/aa9afb93-ghost-sites_hud78661df9259815cb29707ecbfccff73_228853_1500x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=41c0c777a04af6d23bb538962f328d9f" data-og-width="1500" width="1500" data-og-height="558" height="558" data-path="images/aa9afb93-ghost-sites_hud78661df9259815cb29707ecbfccff73_228853_1500x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/aa9afb93-ghost-sites_hud78661df9259815cb29707ecbfccff73_228853_1500x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=94f59d851d942e6e98c52f5dc83b16e5 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/aa9afb93-ghost-sites_hud78661df9259815cb29707ecbfccff73_228853_1500x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=dd64e09d8ad29f8ac805474d2455a101 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/aa9afb93-ghost-sites_hud78661df9259815cb29707ecbfccff73_228853_1500x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=b2921098dc66f67d32ff8079a5e7eae9 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/aa9afb93-ghost-sites_hud78661df9259815cb29707ecbfccff73_228853_1500x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3d6d701d280d5eb838c74f4d2d27d34f 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/aa9afb93-ghost-sites_hud78661df9259815cb29707ecbfccff73_228853_1500x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e2273c0692a829bbd985e2e68b5e1e81 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/aa9afb93-ghost-sites_hud78661df9259815cb29707ecbfccff73_228853_1500x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=835e1d7d378cb3c3e0a4cb56ead10a33 2500w" />
</Frame>

The concepts and components that enable you to turn a Ghost site into a members publication are surprisingly simple and can be broken down into two concepts:

## 1. Memberships

A member of a Ghost site is someone who has opted to subscribe, and confirmed their subscription by clicking the link sent to their inbox. Members are stored in Ghost, to make tracking, managing and supporting an audience a breeze.

### Secure authentication

Ghost uses passwordless JWT email-link based logins for your members. It’s fast, reliable, and incredible for security. Secure email authentication is used for both member sign up and sign in.

### Access levels

Once a visitor has entered their email address and confirmed membership, you can share protected content with them on your Ghost publication. Logged in members are able to access any content that matches their tier.

The following access levels are available to select from the post settings in the editor:

* **Public**
* **Members only**
* **Paid-members only**
* **Specific tier(s)**

Content is securely protected at server level and there is no way to circumvent gated content without being a logged-in member.

### Managing members

Members are stored in Ghost with the following attributes:

* `email` (required)
* `name`
* `note`
* `subscribed_to_emails`
* `stripe_customer_id`
* `status` (free/paid/complimentary)
* `labels`
* `created_at`

### Imports

It’s possible to import Members from any other platform. If you have a list of email addresses, this can be ported into Ghost via CSV, Zapier, or the API.

## 2. Subscriptions

Members in Ghost can be free members, or become paid members with a direct Stripe integration for fast, global payments.

### Connect to Stripe

We’ve built a direct [integration with Stripe](https://ghost.org/integrations/stripe/) which allows publishers to connect their Ghost site to their own billing account using Stripe Connect.

<Frame caption={`Search "Tiers" or "Stripe" in your settings to find the Connect to Stripe button.`}>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-1.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=5031e653ac90bf72c4dd1dcbfe508a3d" data-og-width="1400" width="1400" data-og-height="567" height="567" data-path="images/stripe-step-1.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-1.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=27ef879aa892280f168ce84f1eadb9f3 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-1.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=e361d0afa64ae0fa7e191199d5ed7e58 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-1.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=7bf178ccd0ccf5b101c46f4ffc7626c1 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-1.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=818b4b445319abc1e73d3895b68026f7 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-1.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=6f2a0ace40ff40ed41a2c087932970cc 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-1.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=b4a08c40700646d1f7aa10cf3f3df74d 2500w" />
</Frame>

<br />

<Frame caption="Make sure you're signed up for a Stripe account.">
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-2.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=cf0b313da9a874c3612139e25b49cb99" data-og-width="1400" width="1400" data-og-height="592" height="592" data-path="images/stripe-step-2.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-2.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=da39979c89ee666bf38888e9ad9eb2a6 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-2.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=667f692ad2b462d016dfff3a7958939b 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-2.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=7ac9b527bad77e3cb004a110993fa169 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-2.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=69be240a9593ee97e3f68140f9cfe07d 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-2.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=136ec5575eae7cb8f77a6c73248986fe 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-2.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=e7b301d88352b27cad6b2cfea502fb85 2500w" />
</Frame>

<br />

<Frame caption="Follow the instructions to connect your Stripe account and generate your secure key.">
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-3.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=c33cb5c5f0805cd48eedf73724afca3b" data-og-width="1400" width="1400" data-og-height="767" height="767" data-path="images/stripe-step-3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-3.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=e648b7e4d4e553f7980c09fc0ac0eaab 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-3.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1c2d91761934fd70e0a32fc8171d1520 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-3.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=6d366436ad450c31e9f279f7c1bd4e59 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-3.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=09b79d94006a0a1a03dccc586f683b0d 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-3.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=4eb8c889c2bd51e4fe1004782da5e783 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/stripe-step-3.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=fb9c3f07b4110f0ec6d2acfa183d1a84 2500w" />
</Frame>

Payments are handled by Stripe and billing information is stored securely inside your own Stripe account.

### Transaction fees

Ghost takes **0%** of your revenue. Whatever you generate from a paid blog, newsletter or community is yours to keep. Standard Stripe processing fees still apply.

### Portability

All membership, customer and business data is controlled by you. Your members list can be exported any time and since subscriptions and billing takes place inside your own Stripe account, you retain full ownership of it.

If you’re migrating an existing membership business from another platform, check our our [migration docs](/migration/).

### Alternative payment gateways

To begin with, Stripe is the only natively supported payment provider with Ghost. We’re aware that not everyone has access to Stripe, and we plan to add further payment providers in future.

In the meantime, it is possible to create new members via an external provider, such as [Patreon](https://ghost.org/integrations/patreon/) or [PayPal](https://ghost.org/integrations/paypal/). You can set up any third party payments system and create members in Ghost via API, or using automation tools like Zapier.

### I have ideas / suggestions / problems / feedback

Great! We set up a dedicated [forum category](https://forum.ghost.org/c/members) for feedback about the members feature, we appreciate your input!

We’re continuously shipping improvements and new features at Ghost which you can follow over on [GitHub](https://github.com/tryghost/ghost), or on our [Changelog](https://ghost.org/changelog/).


# Migrating To Ghost
Source: https://docs.ghost.org/migration



<Card icon="box" title="Ghost(Pro) migration services →" href="https://ghost.org/concierge/">
  If you're a Ghost(Pro) customer, our team may be able to help you migrate your content and subscribers.
</Card>

<CardGroup cols={3}>
  <Card href="/migration/substack/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a20fc9d0-substack-logo_huc24aa74ba24fa41c4541cf4ceebe96f7_2278_606x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=deb76cd63ed6686eb160af81053fa369" data-og-width="606" width="606" data-og-height="606" height="606" data-path="images/a20fc9d0-substack-logo_huc24aa74ba24fa41c4541cf4ceebe96f7_2278_606x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a20fc9d0-substack-logo_huc24aa74ba24fa41c4541cf4ceebe96f7_2278_606x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e6946b4af07f10ea0753d18c3cb1cf25 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a20fc9d0-substack-logo_huc24aa74ba24fa41c4541cf4ceebe96f7_2278_606x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cff2fc0dc0b5d910ad01e8345711d1e4 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a20fc9d0-substack-logo_huc24aa74ba24fa41c4541cf4ceebe96f7_2278_606x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cea34e832ad171b01cb9e50c92bbbdd2 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a20fc9d0-substack-logo_huc24aa74ba24fa41c4541cf4ceebe96f7_2278_606x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e82e377e12bfd7e729269ad218cc8415 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a20fc9d0-substack-logo_huc24aa74ba24fa41c4541cf4ceebe96f7_2278_606x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=97b9ace16f54f1ed134bc57afb91d0a5 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a20fc9d0-substack-logo_huc24aa74ba24fa41c4541cf4ceebe96f7_2278_606x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=621e7f65e0b9afee97782a620745dc73 2500w" />

    **Substack**
  </Card>

  <Card href="/migration/beehiiv/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/879d3530-beehiiv-logo_hu4abad0e96a6745a35d2531e307809047_3360_117x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=6f723f5595a120007209528cf81cd651" data-og-width="117" width="117" data-og-height="111" height="111" data-path="images/879d3530-beehiiv-logo_hu4abad0e96a6745a35d2531e307809047_3360_117x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/879d3530-beehiiv-logo_hu4abad0e96a6745a35d2531e307809047_3360_117x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=e56bf03d48957a6cab14d347a67514df 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/879d3530-beehiiv-logo_hu4abad0e96a6745a35d2531e307809047_3360_117x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=1569d4350855371366cefd054a12f6d9 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/879d3530-beehiiv-logo_hu4abad0e96a6745a35d2531e307809047_3360_117x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=48d09e5c4d295d1660d17e54d73c85f2 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/879d3530-beehiiv-logo_hu4abad0e96a6745a35d2531e307809047_3360_117x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=280f913c33ae6339722b616b35273f74 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/879d3530-beehiiv-logo_hu4abad0e96a6745a35d2531e307809047_3360_117x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=ee067962cf69261e8b2a3c9566fbe8d7 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/879d3530-beehiiv-logo_hu4abad0e96a6745a35d2531e307809047_3360_117x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=f70f3939ca476bb1f37fe41208494b67 2500w" />

    **BeeHiiv**
  </Card>

  <Card href="/migration/wordpress/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1dc4f60a-wordpress-logo.svg?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=e9636e1fa67fa0e89d50d7bf09732d24" data-og-width="123" width="123" data-og-height="123" height="123" data-path="images/1dc4f60a-wordpress-logo.svg" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1dc4f60a-wordpress-logo.svg?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1750bc77836062a00d6be0c7325dc9e9 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1dc4f60a-wordpress-logo.svg?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=6d14ba9bbb982d968f2f8f199d83eaa4 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1dc4f60a-wordpress-logo.svg?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=fc75974515b31f42346b147c2933d921 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1dc4f60a-wordpress-logo.svg?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=bcd13eb023fd613561de9e9ad7478dc4 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1dc4f60a-wordpress-logo.svg?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ebe0df28ee9f79f7c96e5965af3d638a 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1dc4f60a-wordpress-logo.svg?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=3036b98bf77da9c79f12b28f9d05ed74 2500w" />

    **WordPress**
  </Card>

  <Card href="/migration/newspack/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e7c980e5-newspack-logo_hu51abf2fafb510de653f416bb72277f36_8844_400x0_resize_q100_h2_box_2.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=937cf51470251f02be21ff9038193334" data-og-width="400" width="400" data-og-height="400" height="400" data-path="images/e7c980e5-newspack-logo_hu51abf2fafb510de653f416bb72277f36_8844_400x0_resize_q100_h2_box_2.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e7c980e5-newspack-logo_hu51abf2fafb510de653f416bb72277f36_8844_400x0_resize_q100_h2_box_2.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=fdb50d32594ea0ca7bb39071a733c02b 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e7c980e5-newspack-logo_hu51abf2fafb510de653f416bb72277f36_8844_400x0_resize_q100_h2_box_2.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=985a39b46dafaabff55aee089e4c70d9 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e7c980e5-newspack-logo_hu51abf2fafb510de653f416bb72277f36_8844_400x0_resize_q100_h2_box_2.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=6bc6c7bc1ffd079dfc9a7b3b2bf63e94 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e7c980e5-newspack-logo_hu51abf2fafb510de653f416bb72277f36_8844_400x0_resize_q100_h2_box_2.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a9dd950265a637dfddfa1cea4787ad3e 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e7c980e5-newspack-logo_hu51abf2fafb510de653f416bb72277f36_8844_400x0_resize_q100_h2_box_2.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=02a1667b255f8d91ffc72e6756fa39e6 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e7c980e5-newspack-logo_hu51abf2fafb510de653f416bb72277f36_8844_400x0_resize_q100_h2_box_2.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=129860b59fd82a6b049382eb93fce375 2500w" />

    **Newspack**
  </Card>

  <Card href="/migration/medium/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/43d2947c-medium-logo_hu653fa3b1dcbd7dcc07a7092f13cb6eea_1762_225x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=b570eb067ec303a34aa9c825437e64ea" data-og-width="225" width="225" data-og-height="225" height="225" data-path="images/43d2947c-medium-logo_hu653fa3b1dcbd7dcc07a7092f13cb6eea_1762_225x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/43d2947c-medium-logo_hu653fa3b1dcbd7dcc07a7092f13cb6eea_1762_225x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=dad84740ee85901fe91005b8a59309d5 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/43d2947c-medium-logo_hu653fa3b1dcbd7dcc07a7092f13cb6eea_1762_225x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1aa779e72fa0aac1ddc6b9f4050d9d9a 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/43d2947c-medium-logo_hu653fa3b1dcbd7dcc07a7092f13cb6eea_1762_225x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=bcc7886a75161ef9765e0a0496eacd4a 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/43d2947c-medium-logo_hu653fa3b1dcbd7dcc07a7092f13cb6eea_1762_225x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f2ad1b0f6a95e937b8ee09c8b903cc24 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/43d2947c-medium-logo_hu653fa3b1dcbd7dcc07a7092f13cb6eea_1762_225x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=9af98b4a40ffaeec707a773b1daa48d8 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/43d2947c-medium-logo_hu653fa3b1dcbd7dcc07a7092f13cb6eea_1762_225x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=4579d9ca072bc756e630546ccbcbdfc8 2500w" />

    **Medium**
  </Card>

  <Card href="/migration/squarespace/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9c50cfe2-squarespace-logo.svg?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a8c450421cf650523096f8bc0a0b1ca7" data-og-width="256" width="256" data-og-height="204" height="204" data-path="images/9c50cfe2-squarespace-logo.svg" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9c50cfe2-squarespace-logo.svg?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=0c73eedda3e007304626d3b27367a73c 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9c50cfe2-squarespace-logo.svg?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=22a04fab4226e45a09488e733379f43a 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9c50cfe2-squarespace-logo.svg?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=866529669accf1ba612a1e034940f56b 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9c50cfe2-squarespace-logo.svg?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=81a15add9479e5addd26baf6888ad632 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9c50cfe2-squarespace-logo.svg?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=fb8be954559f43309e3356d5d4a2f0ab 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/9c50cfe2-squarespace-logo.svg?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a9f629b0d015df98a7d70d7d592fd946 2500w" />

    **SquareSpace**
  </Card>

  <Card href="/migration/kit/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/ca859fc9-kit-logo_hu3614f42c0366863f750e8a2729afab7f_6493_1147x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=01eeac49819ff9ee216db8b4da2f5eaf" data-og-width="1147" width="1147" data-og-height="518" height="518" data-path="images/ca859fc9-kit-logo_hu3614f42c0366863f750e8a2729afab7f_6493_1147x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/ca859fc9-kit-logo_hu3614f42c0366863f750e8a2729afab7f_6493_1147x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=89110e78eb9779f574972ec26b0f7a99 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/ca859fc9-kit-logo_hu3614f42c0366863f750e8a2729afab7f_6493_1147x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=b0cb146f6a2d8f4758ce911ab6973996 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/ca859fc9-kit-logo_hu3614f42c0366863f750e8a2729afab7f_6493_1147x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=a8f3fcdc6acef8f61de2bb501ba53329 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/ca859fc9-kit-logo_hu3614f42c0366863f750e8a2729afab7f_6493_1147x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=572a8e224425a53d9c3ceaa0d0c5d91b 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/ca859fc9-kit-logo_hu3614f42c0366863f750e8a2729afab7f_6493_1147x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=9fe0522da6214cbec13097b5e1fdb7f4 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/ca859fc9-kit-logo_hu3614f42c0366863f750e8a2729afab7f_6493_1147x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=1c7bdfbc3ee91e3908e4cec3cc8a7339 2500w" />

    **Kit**
  </Card>

  <Card href="/migration/mailchimp/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/4227ce5e-mailchimp-logo.svg?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f353115a30383dfb12afe16f3515734d" data-og-width="392" width="392" data-og-height="416" height="416" data-path="images/4227ce5e-mailchimp-logo.svg" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/4227ce5e-mailchimp-logo.svg?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a0f0f7b83a690a52e78194765f3feb6c 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/4227ce5e-mailchimp-logo.svg?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=9dbb9199a04953b7b6a70feb8439dfa0 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/4227ce5e-mailchimp-logo.svg?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=29a4f4613317bf7e857e6f0adf5af804 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/4227ce5e-mailchimp-logo.svg?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=4f13de23620ff5f552d5b521a4a42fd6 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/4227ce5e-mailchimp-logo.svg?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=c61af1363a729bca787a395299b6a0e4 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/4227ce5e-mailchimp-logo.svg?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=11ea96668fe9fdbf0d27c72176f2cddd 2500w" />

    **MailChimp**
  </Card>

  <Card href="/migration/patreon/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a037f8d7-patreon-logo.svg?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=bce1cd3bafd431aa7da4a8a568a72971" data-og-width="180" width="180" data-og-height="180" height="180" data-path="images/a037f8d7-patreon-logo.svg" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a037f8d7-patreon-logo.svg?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=eea841c3b8018178a7fcda150c413d57 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a037f8d7-patreon-logo.svg?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=5b6a5aa4a8f549d2084609945c6aed69 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a037f8d7-patreon-logo.svg?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=7a3649acda6e94c05f94a650796a25df 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a037f8d7-patreon-logo.svg?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=f02482a144f6946ce0eda8e8260fe597 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a037f8d7-patreon-logo.svg?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=905bef0d38b81acae13e159923d0a7c5 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a037f8d7-patreon-logo.svg?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=ce62ce546fb40ab6ae3b206a1194c4bb 2500w" />

    **Patreon**
  </Card>

  <Card href="/migration/buttondown/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d8e13837-buttondown-logo_hucb227c87b3a9ce9bdbff00a32f010ee0_5514_400x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f63387da02aefd1dc14db10449e1d521" data-og-width="400" width="400" data-og-height="400" height="400" data-path="images/d8e13837-buttondown-logo_hucb227c87b3a9ce9bdbff00a32f010ee0_5514_400x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d8e13837-buttondown-logo_hucb227c87b3a9ce9bdbff00a32f010ee0_5514_400x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2fd4e19d82c12c7ac7a0334ba7ffd0c8 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d8e13837-buttondown-logo_hucb227c87b3a9ce9bdbff00a32f010ee0_5514_400x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=34ae19746e30c4656eff31e8accc6766 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d8e13837-buttondown-logo_hucb227c87b3a9ce9bdbff00a32f010ee0_5514_400x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3eb1fc8270db340bfb9973ea4d677529 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d8e13837-buttondown-logo_hucb227c87b3a9ce9bdbff00a32f010ee0_5514_400x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=c45f19c140f2f0c980439c45ab89bf77 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d8e13837-buttondown-logo_hucb227c87b3a9ce9bdbff00a32f010ee0_5514_400x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=a19a6768f100534c4dfd40b2c1395573 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d8e13837-buttondown-logo_hucb227c87b3a9ce9bdbff00a32f010ee0_5514_400x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=3b284317ca42a23892d5c88674b758bf 2500w" />

    **Buttondown**
  </Card>

  <Card href="/migration/memberful/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c403fb30-memberful-logo_hu1c13118575e70f224d3c44abd46f644f_10288_475x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=ab071b7ad4513c39316f62ff4fc1acd0" data-og-width="475" width="475" data-og-height="475" height="475" data-path="images/c403fb30-memberful-logo_hu1c13118575e70f224d3c44abd46f644f_10288_475x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c403fb30-memberful-logo_hu1c13118575e70f224d3c44abd46f644f_10288_475x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7f582559ae72e285ef2c64a3076de828 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c403fb30-memberful-logo_hu1c13118575e70f224d3c44abd46f644f_10288_475x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=34e6d0b6a287621a6c5449846d12f2d4 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c403fb30-memberful-logo_hu1c13118575e70f224d3c44abd46f644f_10288_475x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=1a8ab02e5cbb567c960bb9df0318179b 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c403fb30-memberful-logo_hu1c13118575e70f224d3c44abd46f644f_10288_475x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=69c717197aa43afac22a73a76668fed7 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c403fb30-memberful-logo_hu1c13118575e70f224d3c44abd46f644f_10288_475x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f7f3c877a6278827c17ee7487368bb09 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c403fb30-memberful-logo_hu1c13118575e70f224d3c44abd46f644f_10288_475x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=42e82ecaa6167552d056b5b11fc11e32 2500w" />

    **Memberful**
  </Card>

  <Card href="/migration/gumroad/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6a6605e0-gumroad-logo_hud0833833547c6e5b6eb8af1cc6586779_22238_962x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a47b5cfd98e98d0e3bc63066eafcaf4c" data-og-width="962" width="962" data-og-height="1014" height="1014" data-path="images/6a6605e0-gumroad-logo_hud0833833547c6e5b6eb8af1cc6586779_22238_962x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6a6605e0-gumroad-logo_hud0833833547c6e5b6eb8af1cc6586779_22238_962x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=0268a923cb2ca70dc79fe8d98535f32a 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6a6605e0-gumroad-logo_hud0833833547c6e5b6eb8af1cc6586779_22238_962x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=f2eae0dd6b9b25c141d1b36c3edb1103 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6a6605e0-gumroad-logo_hud0833833547c6e5b6eb8af1cc6586779_22238_962x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=4aa51903202fd14f4bb54bd51b8c37e4 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6a6605e0-gumroad-logo_hud0833833547c6e5b6eb8af1cc6586779_22238_962x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a2fbab3dabd7a17aade679582a129d73 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6a6605e0-gumroad-logo_hud0833833547c6e5b6eb8af1cc6586779_22238_962x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=7339106301b95db472ef457c6748600b 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/6a6605e0-gumroad-logo_hud0833833547c6e5b6eb8af1cc6586779_22238_962x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=825893f6075ced5ae005cd8864e1a915 2500w" />

    **Gumroad**
  </Card>

  <Card href="/migration/jekyll/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/590bd129-jekyll-logo.svg?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=15041c73090c32e9c57a980efb6557a5" data-og-width="230" width="230" data-og-height="410" height="410" data-path="images/590bd129-jekyll-logo.svg" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/590bd129-jekyll-logo.svg?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=20bd5e4f1d80ab92a1ec382330bf1efc 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/590bd129-jekyll-logo.svg?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=3dfad87ffe78afb2c9a4564982c6221e 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/590bd129-jekyll-logo.svg?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=dafbfe515c0f6362b7c93858a18e1755 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/590bd129-jekyll-logo.svg?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=ab9cb8d185b1de55c6b5e71795c8ec03 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/590bd129-jekyll-logo.svg?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=309ccb0311b6d9d67d75b319e0b07a33 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/590bd129-jekyll-logo.svg?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=f43c66234e07916ff560f0af72009486 2500w" />

    **Jekyll**
  </Card>

  <Card href="/migration/ghost/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4a37ff4f-orb-black-1_hucb802f9049ed3348f8217d8dc62f8bad_51786_400x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=5753f42891ac58d5a0668cc8c040797e" data-og-width="400" width="400" data-og-height="400" height="400" data-path="images/4a37ff4f-orb-black-1_hucb802f9049ed3348f8217d8dc62f8bad_51786_400x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4a37ff4f-orb-black-1_hucb802f9049ed3348f8217d8dc62f8bad_51786_400x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=8496a3de5a0ebc93c6b9ccc5f476e7cc 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4a37ff4f-orb-black-1_hucb802f9049ed3348f8217d8dc62f8bad_51786_400x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=509d095e1853a2b3f1a06e7b2aa0ec55 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4a37ff4f-orb-black-1_hucb802f9049ed3348f8217d8dc62f8bad_51786_400x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=c79991567f2b00eb74c09175ec0201a2 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4a37ff4f-orb-black-1_hucb802f9049ed3348f8217d8dc62f8bad_51786_400x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=edd1db8a756decce7f8f4c2731c06879 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4a37ff4f-orb-black-1_hucb802f9049ed3348f8217d8dc62f8bad_51786_400x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=f3c13cbed179a0088c9e04b2491a12d9 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4a37ff4f-orb-black-1_hucb802f9049ed3348f8217d8dc62f8bad_51786_400x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=7b76c2b8f77f16ac8d20f59711b6c4df 2500w" />

    **Ghost**
  </Card>

  <Card href="/migration/custom/">
    <img noZoom className="w-20 h-20 mb-2" src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d02cff37-custom.svg?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=02398015f2d14a368d476da934ee39e4" data-og-width="1487" width="1487" data-og-height="516" height="516" data-path="images/d02cff37-custom.svg" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d02cff37-custom.svg?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=a1acb749c22da4908198779fc1b43eba 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d02cff37-custom.svg?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=adda39d33ab5dde187b7371bdc5ce19c 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d02cff37-custom.svg?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=67b22080534adca044889ef77da19cb8 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d02cff37-custom.svg?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=8850fce1b8666e0ed687b7b6dc707d45 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d02cff37-custom.svg?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e0c072ae89d36355073f2d29c38bbe47 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/d02cff37-custom.svg?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=83d2329ac07c7986006d6c588dbfcd3b 2500w" />

    **Other platforms**
  </Card>
</CardGroup>


# Migrating from BeeHiiv
Source: https://docs.ghost.org/migration/beehiiv

Migrate from BeeHiiv and import your content to Ghost with this guide

<Note>
  If you're a Ghost(Pro) customer, our team may be able to help you migrate your content and subscribers. Learn more about our [Concierge service](https://ghost.org/concierge/).
</Note>

## Exporting your subscribers

To get started, [download your full subscriber list](https://support.beehiiv.com/hc/en-us/articles/12234988536215-How-to-export-subscribers) (**Export Subscribers (Full)**) from BeeHiiv.

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5830e1b4-beehiiv-subscriber-exports_huae1d966f695844077fd5c2e1914a81b1_25651_2148x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a1d79abf14c646779ef52793a5dc9c4e" data-og-width="2148" width="2148" data-og-height="576" height="576" data-path="images/5830e1b4-beehiiv-subscriber-exports_huae1d966f695844077fd5c2e1914a81b1_25651_2148x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5830e1b4-beehiiv-subscriber-exports_huae1d966f695844077fd5c2e1914a81b1_25651_2148x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=b92239e807e488a55ba633bd3a15eb41 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5830e1b4-beehiiv-subscriber-exports_huae1d966f695844077fd5c2e1914a81b1_25651_2148x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=84932d1013910867b13f4cffd61b5a71 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5830e1b4-beehiiv-subscriber-exports_huae1d966f695844077fd5c2e1914a81b1_25651_2148x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=36d52af7f89f0a00fed1be70fb089d96 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5830e1b4-beehiiv-subscriber-exports_huae1d966f695844077fd5c2e1914a81b1_25651_2148x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=e1e0650f28fb60b0511d1f1528a08da8 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5830e1b4-beehiiv-subscriber-exports_huae1d966f695844077fd5c2e1914a81b1_25651_2148x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=ab022eb3bfe004d870e1c495468034dd 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5830e1b4-beehiiv-subscriber-exports_huae1d966f695844077fd5c2e1914a81b1_25651_2148x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=6e4f3e613083a99b2feefd273d6866cc 2500w" />
</Frame>

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cbffd4f4-beehiiv-subscriber-download_huff7cd490bded2324dbd2f44e962cade4_16919_2148x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2ee3c63a68e22be7c63a7fac1b44f0d0" data-og-width="2148" width="2148" data-og-height="602" height="602" data-path="images/cbffd4f4-beehiiv-subscriber-download_huff7cd490bded2324dbd2f44e962cade4_16919_2148x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cbffd4f4-beehiiv-subscriber-download_huff7cd490bded2324dbd2f44e962cade4_16919_2148x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=803ade259a24596a0b6a5203fecdf828 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cbffd4f4-beehiiv-subscriber-download_huff7cd490bded2324dbd2f44e962cade4_16919_2148x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=dfd32d58fd1017da3acc8bddca0dfa82 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cbffd4f4-beehiiv-subscriber-download_huff7cd490bded2324dbd2f44e962cade4_16919_2148x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e5d8f944690e8829823cc49317d9b838 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cbffd4f4-beehiiv-subscriber-download_huff7cd490bded2324dbd2f44e962cade4_16919_2148x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=294501d05f8684bd9720a02554e6a82e 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cbffd4f4-beehiiv-subscriber-download_huff7cd490bded2324dbd2f44e962cade4_16919_2148x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=12fb05f51bd114e6dd08689e1b6732b7 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cbffd4f4-beehiiv-subscriber-download_huff7cd490bded2324dbd2f44e962cade4_16919_2148x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=472a9d1028a3f01fc5b5f6a394a5f80c 2500w" />
</Frame>

## Import subscribers to Ghost

If all of your subscribers are free, you can import this into Ghost directly.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1f2f8d5b608e1dd8e7ac1b58960fc752" data-og-width="1000" width="1000" data-og-height="167" height="167" data-path="images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ddcfbaa05045604d7a3cb57df0eee4c0 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f604af49134c94d2e4ac4471bef53b27 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=526f82470ae6d5811dd6ed7c5c806846 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=e4a4d46f7842d8139b9b3353182f512c 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d174b72f8d3ee6fef63d1d59c902bcac 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=58eabc1e3b29ea3f79cb9d852afd4096 2500w" />
</Frame>

If you have paid subscribers, you need to relate Stripe Customer IDs with your subscribers emails.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=6d35692e55955554d4cb0ec7505539d8" data-og-width="1000" width="1000" data-og-height="1022" height="1022" data-path="images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=322f2175526eda166eb6255fee83ea1c 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=bab77bf6889d2f89ecfff1d20de15c11 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=35e76445c15b69004ed3e38e306193b9 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=655701b0ac85ff5fabd78e41b01c3ba4 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=b9589e7b21cf89271d7b77307624da8d 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a359f64b05aaf4a464e590f8b2122099 2500w" />
</Frame>

If you cannot connect your Ghost site to the same Stripe account you used with BeeHiiv, you may need to migrate customer data, products, prices, coupons to a new Stripe account, and then recreate the subscriptions before importing into your Ghost site. The [Ghost Concierge](https://ghost.org/concierge/) team can help with this.

## Migrating Content

Developers can migrate content from BeeHiiv to Ghost using our [migration CLI tools](https://github.com/TryGhost/migrate/tree/main/packages/mg-beehiiv).

You will first need to [export your posts](https://support.beehiiv.com/hc/en-us/articles/12258595483543-How-to-export-your-post-content) from BeeHiiv. This will be a CSV file which includes all post content, titles, dates, etc.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0e894c9e-beehiiv-content-export_hu692b89da164ad0d3b6abc7f18ee87332_11063_2148x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=4e0a182891d2557c2d181ecc3f6679fe" data-og-width="2148" width="2148" data-og-height="432" height="432" data-path="images/0e894c9e-beehiiv-content-export_hu692b89da164ad0d3b6abc7f18ee87332_11063_2148x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0e894c9e-beehiiv-content-export_hu692b89da164ad0d3b6abc7f18ee87332_11063_2148x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d2efc671ac43c6849db2c8951890a4e1 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0e894c9e-beehiiv-content-export_hu692b89da164ad0d3b6abc7f18ee87332_11063_2148x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1f5451cfcee666c451e96b3aa0aca1b0 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0e894c9e-beehiiv-content-export_hu692b89da164ad0d3b6abc7f18ee87332_11063_2148x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=5d5c142e334525df310b1a7de6fbc15c 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0e894c9e-beehiiv-content-export_hu692b89da164ad0d3b6abc7f18ee87332_11063_2148x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=30b5a9bc5f4e5a9aa6b2330fb7b6f192 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0e894c9e-beehiiv-content-export_hu692b89da164ad0d3b6abc7f18ee87332_11063_2148x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8dc41b91b49ab131ce5244f4aa6fbca8 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0e894c9e-beehiiv-content-export_hu692b89da164ad0d3b6abc7f18ee87332_11063_2148x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=75b29b1cfbf76b8bfa6766a748c29a1e 2500w" />
</Frame>

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c0d9391-beehiiv-content-download_hu2bc2e7c63f879a9affdf18f111de440a_16136_2148x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=2694d106c8ab147cdd43e05e1ecb02d0" data-og-width="2148" width="2148" data-og-height="602" height="602" data-path="images/1c0d9391-beehiiv-content-download_hu2bc2e7c63f879a9affdf18f111de440a_16136_2148x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c0d9391-beehiiv-content-download_hu2bc2e7c63f879a9affdf18f111de440a_16136_2148x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=56f89944c8ac833fca0650b381f4cadd 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c0d9391-beehiiv-content-download_hu2bc2e7c63f879a9affdf18f111de440a_16136_2148x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=3bae4e177b8399928b5493cb60623231 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c0d9391-beehiiv-content-download_hu2bc2e7c63f879a9affdf18f111de440a_16136_2148x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=e0988c84a78cb1bc9093db4c2d41155c 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c0d9391-beehiiv-content-download_hu2bc2e7c63f879a9affdf18f111de440a_16136_2148x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=78dd3974dea57a87127c10a707673175 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c0d9391-beehiiv-content-download_hu2bc2e7c63f879a9affdf18f111de440a_16136_2148x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=cb3bc34353d6ce2a0e7d5044208ddaaf 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c0d9391-beehiiv-content-download_hu2bc2e7c63f879a9affdf18f111de440a_16136_2148x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=5b490845e67c70655416a7a5c096cae2 2500w" />
</Frame>

First, make sure the CLI is installed.

```sh  theme={"dark"}
# Install CLI
npm install --global @tryghost/migrate

# Verify it's installed
migrate
```

To run a basic migration with the default commands:

```sh  theme={"dark"}
# Basic migration
migrate beehiiv --posts /path/to/posts.csv --url https://example.com
```

There are [more options](https://github.com/TryGhost/migrate/tree/main/packages/mg-beehiiv#usage), such as the ability define a default author name and choose where `/subscribe` links go to.

Once the CLI task has finished, it creates a new ZIP file which you can [import into Ghost](https://ghost.org/help/imports/).

### Using custom domains

If you’re using a custom domain on BeeHiiv, you’ll need to implement redirects in Ghost to prevent broken links.

BeeHiiv uses `/p/` as part of the public post URL, where as Ghost uses it in the URL for post previews. This means the redirect regular expression is quite complex, but necessary so that post previews in Ghost function correctly.

```yaml  theme={"dark"}
# redirects.yaml
301:
  ^\/p\/(?![0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(.*): /$1
  ^\/polls\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(.*): /
  ^\/t\/(.*): /tag/$1

302:
```

This means that if a visitor or crawler goes to `https://mysite.com/p/awesome-post`, they will automatically be redirected to `https://mysite.com/awesome-post`.

***

## Summary

Congratulations on your migration to Ghost 🙌. All that’s left to do is check over your content to ensure the migration has worked as expected. We also have a guide on [how to implement redirects](https://ghost.org/tutorials/implementing-redirects/) to make your transition smoother.


# Migrating from Buttondown
Source: https://docs.ghost.org/migration/buttondown

Migrate from Buttondown and import your content to Ghost with this guide

<Note>
  If you're a Ghost(Pro) customer, our team may be able to help you migrate your content and subscribers. Learn more about our [Concierge service](https://ghost.org/concierge/).
</Note>

## Export your subscribers

To get started, export your current subscribers in CSV format.

## Import subscribers to Ghost

Under the Ghost Admin members settings, select the import option from the settings menu.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1f2f8d5b608e1dd8e7ac1b58960fc752" data-og-width="1000" width="1000" data-og-height="167" height="167" data-path="images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ddcfbaa05045604d7a3cb57df0eee4c0 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f604af49134c94d2e4ac4471bef53b27 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=526f82470ae6d5811dd6ed7c5c806846 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=e4a4d46f7842d8139b9b3353182f512c 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d174b72f8d3ee6fef63d1d59c902bcac 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=58eabc1e3b29ea3f79cb9d852afd4096 2500w" />
</Frame>

Upload your CSV file to Ghost, and map each of the fields contained in your export file to the corresponding fields in Ghost. The **email** field is required in order to create members in Ghost, while the other fields are optional.

To import paid members with an existing Stripe subscription, you must import their **Stripe customer ID**.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=6d35692e55955554d4cb0ec7505539d8" data-og-width="1000" width="1000" data-og-height="1022" height="1022" data-path="images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=322f2175526eda166eb6255fee83ea1c 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=bab77bf6889d2f89ecfff1d20de15c11 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=35e76445c15b69004ed3e38e306193b9 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=655701b0ac85ff5fabd78e41b01c3ba4 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=b9589e7b21cf89271d7b77307624da8d 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/19216f0e-import-members-2_hu4666f031efd860d74fa4f40b2a587fd0_130604_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a359f64b05aaf4a464e590f8b2122099 2500w" />
</Frame>

Once the import has completed, all your subscribers will be migrated to Ghost. There’s nothing else you need to do, members can now log into your site and receive email newsletters.


# Developer Migration Docs
Source: https://docs.ghost.org/migration/custom

If no export tools exist for your current plublishing platform you’ll need to create one that generates a JSON file as described here. There is a full example at the end of this file. Please note that your final JSON file should have no comments in the final format. Those are only included here for readability and explanatory purposes.

### JSON file structure

First and foremost, your JSON file must contain valid JSON. You can test your file is valid using the [JSONLint](https://jsonlint.com/) online tool.

The file structure can optionally be wrapped in:

```json  theme={"dark"}
{
  "db": [...contents here...]
}
```

Both with and without are valid Ghost JSON files. But you must include a `meta` and a `data` object.

### The meta object

```json  theme={"dark"}
"meta": {
    "exported_on": 1753891082041,
    "version": "6.0.0"
}
```

The `meta` block expects two keys, `exported_on` and `version`. `exported_on` should be an epoch timestamp in milliseconds, version should be the Ghost version the import is valid for.

### The data block

Ghost’s JSON format mirrors the underlying database structure, rather than the API, as it allows you to override fields that the API would ignore.

```json  theme={"dark"}
"data": {
  "posts": [{...}, ...],
  "posts_meta": [{...}, ...],
  "tags": [],
  "posts_tags": [],
  "users": [],
  "posts_authors": []
}
```

The data block contains all of the individual post, tag, and user resources that you want to import into your site, as well as the relationships between all of these resources. Each item that you include should be an array of objects.

Relationships can be defined between posts and tags, posts and users (authors).

IDs inside the file are relative to the file only, so if you have a `post` with `id: "1234"` and a `posts_tags` object which references `post_id: "1234"`, then those two things will be linked, but they do not relate to the `post` with `id: "1234"` in your database.

The example below is a working but simplified to cover most use-cases. To see what fields are available,  types, lengths, and validations, please refer to the [Ghost schema on GitHub](https://github.com/TryGhost/Ghost/blob/main/ghost/core/core/server/data/schema/schema.js).

## Example

```json  theme={"dark"}
{
    "meta": {
        "exported_on": 1753891082041,
        "version":     "6.0.0" // Ghost version the import is valid for
    },
    "data": {
        "posts": [
            {
                "id":             "1234", // The post ID, which is refered to in other places in this file
                "title":          "My Blog Post Title",
                "slug":           "my-blog-post-title",
                "html":           "<p>Hello world, this is an article</p>", // You could use `lexical` instead to to represent your content
                "comment_id":     "1234-old-cms-post-id", // The ID from the old CMS, which can be output in the theme
                "feature_image":  "/content/images/2024/waving.jpg",
                "type":           "post", // post | page
                "status":         "published", // published | draft
                "visibility":     "public", // public | members | paid
                "created_at":     "2025-06-30 15:31:36",
                "updated_at":     "2025-07-02 08:22:14",
                "published_at":   "2025-06-30 15:35:36",
                "custom_excerpt": "My custom excerpt"
            }
        ],
        // Optionally define post metadata
        "posts_meta": [
            {
                "post_id":               "1234", // This must be the same as the post it references
                "feature_image_alt":     "A group of people waving at the camera",
                "feature_image_caption": "The team says hello!"
            }
        ],
        // Define the tags
        "tags": [
            {
                "id":   "3456", // Unique ID for this tag
                "name": "News & Weather",
                "slug": "news-weather"
            }
        ],
        // Relate posts to tags
        "posts_tags": [
            {
                "post_id": "1234", // The post ID from the `posts` array
                "tag_id":  "3456" // The tag ID from the `tags` array
            }
        ],
        // Define the users
        "users": [
            {
                "id":            "5678", // Unique ID for this author
                "name":          "Jo Bloggs",
                "slug":          "jo-blogs",
                "email":         "jo@example.com",
                "profile_image": "/content/images/2025/scenic-background.jpg",
                "roles": [
                    "Contributor" // Contributor | Author| Editor | Administrator
                ]
            }
        ],
        // Relate posts to authors
        "posts_authors": [
            {
                "post_id":   "1234", // The post ID from the `posts` array
                "author_id": "5678" // The author ID from the `users` array
            }
        ]
    }
}
```


# Migrating from Ghost To Ghost
Source: https://docs.ghost.org/migration/ghost

Migrate from a self-hosted instance to Ghost(Pro) with this guide

<Note>
  If you're a Ghost(Pro) customer, our team may be able to help you migrate your content and subscribers. Learn more about our [Concierge service](https://ghost.org/concierge/).
</Note>

This guide will walk you through the process of migrating from a self-hosted Ghost instance on your own server to Ghost(Pro).

## Prerequisites

If your self-hosted site is running an older major version of Ghost, you may need to update. Check the latest [version of Ghost on GitHub](https://github.com/TryGhost/Ghost/releases), and follow this [upgrade guide](/update/).

## Back up your data

The first step towards moving from your own self-hosted Ghost instance to Ghost(Pro) is to retrieve all of your data from your server to your local machine. It’s best to do this first, to ensure you have a backup in place.

<Note>
  The commands in this guide assume you followed our [Ubuntu guide](/install/ubuntu/) to set up your own instance. If you used another method, you’ll need to adapt the paths in the commands to suit.
</Note>

### Exporting content

Log into Ghost Admin for your self-hosted in production and navigate to the **Labs** view, and click **Export** to download your content. This will be `.json` file, with a name like `my-site.ghost.2020-09-30-14-15-49.json`.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cf649c9d-ghost-content-import-export_hu272562aa500e83b9baeec6c17282ce1a_25089_1628x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=fbf82aca5ec467c9a9234ee2aeff5e75" data-og-width="1628" width="1628" data-og-height="589" height="589" data-path="images/cf649c9d-ghost-content-import-export_hu272562aa500e83b9baeec6c17282ce1a_25089_1628x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cf649c9d-ghost-content-import-export_hu272562aa500e83b9baeec6c17282ce1a_25089_1628x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=c5eeb46bb99273542cef6b325e66851a 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cf649c9d-ghost-content-import-export_hu272562aa500e83b9baeec6c17282ce1a_25089_1628x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=fcc1cc79014435c66c1feab15357c754 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cf649c9d-ghost-content-import-export_hu272562aa500e83b9baeec6c17282ce1a_25089_1628x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=1b00ba6a706ddb36e44713ca540ee77c 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cf649c9d-ghost-content-import-export_hu272562aa500e83b9baeec6c17282ce1a_25089_1628x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=319b82eeb3c467073ed72e5ab71083c4 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cf649c9d-ghost-content-import-export_hu272562aa500e83b9baeec6c17282ce1a_25089_1628x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cb02f8642f13009364c29e22763ab778 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/cf649c9d-ghost-content-import-export_hu272562aa500e83b9baeec6c17282ce1a_25089_1628x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=384c0a05587c4052ed0c7fae364fa6ac 2500w" />
</Frame>

### Routes and redirects

Staying on the **Labs** page, click **Download current redirects** to get your redirects file. This will be called `redirects.yaml` (or `redirects.json` depending on your Ghost version). If you’re using custom routes, click **Download current routes.yaml** to get your `routes.yaml` file.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3012acb6-ghost-route-redirects_hu954a63ee77a86db320db7d009e6fb2e9_29801_1628x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ff79627fed8e58647a0704ca81a122e4" data-og-width="1628" width="1628" data-og-height="672" height="672" data-path="images/3012acb6-ghost-route-redirects_hu954a63ee77a86db320db7d009e6fb2e9_29801_1628x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3012acb6-ghost-route-redirects_hu954a63ee77a86db320db7d009e6fb2e9_29801_1628x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=42a8f4b9c0f8cf5bf772c0a802e84a36 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3012acb6-ghost-route-redirects_hu954a63ee77a86db320db7d009e6fb2e9_29801_1628x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a1841de88c7e8c2630c4664eefd058ba 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3012acb6-ghost-route-redirects_hu954a63ee77a86db320db7d009e6fb2e9_29801_1628x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=526a26d3cf909a495e34c912f546b619 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3012acb6-ghost-route-redirects_hu954a63ee77a86db320db7d009e6fb2e9_29801_1628x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=9826eb3464094938ebb0f4af216b55bb 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3012acb6-ghost-route-redirects_hu954a63ee77a86db320db7d009e6fb2e9_29801_1628x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8233c2e661a16f0ba774745612448039 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3012acb6-ghost-route-redirects_hu954a63ee77a86db320db7d009e6fb2e9_29801_1628x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=33c0d49180dc707c27d40d15ff64677a 2500w" />
</Frame>

### Themes

Navigate to the **Design** view, and click the **Download** button next to the Active label export your current theme. This will be a `.zip` file. Optionally, if you have other themes that you’d like to save, download them and back them up.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/39467d2a-ghost-themes-settings_hu3b859fed207678d52a22902f80176aaf_12909_1628x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8000f7b57bad815c05fff0e6fb850221" data-og-width="1628" width="1628" data-og-height="512" height="512" data-path="images/39467d2a-ghost-themes-settings_hu3b859fed207678d52a22902f80176aaf_12909_1628x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/39467d2a-ghost-themes-settings_hu3b859fed207678d52a22902f80176aaf_12909_1628x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=c201e7160ecd305bc7e4b0a6e44d7f56 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/39467d2a-ghost-themes-settings_hu3b859fed207678d52a22902f80176aaf_12909_1628x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=41fc3e33876bd9192b729708cf4dee47 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/39467d2a-ghost-themes-settings_hu3b859fed207678d52a22902f80176aaf_12909_1628x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a36f88467d49909c53224823694f7025 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/39467d2a-ghost-themes-settings_hu3b859fed207678d52a22902f80176aaf_12909_1628x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=33ed27c163703db6606b59aeb5be84c1 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/39467d2a-ghost-themes-settings_hu3b859fed207678d52a22902f80176aaf_12909_1628x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=3f17633a57308a4db8694034e71dffd7 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/39467d2a-ghost-themes-settings_hu3b859fed207678d52a22902f80176aaf_12909_1628x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=dec9f5c129548e310c9086a9b8e403de 2500w" />
</Frame>

### Images

To download your images, you’ll need shell access to your server. If you’re unable to gain shell access to your current web host, you may need to contact their support team and ask for a zip of your images directory.

Once you’re logged in to your server, `cd` to the `content` directory:

```bash  theme={"dark"}
cd /var/www/ghost/content
```

And then `zip` the `images` directory with all its contents:

```bash  theme={"dark"}
zip -r images.zip images/*
```

Ensure your `images` folder only contains images. Any other file types may cause import errors.

Now we need to get that zip file from your server onto your local machine:

```bash  theme={"dark"}
scp user@123.456.789.123:/var/www/ghost/content/images.zip ~/Desktop/images.zip
```

The folder structure should look like this, with `images` being the only top-level folder once unzipped:

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a28febce-images-in-finder_huf248f9006ca4711e6e56a11852458172_99427_1260x0_resize_q100_h2_box.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=089e9370f7047f700d885005f13cbf73" data-og-width="1260" width="1260" data-og-height="766" height="766" data-path="images/a28febce-images-in-finder_huf248f9006ca4711e6e56a11852458172_99427_1260x0_resize_q100_h2_box.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a28febce-images-in-finder_huf248f9006ca4711e6e56a11852458172_99427_1260x0_resize_q100_h2_box.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=7b3acefaf9b6ce8711b12d9d22eace75 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a28febce-images-in-finder_huf248f9006ca4711e6e56a11852458172_99427_1260x0_resize_q100_h2_box.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=6f6db6902f100d9209d53f6faae52e24 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a28febce-images-in-finder_huf248f9006ca4711e6e56a11852458172_99427_1260x0_resize_q100_h2_box.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=9ce6d55710906b2121e5588344e50a91 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a28febce-images-in-finder_huf248f9006ca4711e6e56a11852458172_99427_1260x0_resize_q100_h2_box.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0928ed4fa30af4e5a15ae4c5d398ad67 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a28febce-images-in-finder_huf248f9006ca4711e6e56a11852458172_99427_1260x0_resize_q100_h2_box.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=8e05d81b2660e9dc71a7f1d1af151bec 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/a28febce-images-in-finder_huf248f9006ca4711e6e56a11852458172_99427_1260x0_resize_q100_h2_box.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=de9a7e0fe8c8b7ba64e28ccc3eb50f80 2500w" />
</Frame>

## Uploading to Ghost(Pro)

Once you’ve retrieved all of these exports, you can upload them to Ghost(Pro) in the same order.

### Content

Log into your new Ghost(Pro) site, and head to the **Labs** view. Next to the **Import content** header, select your content `.json` file and click **Import**.

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/64953ab4-ghost-import-successful_huade8b63d13532484da2176e269d2dc02_38287_1628x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=3325dfd55e141adeec1c9678dbcd7b84" data-og-width="1628" width="1628" data-og-height="889" height="889" data-path="images/64953ab4-ghost-import-successful_huade8b63d13532484da2176e269d2dc02_38287_1628x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/64953ab4-ghost-import-successful_huade8b63d13532484da2176e269d2dc02_38287_1628x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=e35308216d99da42d56c9c47622f490e 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/64953ab4-ghost-import-successful_huade8b63d13532484da2176e269d2dc02_38287_1628x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=e548013fae4241e82659bf467433c1ba 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/64953ab4-ghost-import-successful_huade8b63d13532484da2176e269d2dc02_38287_1628x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=3e06d673e824811f6ff8b13ff495505b 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/64953ab4-ghost-import-successful_huade8b63d13532484da2176e269d2dc02_38287_1628x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=c4b8cb333851d54b764a0a60be081aa3 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/64953ab4-ghost-import-successful_huade8b63d13532484da2176e269d2dc02_38287_1628x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=3ec0680ebab1ffe225be50ebbd8f7642 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/64953ab4-ghost-import-successful_huade8b63d13532484da2176e269d2dc02_38287_1628x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=d88f01d1d08c0e948bf3da9fd0184e56 2500w" />
</Frame>

### Routes and Redirects

Staying on the **Labs** view, click **Upload redirects JSON**, then select your `redirects.json` file to upload it. Then click **Upload routes YAML**, select your `routes.yaml` file to upload that.

### Themes

Head over to the **Design** view, and click **Upload a theme**, select your theme `.zip` file, and activate it.

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/775cf633-ghost-theme-upload_huf4a027a768e71e6bd93af4733d14943e_23711_1226x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=e313f8d4a28f1f6feb72889fdc5d55d7" data-og-width="1226" width="1226" data-og-height="520" height="520" data-path="images/775cf633-ghost-theme-upload_huf4a027a768e71e6bd93af4733d14943e_23711_1226x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/775cf633-ghost-theme-upload_huf4a027a768e71e6bd93af4733d14943e_23711_1226x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a9ce8d686a97f1c2362493598f304bde 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/775cf633-ghost-theme-upload_huf4a027a768e71e6bd93af4733d14943e_23711_1226x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=54d5a00dc1d3b8349086313b84e86900 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/775cf633-ghost-theme-upload_huf4a027a768e71e6bd93af4733d14943e_23711_1226x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=fca24b60278644e035d782bcbc9ef198 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/775cf633-ghost-theme-upload_huf4a027a768e71e6bd93af4733d14943e_23711_1226x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=53f2922805b33587c474d16b5396de3f 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/775cf633-ghost-theme-upload_huf4a027a768e71e6bd93af4733d14943e_23711_1226x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=14e92932b80ba3fcf50b26e395391c0a 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/775cf633-ghost-theme-upload_huf4a027a768e71e6bd93af4733d14943e_23711_1226x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=50e5ddc416653e226395136ba346a971 2500w" />
</Frame>

### Images

The final step is to upload your images. The best way to approach this depends on how big your `images.zip` file is. A large file will take longer to upload and process.

If your file is less than 500mb, you can upload this zip in the same way you uploaded your content JSON file. If the file is larger, it’s recommended to split it into multiple smaller files, whilst retaining the folder structure.

If you have a large image directory or encounter any errors, contact support so we can help upload your images.

***

## Summary

Congratulations on moving to Ghost(Pro). All that’s left to do is check over your content to ensure everything works as expected.

By hosting your site with us, you directly fund future product development of Ghost itself and allow us to make the product better for everyone 💘


# Migrating from Gumroad
Source: https://docs.ghost.org/migration/gumroad

Migrate from Gumroad and import your customers to Ghost with this guide

## Overview

Since Gumroad manages your subscriptions on your behalf, there is no direct migration path to move your paid subscriptions from Gumroad to other platforms.

The good news: Ghost makes it possible to import all of your existing customer emails and give them access to premium content, or to sync your Gumroad with your Ghost site using an automation.

## Export your customers

To get started, export your current subscribers from Gumroad in CSV format.

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a10c70bc-gumroad-export_hu56c76fc0713e6fce5586b59ad57c30de_7136_1520x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=f00a1431e97f8afe76b0061d3beaaab6" data-og-width="1520" width="1520" data-og-height="261" height="261" data-path="images/a10c70bc-gumroad-export_hu56c76fc0713e6fce5586b59ad57c30de_7136_1520x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a10c70bc-gumroad-export_hu56c76fc0713e6fce5586b59ad57c30de_7136_1520x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=97e614856b5265d2493f9fea4f7bfd76 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a10c70bc-gumroad-export_hu56c76fc0713e6fce5586b59ad57c30de_7136_1520x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=fa6e27e69872c3159bb4173269690eac 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a10c70bc-gumroad-export_hu56c76fc0713e6fce5586b59ad57c30de_7136_1520x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a80da84065e8bc6ab8b77e336719e84d 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a10c70bc-gumroad-export_hu56c76fc0713e6fce5586b59ad57c30de_7136_1520x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=6e9262032adc782217a6cc80ab8429b2 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a10c70bc-gumroad-export_hu56c76fc0713e6fce5586b59ad57c30de_7136_1520x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=81ef1c448d77e6391772d404218305b3 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/a10c70bc-gumroad-export_hu56c76fc0713e6fce5586b59ad57c30de_7136_1520x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=0e40596f98c70c43b7ce2dd3778adced 2500w" />
</Frame>

Gumroad allows you to export all customers who have ever purchased from you within a specific date range, or to segment your export per product.

## Import subscribers to Ghost

Under the Ghost Admin members settings, select the import option from the settings menu.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1f2f8d5b608e1dd8e7ac1b58960fc752" data-og-width="1000" width="1000" data-og-height="167" height="167" data-path="images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ddcfbaa05045604d7a3cb57df0eee4c0 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f604af49134c94d2e4ac4471bef53b27 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=526f82470ae6d5811dd6ed7c5c806846 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=e4a4d46f7842d8139b9b3353182f512c 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d174b72f8d3ee6fef63d1d59c902bcac 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=58eabc1e3b29ea3f79cb9d852afd4096 2500w" />
</Frame>

Upload your CSV file to Ghost, and map each of the fields contained in your export file to the corresponding fields in Ghost. The **email** field is required in order to create members in Ghost, while the other fields are optional.

It’s recommended to edit your data as required before uploading your CSV file to Ghost.

Once the import has completed, all your subscribers will be migrated to Ghost. There’s nothing else you need to do, members can now log into your site and receive email newsletters.

## Running Ghost alongside Gumroad

It’s also possible to use Zapier or the Ghost API to keep customers who have purchased from you on Gumroad in sync with a Ghost membership site. This is useful if you’re giving your existing customers on Gumroad access to premium content on a custom Ghost site as an additional perk, or if you’re accepting signups on both platforms.

To find out how to connect Ghost with Gumroad, check out our [integration](https://ghost.org/integrations/gumroad/).


# Migrating from Jekyll
Source: https://docs.ghost.org/migration/jekyll

Migrate from Jekyll and import your content to Ghost with this guide

Migrations from Jekyll are a complex manual process with a lot of data sanitisation work. If you want to do a migration yourself, you’ll need to follow our [developer documentation](/migration/custom/) to create your own migration archive.

Jekyll users can try the [Jekyll to Ghost Plugin](https://github.com/mekomlusa/Jekyll-to-Ghost)


# Migrating from Kit
Source: https://docs.ghost.org/migration/kit

Migrate from Kit and import your subscribers to Ghost with this guide

## Overview

Since Kit manages subscriptions on your behalf, there is no direct migration path to move any paid subscriptions from Kit to other platforms.

The good news: Ghost makes it possible to import all of your existing subscriber emails and give them access to premium content on your custom Ghost publication, or to sync your Kit subscribers with Ghost using an automation.

## Export your subscribers

To get started, export your current subscribers from Kit in CSV format.

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7f093338-export-convertkit_huc44eb2f23f6040a066f2331419f0a0c1_32934_2336x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=cb13127a1a4861e49be7f6ce8af15e20" data-og-width="2336" width="2336" data-og-height="920" height="920" data-path="images/7f093338-export-convertkit_huc44eb2f23f6040a066f2331419f0a0c1_32934_2336x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7f093338-export-convertkit_huc44eb2f23f6040a066f2331419f0a0c1_32934_2336x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=b698e045e0d19a18c324fa8a6cf5314f 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7f093338-export-convertkit_huc44eb2f23f6040a066f2331419f0a0c1_32934_2336x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=30d2f61c098c8a8eff7b148be39431e2 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7f093338-export-convertkit_huc44eb2f23f6040a066f2331419f0a0c1_32934_2336x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=8157f171bdc61d32792c5f5f4ac1ad22 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7f093338-export-convertkit_huc44eb2f23f6040a066f2331419f0a0c1_32934_2336x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=c5961f679b18b2129d09ae73cbcbaab5 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7f093338-export-convertkit_huc44eb2f23f6040a066f2331419f0a0c1_32934_2336x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=e776f4a7352c5eadd7c60050a3e6da23 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7f093338-export-convertkit_huc44eb2f23f6040a066f2331419f0a0c1_32934_2336x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=713267c565194f9f6185721aaf858bd0 2500w" />
</Frame>

## Import subscribers to Ghost

Under the Ghost Admin members settings, select the import option from the settings menu.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1f2f8d5b608e1dd8e7ac1b58960fc752" data-og-width="1000" width="1000" data-og-height="167" height="167" data-path="images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ddcfbaa05045604d7a3cb57df0eee4c0 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f604af49134c94d2e4ac4471bef53b27 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=526f82470ae6d5811dd6ed7c5c806846 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=e4a4d46f7842d8139b9b3353182f512c 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d174b72f8d3ee6fef63d1d59c902bcac 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=58eabc1e3b29ea3f79cb9d852afd4096 2500w" />
</Frame>

Upload your CSV file to Ghost, and map each of the fields contained in your export file to the corresponding fields in Ghost. The **email** field is required in order to create members in Ghost, while the other fields are optional.

It’s recommended to edit your data as required before uploading your CSV file to Ghost.

Once the import has completed, all your subscribers will be migrated to Ghost. There’s nothing else you need to do, members can now log into your site and receive email newsletters.

## Running Ghost alongside Kit

It’s also possible to use Zapier or the Ghost API to keep email subscribers from Kit in sync with a Ghost membership site. This is useful if you’re giving your existing audience in Kit access to premium content on a your Ghost site as an additional perk, or if you’re accepting signups on both platforms.

To find out how to connect Ghost with Kit, check out our [integration](https://ghost.org/integrations/convertkit/).


# Migrating from Mailchimp
Source: https://docs.ghost.org/migration/mailchimp

Migrate from Mailchimp and import your content to Ghost with this guide

You can easily migrate your subscribers from Mailchimp to Ghost in just a few clicks, using the Mailchimp migrator in Ghost Admin.

<Warning>
  ✏️ It's not currently possible to migrate your Mailchimp content.
</Warning>

## **Run the migration**

The Mailchimp migrator allows you to quickly import members from your Mailchimp to your Ghost publication. You can access the migrator tool from the **Settings → Advanced →** **Import/Export** area of Ghost Admin.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ea5e2e43c61b34a3df46aff7e2284e75" alt="migrate-tools-apr-2025.png" data-og-width="1000" width="1000" data-og-height="441" height="441" data-path="images/migrate-tools-apr-2025.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=974ddd5f6e820f26d9e040868a205751 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1926fb26e76c64fee135963a8d3129ca 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=022bb6c0f90512b8bff4fa3de651a0a7 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f61c57dfe8671ac2be7b4a7d19122178 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9607677410164b3353dc6441bbab74a7 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a5efdeb3024d7f343e73a0c72f6aa917 2500w" />

It's helpful to log in to your Mailchimp account before running the migration in Ghost Admin.

### **1. Export subscribers**

Next, it's time to import your Mailchimp subscribers. Click **Open Mailchimp Audience**, and click **Export Audience**.

Once downloaded, select **Click or drag file here to upload** and navigate to the text download, and click **Continue**.

<img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/audience-1.png?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=68a11dc353cbf32c14e2b929314be256" alt="audience-1.png" data-og-width="1582" width="1582" data-og-height="2092" height="2092" data-path="images/audience-1.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/audience-1.png?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=05461bd3f277329f1599469f3b2a6190 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/audience-1.png?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e5f27f7b56df71441486bbc15896cc91 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/audience-1.png?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0c8af47eaa66db851ecf6e19e5076fa9 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/audience-1.png?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f5c811db1f4e98dd4d1d50936dd97ac3 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/audience-1.png?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=25211b080de70e70aefe4f3553175225 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/audience-1.png?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=ca837dd0d1af313ce8aa4db61963c81b 2500w" />

### **2. Review**

Ghost will confirm the number of subscribers that will be imported to your publication. If satisfied, click **Import subscribers** to begin the import of your data.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview-2.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=016fdc8eb63e21031a09bc080c82fe7a" alt="overview-2.png" data-og-width="1582" width="1582" data-og-height="1134" height="1134" data-path="images/overview-2.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview-2.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=b66dc4f1c2ce25e55d595f8aae1c31d1 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview-2.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=77fb875bdd93ba603dc94721503346c0 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview-2.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=54f1c7609ecbae959adbf4310d993aa8 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview-2.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=3840326214508964e22f626c57274d33 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview-2.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=48d610e008e0fd5f36e71c544d9a1117 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview-2.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=80287ee416e704ebada5e0b880ed0d7b 2500w" />

After a few moments, you'll see a confirmation message, confirming that your data was successfully migrated to your Ghost site.

## **Large and Complex migrations**

If your migration needs go beyond what our in-built migration tools can support you can still move to Ghost.

If you're a **Ghost(Pro) customer**, our Migrations team can support you in migrating your content and subscribers. Learn more and get in touch with the team [here](https://ghost.org/concierge/).

Alternatively, if you are a developer, comfortable with using the command line, or running a self-hosted Ghost instance, we have a suite of[ open-source migration tools ](https://github.com/TryGhost/migrate)to help with large, complex and custom migrations.


# Migrating from Medium
Source: https://docs.ghost.org/migration/medium

Migrate from Medium and import your content to Ghost with this guide

You can easily migrate your posts and subscribers from Medium to Ghost in just a few clicks, using the Medium migrator in Ghost Admin.

## **Run the migration**

The Medium migrator allows you to quickly import content and members from your Medium to your Ghost publication. You can access the migrator tool from the **Settings → Advanced →** **Import/Export** area of Ghost Admin.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ea5e2e43c61b34a3df46aff7e2284e75" alt="migrate-tools-apr-2025.png" data-og-width="1000" width="1000" data-og-height="441" height="441" data-path="images/migrate-tools-apr-2025.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=974ddd5f6e820f26d9e040868a205751 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1926fb26e76c64fee135963a8d3129ca 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=022bb6c0f90512b8bff4fa3de651a0a7 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f61c57dfe8671ac2be7b4a7d19122178 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9607677410164b3353dc6441bbab74a7 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a5efdeb3024d7f343e73a0c72f6aa917 2500w" />

It's helpful to log in to your Medium account before running the migration in Ghost Admin.

### **1. Enter your Medium URL**

To start the migration process, enter the public URL to your Medium, and click **Continue**.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/url.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=4196f5c27e93dea8bdb6c2bcee4fd9de" alt="url.png" data-og-width="1582" width="1582" data-og-height="1154" height="1154" data-path="images/url.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/url.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=821350cd205b9f116e061c5f16f80fa9 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/url.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=3f6fa7d33a60ee8e5a9092ed2db1fae2 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/url.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a3ad8cbec9d5d979c716cf2a83bb37e8 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/url.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9cf07837f7c20ce562659c3f9cd2add5 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/url.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=08f7c0805c8080ffe7699e6959ea0c91 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/url.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=aed2f188b32a8825e181ee660c8dc35a 2500w" />

### **2. Export content**

Next, click **Open Medium Settings**, and click **Download your information**. A link to download the export will be sent to your email.

<img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/content.png?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=370afaaa97b89e36db8fd6ef4745913f" alt="content.png" data-og-width="1582" width="1582" data-og-height="2408" height="2408" data-path="images/content.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/content.png?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=ce69f26b078cff3a84d43a071042ad44 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/content.png?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=fe039840b75961c3c6b1f91dd45e67ac 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/content.png?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=39446cbe7e561b3748c9d50b3a66a52f 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/content.png?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=064da533c181e1271f9d5663b4db516e 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/content.png?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=1da9d70c7834d78820a428c3043fc99f 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/content.png?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=2b71f111495936b00c977441c2d896e7 2500w" />

### **3. Upload content**

Once your export has been downloaded, return to the migrator window in Ghost Admin, and select **Click or drag file here to upload**, and navigate to the zip file you downloaded from Medium, once uploaded click **Continue**.

If you're unsure of where the file was saved, check your Downloads folder.

### **4. Export subscribers**

Next, it's time to import your Medium subscribers. Click **Open Medium Audience stats**, and click **Export this list**.

Once downloaded, select **Click or drag file here to upload** and navigate to the text download, and click **Continue**.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/subscribers.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=4df916dc508445c18a9d7f23e7003762" alt="subscribers.png" data-og-width="1582" width="1582" data-og-height="2318" height="2318" data-path="images/subscribers.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/subscribers.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=c520c1fbed3e6d39386e3e435778511b 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/subscribers.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f1fe6fc09b8567c3d566ee096764b159 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/subscribers.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=fee9021869e58f8ef527a7178d6503c5 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/subscribers.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=4c9df248cfe3f208ac6b8aaf45b26ae0 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/subscribers.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9daf503acca1f83d860029e3a1da5f14 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/subscribers.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=aaf028735a702a6c40f12360eade4ecb 2500w" />

### **5. Review**

Ghost will confirm the number of posts and members that will be imported to your publication. If satisfied, click **Import content and subscribers** to begin the import of your data.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=456e95e54c705a7812ef89da292daf50" alt="overview.png" data-og-width="1582" width="1582" data-og-height="1364" height="1364" data-path="images/overview.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=423b9ddbacd09949b841fdd888b48ad3 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=bb6f42804716f1ec16866e287d1c445c 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=8d13d743c3369c598db355d125fd672e 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=3f244697bd9fc5651e3c979236526e50 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=c47b9fa44e0f038d26c64f671c3a22b5 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/overview.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=3d58816039eb054e5f3c7cb968b57a59 2500w" />

After a few moments, you'll see a confirmation message, confirming that your data was successfully migrated to your Ghost site.

### **6. Verification and manual checks**

<Warning>
  ⚠️ The Medium content export includes all of your posts and **all of the comments you've written across Medium**. There is no sure-fire way to differentiate between these content types, so you should check the import to verify your posts are live.
</Warning>

The importer will make a post in Ghost for all posts and comments in your Medium export. The importer will try to sort posts and comments, based on the following rules:

* If a piece has only one paragraph, treat it as a **comment**
* If a piece of any length has an image, treat it as a **post**
* Otherwise, treat the piece as a **post**
* All pieces that are treated as **comments** will be saved as **drafts**
* All **posts** that were **drafts** in Medium, will be **drafts** in Ghost
* All \*\*posts \*\*that were **published** in Medium will be **published** in Ghost

You should check that comments and posts were sorted correctly. Possible comments that have been saved as drafts will be tagged `#Medium Possible Comment`.

### Using custom domains

If you’re using a custom domain on Medium, you’ll need to implement redirects in Ghost to prevent broken links.

Medium appends a small random ID to each post, which is removed in the migration step above. The regular expression below removes that random ID, but does not affect preview links.

```yaml  theme={"dark"}
# redirects.yaml
301:
    ^\/(?!p\/?)(.*)(-[0-9a-f]{10,12}): /$1

302:
```

This means that if a visitor or crawler goes to `https://mysite.com/awesome-post-a1b2c3d4e5f6`, they will automatically be redirected to `https://mysite.com/awesome-post`.

Learn more about Medium redirects [here](https://ghost.org/tutorials/implementing-redirects/#medium).

***

## **Large and Complex migrations**

If your migration needs go beyond what our in-built migration tools can support you can still move to Ghost.

If you're a **Ghost(Pro) customer**, our Migrations team can support you in migrating your content and subscribers. Learn more and get in touch with the team [here](https://ghost.org/concierge/).

Alternatively, if you are a developer, comfortable with using the command line, or running a self-hosted Ghost instance, we have a suite of[ open-source migration tools ](https://github.com/TryGhost/migrate)to help with large, complex and custom migrations.


# Migrating from Memberful
Source: https://docs.ghost.org/migration/memberful

Migrate from Memberful and import your members to Ghost with this guide

<Note>
  If you're a Ghost(Pro) customer, our team may be able to help you migrate your content and subscribers. Learn more about our [Concierge service](https://ghost.org/concierge/).
</Note>

## Export your subscribers

To get started, export your current subscribers in CSV format.

## Import subscribers to Ghost

Under the Ghost Admin members settings, select the import option from the settings menu.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1f2f8d5b608e1dd8e7ac1b58960fc752" data-og-width="1000" width="1000" data-og-height="167" height="167" data-path="images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ddcfbaa05045604d7a3cb57df0eee4c0 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f604af49134c94d2e4ac4471bef53b27 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=526f82470ae6d5811dd6ed7c5c806846 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=e4a4d46f7842d8139b9b3353182f512c 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d174b72f8d3ee6fef63d1d59c902bcac 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=58eabc1e3b29ea3f79cb9d852afd4096 2500w" />
</Frame>

Upload your CSV file to Ghost, and map each of the fields contained in your export file to the corresponding fields in Ghost. The **email** field is required in order to create members in Ghost, while the other fields are optional.

If you’d like to give these members access to content with an access level of `paid-members only` but retain their subscriptions in Memberful, you can give them unlimited access by setting their `complimentary_plan` status to `true` — read more about [Member imports](https://ghost.org/help/import-members/).

Once the import has completed, all your subscribers will be migrated to Ghost. There’s nothing else you need to do, members can now log into your site and receive email newsletters.


# Migrating from Newspack
Source: https://docs.ghost.org/migration/newspack

Migrate from Newspack and import your content to Ghost with this guide. You can manage a migration from Newspack yourself or, if you prefer, our team can take care of the migration for you.

<Note>
  If you're a Ghost(Pro) customer, our team may be able to help you migrate your content and subscribers. Learn more about our [Concierge service](https://ghost.org/concierge/).
</Note>

If you’d rather do the migration yourself, that’s fine too, and you can follow the guide below.

## Newspack migration steps

In order to migrate fully from Newspack to Ghost, here are the different steps you’ll need to take.

#### Migrating content

Newspack sites run on WordPress, so the first thing you’ll want to do is follow our [WordPress migration guide](/migration/wordpress/). This will allow you export all your published content, and bring it into Ghost.

#### Migrating your theme

Ghost comes with several free themes built with news publishers in mind. We suggest starting with [Headline](https://ghost.org/themes/headline/), which is lightning fast, SEO optimised, and can be further customised to match your brand.

#### Migrating email subscribers

Ghost can import email subscribers from any platform. Most newspack publishers use Mailchimp, and to migrate contacts you can follow our [Mailchimp migration guide](/migration/mailchimp/). Email newsletters are built into Ghost natively, so you won’t need to keep paying for a 3rd party service anymore after migrating.

#### Migrating paid subscribers

Newspack and Ghost both use Stripe for subscription payments, and you can easily import paying subscribers into Ghost by connecting to your Stripe account. When [importing subscribers](https://ghost.org/help/import-members/#prepare-your-csv-file), make sure to include their Stripe Customer ID, and Ghost will link up the records automatically. If you need help with this, drop us an email on `concierge@ghost.org`.

#### Migrating ads & analytics

Ghost supports all of the same advertising and analytics services as Newspack, and all of these can be migrated easily. You can paste any needed tracking codes into **Settings → Code Injection**, or you can edit your theme directly to include the code snippets there, if you want more control.

#### Migrating URLs

For the most part, Ghost will easily match the URL structure of your old site, so any links to your site will keep working as normal. If you have any URLs that have changed, you can take care of these by [setting up redirects](https://ghost.org/tutorials/implementing-redirects/) in Ghost.

***

## Newspack migration limitations

Ghost has an automatically built-in commenting system for your members and subscribers, but it’s not currently possible to migrate comments from other platforms into Ghost. If you’ve found your comments section is mostly full of spam, though, then you might actually welcome a fresh start.

Ghost does not support marketplace listings / directories. If you use this feature of Newspack, this is not something that can be migrated. However, if it’s really important to you, you could always set up a directory on a subdomain of your site - like `listings.yoursite.com`.

***

## Newspack migration FAQ

**Is migrating from Newspack to Ghost difficult?**\
Not really! Newspack sites are just WordPress, and we’ve migrated tens of thousands of WordPress sites to Ghost over the years. Most people tend to favour Ghost because it’s a fully integrated platform specifically designed for publishers, rather than a disparate set of CMS plugins.

**What about dynamic blocks and pages?**\
Ghost has those, too. They work very similarly to Newspack, but for the most part they’re much easier to use. Ghost places more emphasis on publishing content with rich media, and less emphasis on dragging/dropping things into complex layouts. We’ve also got [a handy comparison guide](https://ghost.org/vs/newspack/) if you want to get a clearer idea of Newspack features compared to Ghost.

**Why is Ghost so much cheaper than Newspack**\
Good question! Newspack is a side-project by WordPress with a small number of customers, so they have to charge a high amount for each customer in order to be able to afford to maintain their product. Ghost is not a side-project, it’s our only project. We have tens of thousands of customers and millions of users, so we don’t need to charge as much per newsroom.

**Newspack works with Google News Initiative, won’t I lose that advantage in migrating to Ghost?**\
Not at all. Ghost has been working with Google News Initiative for years, and we’re proud to be an official technology partner for Google News Initiative bootcamps. We’re thrilled to work with Google on supporting as many local news publishers as we can.

**I read that you offer additional support for small newsrooms, what’s that about?**\
We do! If you run a small local news organisation and would like to chat about how we can support you, get in touch with us by email on `concierge@ghost.org`.

**I’m not confident with tech. How can I do these migration steps?**\
Let our team do them for you, for free. Drop us an email on `concierge@ghost.org` to find out more.


# Migrating from Patreon
Source: https://docs.ghost.org/migration/patreon

Migrate from Patreon and import your Patrons to Ghost with this guide

## Overview

Since Patreon manages your subscriptions on your behalf, there is no direct migration path to move your paid subscriptions from Patreon to other platforms.

The good news: Ghost makes it possible to import all of your existing patrons and give them access to premium content on a custom Ghost publication, or to sync your Patreon account with Ghost using an automation. [Learn more here](https://ghost.org/resources/patreon-vs-your-own-site/).

## Migrating Patrons to Ghost

Ghost has an easy to use importer that allows you to migrate a list of members from any other tool, including Patreon.

This method is useful if you’re planning to turn signups in Patreon off and have all new members sign up via Ghost, but still need to give your existing Patrons access to your new Ghost Publication.

### Export your subscribers

To get started, export your current subscribers in CSV format from [this page](https://www.patreon.com/members) in your Patreon account.

### Import subscribers to Ghost

Under the Ghost Admin members settings, select the import option from the settings menu.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1f2f8d5b608e1dd8e7ac1b58960fc752" data-og-width="1000" width="1000" data-og-height="167" height="167" data-path="images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ddcfbaa05045604d7a3cb57df0eee4c0 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f604af49134c94d2e4ac4471bef53b27 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=526f82470ae6d5811dd6ed7c5c806846 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=e4a4d46f7842d8139b9b3353182f512c 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d174b72f8d3ee6fef63d1d59c902bcac 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2f96f746-import-members-1_huc3d26abd3bec140dac4d1e5fd61f2b53_17353_1000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=58eabc1e3b29ea3f79cb9d852afd4096 2500w" />
</Frame>

Upload your CSV file to Ghost, and map each of the fields contained in your export file to the corresponding fields in Ghost. The **email** field is required in order to create members in Ghost, while the other fields are optional.

If you’d like to give these members access to content with an acceess level of `paid-members only` but retain their subscriptions in Patreon, you can give them unlimited access by setting their `complimentary_plan` status to `true` — read more about [Member imports](https://ghost.org/help/import-members/).

Once the import has completed, all your subscribers will be migrated to Ghost. There’s nothing else you need to do, members can now log into your site and receive email newsletters.

## Running Ghost alongside Patreon

It’s also possible to use Zapier or the Ghost API to keep your Patrons and Members in sync in both platforms. This is useful if you’re giving your audience on Patreon access to premium content on a custom Ghost site as an additional perk, or if you’re accepting signups on both platforms.

To find out how to connect Ghost with Patreon, check out our [integration](https://ghost.org/integrations/patreon/).


# Migrating from Squarespace
Source: https://docs.ghost.org/migration/squarespace

Official guide: How to migrate from Squarespace to Ghost

You can easily migrate your posts from your Squarespace site to Ghost in just a few clicks, using the built-in Squarespace migrator in Ghost Admin.

## **Run the migration**

The Squarespace migrator allows you to quickly import content from your Squarespace site to your Ghost publication. You can access the migrator tool from the **Settings → Advanced →** **Import/Export** area of Ghost Admin.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ea5e2e43c61b34a3df46aff7e2284e75" alt="The in app Migrate Tools" data-og-width="1000" width="1000" data-og-height="441" height="441" data-path="images/migrate-tools-apr-2025.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=974ddd5f6e820f26d9e040868a205751 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1926fb26e76c64fee135963a8d3129ca 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=022bb6c0f90512b8bff4fa3de651a0a7 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f61c57dfe8671ac2be7b4a7d19122178 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9607677410164b3353dc6441bbab74a7 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a5efdeb3024d7f343e73a0c72f6aa917 2500w" />

It's helpful to log in to your Squarespace site before running the migration in Ghost Admin.

### **1. Enter your Squarespace URL**

To start the migration process, enter the public URL to your Squarespace site, and click **Continue**.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-1.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ab6c583e93160af6f67a688e97d5f584" alt="Squarespace Step 1" data-og-width="1000" width="1000" data-og-height="767" height="767" data-path="images/squarepace-1.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-1.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=0d20d219e9a4b694ccb7e74ae0fbdcc6 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-1.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=7f24f151e0e1b4bb5e14a871c8046ad6 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-1.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=e8ba1960b24e67f1e30b5d626657e472 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-1.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1ced061b4e476d43c7f1b6efc2120739 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-1.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=32a74c492dacb61b69bf64f281089e8b 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-1.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ab8745f528456b3d4c537f27a6714b07 2500w" />

### **2. Export content**

Next, click **Open Squarespace settings.** If already logged into Squarespace, this will take you directly to the location of your Squarespace site where an export can be generated.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-2.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=0c3232babe3def0d0ba2ce85d2d2702d" alt="Squarespace Step 2" data-og-width="1000" width="1000" data-og-height="1373" height="1373" data-path="images/squarepace-2.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-2.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a95131172d6a340817f0b93276a47a5a 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-2.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=8eccc86c2acaf376f36b2613d3078680 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-2.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=0d59274ae5ece372018dd1bba1c7bb90 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-2.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=875841b9dccb86c002df704801c6c97e 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-2.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=b088c3cc7ad304abfd803cde41a0c622 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-2.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=bd18de282114819827370ee535d1dd17 2500w" />

Click **Export**, which will download an XML file with your content in it.

### **3. Upload content**

Once your export has been downloaded, return to the migrator window in Ghost Admin, and select **Click or drag file here to upload**, and navigate to the XML file you downloaded from Squarespace, once uploaded click **Continue**.

If you're unsure of where the file was saved, check your Downloads folder.

### **4. Review**

Ghost will confirm the number of posts and pages that will be imported to your publication. If satisfied, click **Import content** to begin the import of your data.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-3.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=16a331fa04372c1f686edb90044a8306" alt="Squarespace Step 3" data-og-width="1000" width="1000" data-og-height="845" height="845" data-path="images/squarepace-3.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-3.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=5a77742a5b49a36f71b8951c76afc1db 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-3.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=cf7350823a5fe5fb5a3c1e08f60e8b5b 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-3.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=98c51924c77b18c541397ea857fc1ea3 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-3.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=8129dbe0f56455de0a996c9140d01169 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-3.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=7310c9a4909b0978d7305b53e76b7fda 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/squarepace-3.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=79bc1e737d5937a6cfe9b50ea68cb906 2500w" />

After a few moments, you'll see a confirmation message, confirming that your data was successfully migrated to your Ghost site.

***

### **Redirects**

<Info>
  Squarespace categories are converted to [tags](https://ghost.org/help/tags/) during the migration. The first category for any post will also become the [primary tag](https://ghost.org/help/tags/#primary-tags).
</Info>

You may need to add [redirects](https://ghost.org/help/redirects/) to ensure backlinks lead to the correct content.

Please refer to this list of the [most common redirection rules for Squarespace migrations](https://ghost.org/tutorials/implementing-redirects/#squarespace).

***

## Large and Complex migrations

If your migration needs go beyond what our in-built migration tools can support you can still move to Ghost.

If you're a **Ghost(Pro) customer**, our Migrations team can support you in migrating your content and subscribers. Learn more and get in touch with the team [here](https://ghost.org/concierge/).

Alternatively, if you are a developer, comfortable with using the command line, or running a self-hosted Ghost instance, we have a suite of[ open-source migration tools ](https://github.com/TryGhost/migrate)to help with large, complex and custom migrations.


# Migrating from Substack
Source: https://docs.ghost.org/migration/substack

Migrate from Substack and import your content to Ghost with this guide

<Tip>
  💡 **Migrating paid memberships from Substack?** You will need to set up Stripe first — [**find out more**](https://ghost.org/help/stripe/). Make sure to use the same Stripe account that is connected to your Substack.
</Tip>

## **Run the migration**

The Substack migrator allows you to quickly import content and members from your Substack to your Ghost publication. You can access the migrator tool from the **Settings → Advanced →** **Import/Export** area of Ghost Admin.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ea5e2e43c61b34a3df46aff7e2284e75" alt="Migrate Tools Apr 2025 Pn" data-og-width="1000" width="1000" data-og-height="441" height="441" data-path="images/migrate-tools-apr-2025.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=974ddd5f6e820f26d9e040868a205751 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1926fb26e76c64fee135963a8d3129ca 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=022bb6c0f90512b8bff4fa3de651a0a7 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f61c57dfe8671ac2be7b4a7d19122178 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9607677410164b3353dc6441bbab74a7 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a5efdeb3024d7f343e73a0c72f6aa917 2500w" />

It's helpful to log in to your Substack account before running the migration in Ghost Admin.

### **1. Enter your Substack URL**

To start the migration process, enter the public URL to your Substack, and click **Continue**.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/enter-url.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=2a841004278c2585bd25d438605e4bd7" alt="enter-url.png" data-og-width="1582" width="1582" data-og-height="1154" height="1154" data-path="images/enter-url.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/enter-url.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=3821aeffe6089ef54cc9f01d2473c1cd 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/enter-url.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=5468d523d43bad64e1bff489f575b394 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/enter-url.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=39d2d8bcaf3601a603505c9972b9822e 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/enter-url.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=47642a179caa7bd48515897c7984c3b4 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/enter-url.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9ccd1bb1f8f0158e69ec5e8944d31b4b 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/enter-url.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=6d71fe3560dd6752d1234171c4f8788d 2500w" />

### **2. Export content**

Next, click **Open Substack Settings.** If already logged into Substack, this will take you directly to the location of your Substack account where an export can be generated.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-content.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=30b256ab7c14801de1fea6ec7e96c4b3" alt="import-content.png" data-og-width="1582" width="1582" data-og-height="2296" height="2296" data-path="images/import-content.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-content.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=37e9831727ccc6bf3628c668a3a6fcbf 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-content.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=5d93c8d497ef1ac4bfec01097750e087 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-content.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a5c758c32536c9dec462243693502fe9 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-content.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=0fcfea5ecd42aaeb58c890fee1c596d7 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-content.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=93cdc588feb2890577c93b29f3b2c214 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-content.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ca3a0f0cc72d6cfe520526ca9850094a 2500w" />

Click **Create new export**, and then download the zip file that's generated after the export is completed in Substack.

### **3. Upload content**

Once your export has been downloaded, return to the migrator window in Ghost Admin, and select **Click or drag file here to upload**, and navigate to the zip file you downloaded from Substack, once uploaded click **Continue**.

If you're unsure of where the file was saved, check your Downloads folder.

### **4. Export free subscribers**

Next, it's time to import your Substack subscribers. Click **Download free subscribers from Substack**, to trigger a CSV file download of your subscriber list.

Once downloaded, select **Click or drag CSV file here to upload** and navigate to the CSV download, and click **Continue**.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-free-subscribers.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9419cf3991836a6fb9f5570c351cc73c" alt="import-free-subscribers.png" data-og-width="1582" width="1582" data-og-height="1770" height="1770" data-path="images/import-free-subscribers.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-free-subscribers.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=85444c945ef96ef855764d137d93901d 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-free-subscribers.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=64e21cf4200a16c57e0d2e3d69951c39 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-free-subscribers.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9eb00021eea12079cd48780493e7aab0 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-free-subscribers.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=661f3b3ffbe3cffacb9f259925b47761 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-free-subscribers.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=12f646e33797d4da0112325db9443b8d 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-free-subscribers.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=e9ae97f243770a2d381f95242725312d 2500w" />

### **5. Export paid subscribers**

<Tip>
  💡 **Migrating paid memberships from Substack?** You will need to set up Stripe first — [**find out more**](https://ghost.org/help/stripe/). Make sure to use the same Stripe account that is connected to your Substack.
</Tip>

Next, it's time to import your Substack subscribers, if you have them. Click **Download paid subscribers from Substack**, to trigger a CSV file download of your subscriber list.

Once downloaded, select **Click or drag CSV file here to upload** and navigate to the CSV download, and click **Continue**.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-paid-subscribers.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=c0601ec4d554da6e91660da58b60129c" alt="import-paid-subscribers.png" data-og-width="1582" width="1582" data-og-height="1770" height="1770" data-path="images/import-paid-subscribers.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-paid-subscribers.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=96b057e801082f7437eb9138eec7c5e6 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-paid-subscribers.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=6789a69ad9e2091502a49791bd0c6c61 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-paid-subscribers.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=bfd34a957c3071c222f154c1ea42ce33 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-paid-subscribers.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=7e6bbe25e158f7752f2d8ebf9b98d664 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-paid-subscribers.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=46101c7c54ac5c9b685f5fa2b41ff4cc 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/import-paid-subscribers.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=e51a736257e370b2a36d2920549da6f0 2500w" />

### **6. Review**

Ghost will confirm the number of posts and members that will be imported to your publication. If satisfied, click **Import content and subscribers** to begin the import of your data.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/summary.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f5b5b427309a614760af7075b8965f79" alt="summary.png" data-og-width="1582" width="1582" data-og-height="1430" height="1430" data-path="images/summary.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/summary.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=3a669020e55d238d0ed657d4d53f6249 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/summary.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9ea0e2547cbcdd1e4a151a2e1663b30f 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/summary.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1922efe19e994554c1c52323c3bc67a9 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/summary.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=c64bf90aed9b3848bb0bb9dc2b50a3ab 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/summary.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=28436ac164dc0d0074260130da377b29 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/summary.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=46041d8fb4f0e3b207b32bbb8a39ffe3 2500w" />

After a few moments, you'll see a confirmation message, confirming that your data was successfully migrated to your Ghost site.

### **Substack fees**

Ghost does not take a cut of your revenue. Substack will continue to take **10% fees** on your existing paid subscriptions. If you would like help getting payment fees removed, contact [concierge@ghost.org](mailto:concierge@ghost.org).

### **Statement descriptor**

The statement descriptor is what's shown on bank statements, and depending on how the account was set up, might include 'Substack' in the name. We recommend updating this in your [Stripe public details settings](https://dashboard.stripe.com/settings/update/public/support-details).

### **Using custom domains**

If you’re using a custom domain on Substack, you’ll need to implement redirects in Ghost to prevent broken links.

Substack uses `/p/` as part of the public post URL, where as Ghost uses it in the URL for post previews. This means the redirect regular expression is quite complex, but necessary so that post previews in Ghost function correctly.

```yaml  theme={"dark"}
# redirects.yaml
301:
    \/p\/(?![0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(.*): /$1

302:
```

This means that if a visitor or crawler goes to `https://mysite.com/p/awesome-post`, they will automatically be redirected to `https://mysite.com/awesome-post`.

For more information on Substack redirects, visit our guide [here](https://ghost.org/tutorials/implementing-redirects/#substack).

## Large and Complex migrations

If your migration needs go beyond what our in-built migration tools can support you can still move to Ghost.

If you're a **Ghost(Pro) customer**, our Migrations team can support you in migrating your content and subscribers. Learn more and get in touch with the team [here](https://ghost.org/concierge/).

Alternatively, if you are a developer, comfortable with using the command line, or running a self-hosted Ghost instance, we have a suite of[ open-source migration tools ](https://github.com/TryGhost/migrate)to help with large, complex and custom migrations.


# Migrating from WordPress
Source: https://docs.ghost.org/migration/wordpress

Migrate from WordPress and import your content to Ghost with this guide

You can easily migrate your posts and pages from WordPress site to Ghost in just a few clicks, using the WordPress migrator in Ghost Admin.

## **Run the migration**

The WordPress migrator allows you to quickly import content from your WordPress site to your Ghost publication. You can access the migrator tool from the **Settings → Advanced →** **Import/Export** area of Ghost Admin.

<img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ea5e2e43c61b34a3df46aff7e2284e75" alt="migrate-tools-apr-2025.png" data-og-width="1000" width="1000" data-og-height="441" height="441" data-path="images/migrate-tools-apr-2025.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=974ddd5f6e820f26d9e040868a205751 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1926fb26e76c64fee135963a8d3129ca 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=022bb6c0f90512b8bff4fa3de651a0a7 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f61c57dfe8671ac2be7b4a7d19122178 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9607677410164b3353dc6441bbab74a7 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/migrate-tools-apr-2025.png?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a5efdeb3024d7f343e73a0c72f6aa917 2500w" />

It's helpful to log in to your WordPress site before running the migration in Ghost Admin.

### **1. Enter your WordPress URL**

To start the migration process, enter the public URL to your WordPress site, and click **Continue**.

<img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1.png?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ea41a548f1ac0c5fbc98126d367ccf37" alt="1.png" data-og-width="1000" width="1000" data-og-height="795" height="795" data-path="images/1.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1.png?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=39dc8a14ccce327afdb258ec78a081ec 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1.png?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7c35ce0244f64a223564f70a1fcc3948 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1.png?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ddf454caf216fa5a9605081f5d131c41 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1.png?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7bcf93eb2753a04a4e0563ae439326cb 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1.png?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=aae8085dd13f3040a050c4961f4efefc 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1.png?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7aba669b4bc0c14e8c511ca720df25bd 2500w" />

### **2. Export content**

Next, click **Open WordPress Settings.** If already logged into WordPress, this will take you directly to the location of your WordPress site where an export can be generated.

<img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2.png?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8bada82e6a12a24221f5ddf6a8800fbc" alt="2.png" data-og-width="1000" width="1000" data-og-height="1302" height="1302" data-path="images/2.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2.png?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=cb79092b9556e94e0a2f45b65f11db35 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2.png?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=2980c566c561e54f6bbc6126ff39b8a0 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2.png?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a0b8b1edb8ef0267f8589dc92eed0212 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2.png?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=008796d2bda8bc1d290d2f4d3e5121fa 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2.png?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f5181685a149d809374ad03d0b6ff8e9 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2.png?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=2d1001558782e13fe78033c0c3fef95d 2500w" />

Select **All content,** click **Download Export File**, which will download an XML file with your content in it.

### **3. Upload content**

Once your export has been downloaded, return to the migrator window in Ghost Admin, and select **Click or drag file here to upload**, and navigate to the XML file you downloaded from WordPress, once uploaded click **Continue**.

If you're unsure of where the file was saved, check your Downloads folder.

### **4. Review**

Ghost will confirm the number of posts and pages that will be imported to your publication. If satisfied, click **Import content** to begin the import of your data.

<img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3.png?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ab4413e91c35344265feb2a45da1dc84" alt="3.png" data-og-width="1000" width="1000" data-og-height="886" height="886" data-path="images/3.png" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3.png?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=cc9a2a0c900a413579eb4f5f36122aee 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3.png?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a1caf77eb40503a17d4e8e6d9e4a81ed 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3.png?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ed3e3870c59a573e2ccabf76cddf0959 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3.png?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=b35429829ff5a57f1efb2e0ec2a5351e 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3.png?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=db29f65d0c4cf2ffd7a8dcad29a6fa63 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/3.png?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=5c8318d9ff8f864f436a0c729c9fe6e4 2500w" />

After a few moments, you'll see a confirmation message, confirming that your data was successfully migrated to your Ghost site.

### Supported Content

What is supported:

* XML files up to 100mb
* Up to 2,500 posts
* Some shortcodes, such as `[caption]`, `[audio]`, `[code]`, along with most `[vc_]` & `[et_]` based shortcodes from page builder plugins.

What's not supported:

* Custom post types
* Most uncommon shortcodes
* Plugins that alter access to content

***

### **Redirects**

<Info>
  ℹ️ WordPress categories are converted to [tags](https://ghost.org/help/tags/) during the migration. The first category for any post will also become the [primary tag](https://ghost.org/help/tags/#primary-tags).
</Info>

You may need to add redirects to ensure backlinks lead to the correct content.

Please refer to this list of the [most common redirection rules for WordPress migrations](https://ghost.org/tutorials/implementing-redirects/#common-redirects).

## **Large and Complex migrations**

If your migration needs go beyond what our in-built migration tools can support you can still move to Ghost.

If you're a **Ghost(Pro) customer**, our Migrations team can support you in migrating your content and subscribers. Learn more and get in touch with the team [here](https://ghost.org/concierge/).

Alternatively, if you are a developer, comfortable with using the command line, or running a self-hosted Ghost instance, we have a suite of[ open-source migration tools ](https://github.com/TryGhost/migrate)to help with large, complex and custom migrations.


# Email Newsletters
Source: https://docs.ghost.org/newsletters

Sites using the Members feature benefit from built-in email newsletters, where all posts can be delivered directly to segments of your audience in just a few clicks.

***

## Overview

Email newsletters in Ghost can be scheduled and delivered to free and paid members, or a segment of free *or* paid members. Newsletters are delivered using a beautiful HTML template that is standardised for most popular email clients.

Ghost sites have a single newsletter by default but additional ones can be created and customised. Multiple newsletters allow you to tailor content for specific audiences and your members to choose which content they receive.

## Bulk email configuration

In order to send email newsletters from a Ghost site, email needs to be configured.

### Ghost(Pro)

When using [Ghost(Pro)](https://ghost.org/pricing/), email delivery is included and the configuration is handled for you automatically.

### Self-hosted

Self-hosted Ghost installs can configure bulk email by entering Mailgun API keys from the **Email newsletter** settings.

Delivering bulk email newsletters can’t be done with basic SMTP. A bulk mail provider is a requirement to reliably deliver bulk mail. At present, Mailgun is the only supported bulk email provider. Mailgun is free for up to 600 emails per month, and has very reasonable pricing beyond that. [More info here](/faq/mailgun-newsletters/)

<Frame>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/mailgun-form.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=0df4ab16115fb1665a28735c5b02bc0a" data-og-width="1400" width="1400" data-og-height="534" height="534" data-path="images/mailgun-form.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/mailgun-form.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=10bb39b7f0f412e3bcff81ebc542cb00 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/mailgun-form.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ff5a0a16e07c5a95badb356b7bf3b927 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/mailgun-form.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=e6eaa60d56fc1a8b9dc517c4c06a2029 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/mailgun-form.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=177703710df246d4390447aae15b232c 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/mailgun-form.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=3930b911024698c25fbc3c45ec44dec6 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/mailgun-form.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f2cfbc29348610fa743228e0de696208 2500w" />
</Frame>

### Auth email

The Members feature uses passwordless email-link based logins for your members. These auth emails are not delivered in bulk and are sent using the standard mail configuration in Ghost.

Self-hosted Ghost installs can [configure mail](/config/#mail) using Mailgun or other providers if preferred.


# Product Principles & Roadmap
Source: https://docs.ghost.org/product

Developing Ghost as a product is a complex process undertaken by a small number of people with a great deal of care.

***

## How we make product decisions

Ghost is a small, bootstrapped non-profit organization with no external funding. We make revenue from our [Ghost(Pro)](https://ghost.org/pricing/) platform, which sustains the company and funds a handful of developers who improve the software. Because we don’t have tens of millions of dollars in VC money or hundreds of developers, we have to carefully choose where to dedicate our limited team and resources. We can’t do everything.

When deciding what to do next, we try to look at what would benefit most users, in most ways, most of the time. You can get a sense of those things over on [our public changelog](https://ghost.org/changelog/).

Outside of the core team, Ghost is completely [open source](https://github.com/tryghost/ghost/), so anyone in the world can contribute and help build a feature that they’d like to see in the software, even if the core team isn’t working on it.

## Feature requests

We welcome feature requests from users over in [the ideas category](https://forum.ghost.org/c/Ideas) of the Ghost Forum. Here, people can request and suggest things which they’d like to see in Ghost, and others can add their votes.

The ideas board is a great way for us to gauge user demand, but it’s not a democratic system. We don’t automatically build things just because they get a lot of votes, and not everything that gets requested makes it into core, but we do pay close attention to things with lots of demand.

## Why haven’t you built X yet? When will you?

Based on how we make product decisions, and what feature requests we get (detailed above) — if neither the core team nor the wider community are building the thing you want, then it’s likely that there isn’t enough demand or interest to make it happen at the moment.

But, the great thing about open source is that if enough people want something, they can easily get together on GitHub and make it happen themselves (or fund someone else to). There’s no need to wait on the core team to deliver it. If you really want or need a particular feature, it’s entirely possible to make that happen.

You can get involved, either by contributing your time and development skills, or by providing financial support to fund someone with these skills.

## I’m very upset you aren’t doing what I want!

For the most part, the Ghost community is kind and understanding of the complexities and constraints of building modern software. Every so often, though, we get a series of comments along the lines of:

> Wow, I can’t believe this is broken and nobody is doing anything. How have you messed up something so basic? Can the devs fix ASAP. Thanks.

Comments like this don't inspire anyone to help you. Not the core team, and certainly not the wider group of volunteer contributors. If you're friendly and polite, other will typically be friendly in return.

If you feel really passionate about something specific, you have 3 potential courses of action:

1. Get involved on GitHub and contribute code to fix the issue
2. Hire a developer to get involved on GitHub and contribute code to fix the issue
3. Start a feature request topic on the forum to demonstrate that lots of other users care about this too, and have voted on it, which is the most likely way the core team will prioritize it.

## Is there a public roadmap for what’s coming next?

The Ghost core team maintains a broad 1-2 year product roadmap at any given time, which defines the overall direction of the company and the software. While the exact roadmap isn’t shared publicly (we tried it and it turned out to be more distracting than helpful), the things being worked on are generally very visible [on GitHub](https://github.com/tryghost/ghost).


# Publishing
Source: https://docs.ghost.org/publishing

Posts are the primary entry-type within Ghost, and generally represent the majority of stored data.

***

By default Ghost will return a reverse chronological feed of posts in the traditional format of a blog. However, a great deal of customisation is available for this behaviour.

## Overview

Posts are created within Ghost-Admin using the editor to determine your site’s main content. Within them are all the fields which you might expect such as title, description, slug, metadata, authors, tags and so on.

Additionally, posts have **Code Injection** fields which mean you can register additional styles, scripts or other content to be injected just before `</head>` or `</body>` on any one particular URL where desired.

Here’s an example of a [post](https://demo.ghost.io/welcome/) in the default Ghost Theme:

<Frame>
  [  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fc2b2ae3-post_hue747db7f2f90c2b84166e8bb760c8a59_946454_3014x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ee4314291fb2fb291dbf10752f7202d5" data-og-width="3014" width="3014" data-og-height="2010" height="2010" data-path="images/fc2b2ae3-post_hue747db7f2f90c2b84166e8bb760c8a59_946454_3014x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fc2b2ae3-post_hue747db7f2f90c2b84166e8bb760c8a59_946454_3014x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=cf0cb4d22ded5be515c4e3ef086641e7 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fc2b2ae3-post_hue747db7f2f90c2b84166e8bb760c8a59_946454_3014x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=76da54256c8ce88a0570e0285a16aa60 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fc2b2ae3-post_hue747db7f2f90c2b84166e8bb760c8a59_946454_3014x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=7a6acfd1820b482e4205fa542062ac93 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fc2b2ae3-post_hue747db7f2f90c2b84166e8bb760c8a59_946454_3014x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=8933fcabec320849d598b23ea5688376 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fc2b2ae3-post_hue747db7f2f90c2b84166e8bb760c8a59_946454_3014x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=afa0033fc15953bbbbc33423c0de3f7c 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fc2b2ae3-post_hue747db7f2f90c2b84166e8bb760c8a59_946454_3014x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=cca6f6e703a0176ade4a52644b9bb2aa 2500w" />](https://demo.ghost.io/welcome/)
</Frame>

## Creating content

Creating content in Ghost is done via the Ghost editor which, for many people, is what attracted to them in the first place. More than just a glossy experience though, Ghost’s editor provides a streamlined workflow for both authors and developers.

### Writing experience

The writing experience in Ghost will be very familiar to most people who have spent time with web based authoring tools. It generally takes after the Medium-like experience which writers want.

Writing simple content is a breeze - but there are tons of powerful shortcuts, too. You can write plaintext, activating formatting options using either the mouse or keyboard shortcuts. But you can also write in Markdown, if you prefer, and the editor will convert it as you type - rendering an instant preview.

<Frame>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/formatting-toolbar.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9aacca235d61dc023a3751e38dd1e190" data-og-width="1400" width="1400" data-og-height="593" height="593" data-path="images/formatting-toolbar.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/formatting-toolbar.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=dce1e5e23d285966ae87aad5d114e017 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/formatting-toolbar.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=24e5b517bc07de35103188bf911aec53 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/formatting-toolbar.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=4d938b2aefc2e01d36433db38179925a 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/formatting-toolbar.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=168dbf11c947e460e23fa92992e9e1d6 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/formatting-toolbar.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1e215a510e4f7544864fcbbe8fb04cda 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/formatting-toolbar.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9fd6ce6681496760280216cdfbe0e703 2500w" />
</Frame>

Additionally, the editor contains intelligent logic around pasting. You can copy and paste from *most* sources and it will be correctly transformed into readable content without needing any special treatment. (Go ahead, try copying the content of this page straight into the editor!) — You can also do things like pasting a URL over the top of any highlighted text to create a link.

### Dynamic cards

Having a clean writing experience is good, but nowadays great publishing means so much more than just text. Modern content contains audio, video, charts, data and interactive elements to provide an engaging experience.

Ghost content comes with extensible, rich media objects called Cards. The easiest way to think of them is like having Slack integrations in your content.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/card-context-menu.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=612d90e9680515a12e7428d92c5487cc" data-og-width="1400" width="1400" data-og-height="1485" height="1485" data-path="images/card-context-menu.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/card-context-menu.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e97f5ca5f55fa510c1f26df66cefe7f0 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/card-context-menu.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=ddae880cfddd91b3199c28e7520da623 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/card-context-menu.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=8aab1a36cc2115baab1a6f5809c76b68 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/card-context-menu.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=0068e324f91be327a67289f7aab21763 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/card-context-menu.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=170fe509bbbb125dc730bbc93fde2726 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/card-context-menu.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f5b79a62a93274e78c6f3e1a26c16c62 2500w" />
</Frame>

**For example:** Either by pressing the `+` button or typing `/` - you can trigger an Unsplash integration to find and insert a royalty-free photo for your post.

*Currently there are only a few simple cards available, but greater support for cards (as well as support for custom cards) is in active development.*

### Document storage

The Ghost editor gets a lot of praise from writers for being a pleasure to use, but developers will find that the standardised JSON-based document storage format under the hood creates an equally great experience when it comes to working with the data.

All post content in Ghost is stored in [Lexical](https://lexical.dev) and then rendered into its final form depending on the delivery destination.

Lexical is extremely portable and can be transformed into multiple formats. This is particularly powerful because it’s just as easy to parse your content into HTML to render on the web as it is to pull the same content into a mobile app using completely different syntax.

### API data

Here’s a sample post object from the Ghost [Content API](/content-api/)

```json  theme={"dark"}
{
  "posts": [
    {
      "slug": "welcome-short",
      "id": "5ddc9141c35e7700383b2937",
      "uuid": "a5aa9bd8-ea31-415c-b452-3040dae1e730",
      "title": "Welcome",
      "html": "<p>👋 Welcome, it's great to have you here.</p>",
      "comment_id": "5ddc9141c35e7700383b2937",
      "feature_image": "https://static.ghost.org/v3.0.0/images/welcome-to-ghost.png",
      "feature_image_alt": null,
      "feature_image_caption": null,
      "featured": false,
      "visibility": "public",
      "created_at": "2019-11-26T02:43:13.000+00:00",
      "updated_at": "2019-11-26T02:44:17.000+00:00",
      "published_at": "2019-11-26T02:44:17.000+00:00",
      "custom_excerpt": null,
      "codeinjection_head": null,
      "codeinjection_foot": null,
      "custom_template": null,
      "canonical_url": null,
      "url": "https://docs.ghost.io/welcome-short/",
      "excerpt": "👋 Welcome, it's great to have you here.",
      "reading_time": 0,
      "access": true,
      "og_image": null,
      "og_title": null,
      "og_description": null,
      "twitter_image": null,
      "twitter_title": null,
      "twitter_description": null,
      "meta_title": null,
      "meta_description": null,
      "email_subject": null
    }
  ]
}
```

## Pages

Pages are a subset of posts which are excluded from all feeds.

While posts are used for grouped content which is generally published regularly like blog posts or podcast episodes, pages serve as a separate entity for static and generally independent content like an `About` or `Contact` page.

### What’s different about pages?

Pages are only ever published on the slug which is given to them, and do not automatically appear anywhere on your site. While posts are displayed in the index collection, within RSS feeds, and in author and tag archives - pages are totally independent. The only way people find them is if you create manual links to them either in your content or your navigation.

Here’s an example of a [page](https://demo.ghost.io/about/) in the default Ghost Theme:

<Frame>
  [  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7431aaee-page_hue747db7f2f90c2b84166e8bb760c8a59_805758_3014x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=c070ac5be5e7f25e198f1eb0b5b5a649" data-og-width="3014" width="3014" data-og-height="2010" height="2010" data-path="images/7431aaee-page_hue747db7f2f90c2b84166e8bb760c8a59_805758_3014x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7431aaee-page_hue747db7f2f90c2b84166e8bb760c8a59_805758_3014x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=f39e689e78a33acbbe0a925b9452f2b2 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7431aaee-page_hue747db7f2f90c2b84166e8bb760c8a59_805758_3014x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a856b36d8e386de494a6c2e622616e75 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7431aaee-page_hue747db7f2f90c2b84166e8bb760c8a59_805758_3014x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=012663b7e946f0fbd5b665464e08372d 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7431aaee-page_hue747db7f2f90c2b84166e8bb760c8a59_805758_3014x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=995abf64d15b81f462aa21406978c83f 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7431aaee-page_hue747db7f2f90c2b84166e8bb760c8a59_805758_3014x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=71757bc8a2a953d9d81dd67af20d5789 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/7431aaee-page_hue747db7f2f90c2b84166e8bb760c8a59_805758_3014x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=ecdc526624dd98cde38363af81cadb99 2500w" />](https://demo.ghost.io/about/)
</Frame>

## Custom templates

If using one of Ghost’s default [Handlebars Themes](/themes/), a common usecase for pages is to give them custom templates.

As well as a regular `page.hbs` default template, you can also create generic reusable custom templates like `page-wide.hbs` - or page-specific templates based on a particular slug, like `page-about.hbs` - so that you have fine-grained control over what markup is used to render your data.

Not much else to say about pages, let’s move right along.

## Tags

Tags are the primary taxonomy within Ghost for filtering and organising the relationships between your content.

Right off the bat, probably the best way to think about tags in Ghost is like labels in GMail. Tags are a powerful, dynamic taxonomy which can be used to categorise content, control design, and drive automation within your site.

Tags are much more than just simple keywords - there are several different ways of using them to accomplish a variety of use-cases.

### Regular tag

All tags come with their own data object and can have a title, description, image and meta data. Ghost Handlebars Themes will automatically generate tag archive pages for any tags which are assigned to active posts. For example all posts tagged with `News` will appear on `example.com/tag/news/`, as well as in the automatically generated XML sitemap.

### Primary tag

Ghost has a concept of `primary_tag`, used simply to refer to the very first tag which a post has. This is useful for when you want to return a singular, most-important tag rather than a full array of all tags assigned to a post.

### Internal tag

Tags which are prefixed by a `#` character, otherwise known as hashtags, are internal tags within Ghost - which is to say that they aren’t rendered publicly. This can be particularly useful when you want to drive particular functionality based on a tag, but you don’t necessarily want to output the tag for readers to see.

### Example usage

As a quick example of how you might use tags, let’s look at a quick example of a Hollywood news site which is publishing a post about Ryan Reynolds being announced as the lead in a new movie called “Son of Deadpool”.

<Frame>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/tag-list-example.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=c01608066a69700c07ed34f9a427bc27" data-og-width="1400" width="1400" data-og-height="513" height="513" data-path="images/tag-list-example.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/tag-list-example.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=e3a6c08c49a91a860f6c38bfa6aa5652 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/tag-list-example.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=c21e116a82f594162462d6991ab42c24 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/tag-list-example.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ab96f224fa5cb73099587e9b787d16d4 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/tag-list-example.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=dc37d0e85fd5e339f46329b130e6d51e 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/tag-list-example.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=cebc29337f29e465870f7a35fae15d78 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/tag-list-example.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=1e247d88cba6b08c4009d14f106b2a57 2500w" />
</Frame>

Here the post has 4 tags:

* `Breaking news` - The **primary tag**
* `Ryan Reynolds` - A regular tag
* `New Releases` - A regular tag
* `#feature` - An internal tag

The front-end of the site has configured a rotating banner on the homepage to pull the latest 3 posts from the `Breaking News` category and highlight them right at the top of the page with a **Breaking News** label beside the byline.

The `Ryan Reynolds` and `New Releases` tags generate archives so that readers can browse other stories in the same categories, as well as their own sitemaps.

The `#feature` tag is used by the front-end or theme-layer as a conditional flag for activating specific formatting. In this instance the Deadpool PR team have supplied some marketing material including a giant wallpaper image which would make a great background, so the post is tagged with `#feature` to push the post image to be full bleed and take over the whole page.

You can see this use-case in action on the main Ghost blog. Here’s [a regular post](https://ghost.org/changelog/image-galleries/), and here’s a [#feature](https://ghost.org/changelog/5/). The design of the post reacts to the tags.

## Tag archives

All actively used public tags (so, those not prefixed with `#`) generate automatic tag archives within Ghost Handlebars Themes. Tag archives are automatically added to the Google XML Sitemap, and have their own pagination and RSS feeds.

Here’s an example of an [tag archive](https://demo.ghost.io/tag/getting-started/) in the default Ghost Theme:

<Frame>
  [  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c109c4c-tag-archive_hue747db7f2f90c2b84166e8bb760c8a59_994594_3014x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=2f5ec93b675ec3c4c76517729ccdc96e" data-og-width="3014" width="3014" data-og-height="2010" height="2010" data-path="images/1c109c4c-tag-archive_hue747db7f2f90c2b84166e8bb760c8a59_994594_3014x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c109c4c-tag-archive_hue747db7f2f90c2b84166e8bb760c8a59_994594_3014x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=6c66f38c0913f5a2d756a41d6bee3dab 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c109c4c-tag-archive_hue747db7f2f90c2b84166e8bb760c8a59_994594_3014x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=189d44ef0bf0e72d01b3a356979f2e35 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c109c4c-tag-archive_hue747db7f2f90c2b84166e8bb760c8a59_994594_3014x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=5dde03b54b2281ae2770797d5e0b6c24 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c109c4c-tag-archive_hue747db7f2f90c2b84166e8bb760c8a59_994594_3014x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=2512b067cb6ea00e2af6a0a23a1724bf 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c109c4c-tag-archive_hue747db7f2f90c2b84166e8bb760c8a59_994594_3014x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=6a7d78bf0b55594c0fae32d78496fe1e 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/1c109c4c-tag-archive_hue747db7f2f90c2b84166e8bb760c8a59_994594_3014x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=be48d523e6e5604594f9976285a12a1e 2500w" />](https://demo.ghost.io/tag/getting-started/)
</Frame>

Tag archives are only generated for tags which are assigned to published posts, any other tags are not publicly visible.

### API data

Here’s a sample tag object from the Ghost [Content API](/content-api/):

```json  theme={"dark"}
{
  "tags": [
    {
      "slug": "getting-started",
      "id": "5ddc9063c35e7700383b27e0",
      "name": "Getting Started",
      "description": null,
      "feature_image": null,
      "visibility": "public",
      "meta_title": null,
      "meta_description": null,
      "og_image": null,
      "og_title": null,
      "og_description": null,
      "twitter_image": null,
      "twitter_title": null,
      "twitter_description": null,
      "codeinjection_head": null,
      "codeinjection_foot": null,
      "canonical_url": null,
      "accent_color": null,
      "url": "https://docs.ghost.io/tag/getting-started/"
    }
  ]
}
```


# Recommendations
Source: https://docs.ghost.org/recommendations



## Overview

With recommendations, publishers can share their favorite sites with their readers and, likewise, be recommended by other publications. See [the Changelog](https://ghost.org/changelog/recommendations/) for an overview of this feature.

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c216b0cf-recommendations_hu87dd64b769c4fd4ef600cc9c9bc971ce_570214_2000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cfcea0ef2cbd9cd0acbcd8aff5a71fb9" data-og-width="2000" width="2000" data-og-height="1266" height="1266" data-path="images/c216b0cf-recommendations_hu87dd64b769c4fd4ef600cc9c9bc971ce_570214_2000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c216b0cf-recommendations_hu87dd64b769c4fd4ef600cc9c9bc971ce_570214_2000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=83726970e09443172d21956defba3e1c 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c216b0cf-recommendations_hu87dd64b769c4fd4ef600cc9c9bc971ce_570214_2000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=d27ee377f9c42ffb7997361360bdbf73 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c216b0cf-recommendations_hu87dd64b769c4fd4ef600cc9c9bc971ce_570214_2000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cb0e0c32b61ab21796c0b3fbae0aa38a 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c216b0cf-recommendations_hu87dd64b769c4fd4ef600cc9c9bc971ce_570214_2000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=97559c281f752b87191e1485cc59805a 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c216b0cf-recommendations_hu87dd64b769c4fd4ef600cc9c9bc971ce_570214_2000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=1149f31c7d7d6cf42a2f610ab2bd9aea 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/c216b0cf-recommendations_hu87dd64b769c4fd4ef600cc9c9bc971ce_570214_2000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=f4e3f75dc7b0aa547b42dcc6dec138cf 2500w" />
</Frame>

Under the hood, Ghost’s recommendations feature is built on the [Webmention open standard](https://www.w3.org/TR/webmention/), which means recommendations aren’t limited to any single platform — but extend to every site on the web!

Recommendations also make it possible for readers to subscribe to recommended publications with a single click. While this feature is currently exclusive to Ghost sites, we are eager to help other platforms in implementing this 1-click functionality. Contact us if you’re interested in building 1-click subscriptions for the open web!

The sections below provide a high-level technical summary of how recommendations work.

## See your site’s recommendations

* The recommendations modal is shown automatically whenever a new member subscribes to a Ghost publication.
* Visiting `https://yoursite.com/#/portal/recommendations` will open the recommendations modal. Use this URL as a link in the navigation menu to create a recommendation button.
* See additional methods for opening the recommendations modal in our [theme docs](/themes/helpers/data/recommendations/).

## How Ghost sends a recommendation

When you make a recommendation, it shows on your website and in Portal at `yoursite.com/#/portal/recommendations`. Behind the scenes, Ghost performs the following steps:

1. Ghost checks to see if the recommended site has Webmentions enabled. While it’s possible to recommend any site, Ghost only notifies sites about your recommendation if they have a Webmention endpoint that can receive it.

2. Ghost adds the recommendation to your site’s `/.well-known/recommendations.json` file. Here’s an example of this file:

```json  theme={"dark"}
[
  {
    "url": "https://shesabeast.co/",
    "updated_at": "2023-09-22T14:09:32.000Z",
    "created_at": "2023-09-22T14:09:32.000Z"
  },
  {
    "url": "https://makerstations.io/",
    "updated_at": "2023-09-22T14:12:40.000Z",
    "created_at": "2023-09-22T14:12:34.000Z"
  }
]
```

3. Ghost notifies the recommended site via a Webmention. This takes the form of a POST request to the endpoint discovered in step 1 and contains a reference to your site’s `recommendations.json` file. Here’s an example of a request:

```http  theme={"dark"}
POST /webmentions/receive/ HTTP/1.1
Host: recommendedsite.com
Content-Type: application/x-www-form-urlencoded

source=https://mysite.com/.well-known/recommendations.json&
target=https://recommendedsite.com/


HTTP/1.1 202 Accepted
```

## How Ghost receives a recommendation

Your site receives recommendations in the same way as described above but as the recipient.

1. Ghost automatically adds a `link` tag to your publication to inform other sites about your Webmention endpoint. That tag looks like this:

```html  theme={"dark"}
<link href="https://myghostsite.com/webmentions/receive/" rel="webmention">
```

2. Ghost listens for Webmentions on this endpoint. Once the incoming recommendation is verified, it’s added to Ghost Admin and you receive a notification.

## Updates and removals

If you update or remove a recommended site, Ghost sends an updated Webmention about the change. Likewise, your site will be automatically updated whenever it receives an incoming recommendation change.

## Theme support

Theme developers can extend the recommendation feature by using the [`recommendations`](/themes/helpers/data/recommendations/) and [`readable_url`](/themes/helpers/data/readable_url/) helpers. See the documentation for these features to learn more.


# Ghost Security
Source: https://docs.ghost.org/security

Ghost is committed to developing secure, reliable products utilising all modern security best practices and processes.

***

The Ghost team is made up of full time staff employed by the Ghost Foundation as well as volunteer open source contributors and security experts. We do both consultation and penetration testing of our software and infrastructure with external security researchers and agencies.

We take security seriously at Ghost and welcome any peer review of our [open source codebase](https://github.com/tryghost/ghost) to help ensure that it remains secure.

## Security features

#### Device verification

All staff user login sessions from a new or unrecognized device must be verified with a code sent to the user’s registered email address.

#### Email 2FA

Ghost can be configured to send two-factor authentication codes by email on all staff user logins.

#### Brute force protection

User login attempts and password reset requests are all limited to 5 per hour per IP address.

#### Automatic SSL

Ghost’s CLI tool automatically configures SSL certificates for all new Ghost installs with Let’s Encrypt by default.

#### Password hashing

Ghost follows [OWASP authentication standards](https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication) with all passwords hashed and salted properly using `bcrypt` to ensure password integrity.

#### Encoded tokens everywhere

All user invitation and password reset tokens are base64 encoded with serverside secret. All tokens are always single use and always expire.

#### SQLi prevention

Ghost uses [Bookshelf](https://bookshelfjs.org/) ORM + [Knex](https://knexjs.org) query builder and does not generate *any* of its own raw SQL queries. Ghost has no interpolation of variables directly to SQL strings.

#### Data validation and serialisation

Ghost performs strong serialisation and validation on all data that goes into the database, as well as automated symlink protection on all uploaded files.

#### XSS prevention

Ghost uses safe/escaped strings used everywhere, including and especially in all custom Handlebars helpers used in [Ghost Themes](/themes/)

#### Standardised permissions

Ghost-CLI does not run as `root` and automatically configures all server directory permissions correctly according to [OWASP Standards](https://www.owasp.org/index.php/File_System).

#### Dependency management

All Ghost dependencies are continually scanned using a combination of automated GitHub tooling and `yarn audit` to ensure their integrity.

***

## Reporting vulnerabilities

Potential security vulnerabilities can be reported directly to us at `security@ghost.org`. The Ghost Security Team communicates privately and works in a secured, isolated repository for tracking, testing, and resolving security-related issues.

### Responsible disclosure

The Ghost Security team is committed to working with security researchers to verify, reproduce and respond to legitimate reported vulnerabilities.

* Provide details of the vulnerability, including information needed to reproduce and validate the vulnerability and a Proof of Concept
* Make a good faith effort to avoid privacy violations, destruction and modification of data on live sites
* Give reasonable time to correct the issue before making any information public

Security issues always take precedence over bug fixes and feature work. We can and do mark releases as “urgent” if they contain serious security fixes.

We will publicly acknowledge any report that results in a security commit to [https://github.com/TryGhost/Ghost](https://github.com/TryGhost/Ghost)

### Issue triage

We’re always interested in hearing about any reproducible vulnerability that affects the security of Ghost users, including…

* Remote Code Execution (RCE)
* SQL Injection (SQLi)
* Server Side Request Forgery (SSRF)
* Cross Site Request Forgery (CSRF)
* Cross Site Scripting (XSS) but please read on before reporting XSS…

**However, we’re generally *not* interested in…**

* [Privilege escalation](#privilege-escalation-attacks) as result of trusted users publishing arbitrary JavaScript[1](#privilege-escalation-attacks)
* HTTP sniffing or HTTP tampering exploits
* Open API endpoints serving public data
* Ghost version number disclosure
* Brute force, DoS, DDoS, phishing, text injection, or social engineering attacks.
* Output from automated scans
* Clickjacking with minimal security implications
* Missing DMARC records

**Privilege escalation attacks**

Ghost is a content management system and all users are considered to be privileged/trusted. A user can only obtain an account and start creating content after they have been invited by the site owner or similar administrator-level user.

A basic feature of Ghost as a CMS is to allow content creators to make use of scripts, SVGs, embedded content & other file uploads that are required for the content to display as intended. Because of this there will always be the possibility of “XSS” attacks, albeit only from users that have been trusted to build the site’s content.

Ghost’s admin application does a lot to ensure that unknown scripts are not run within the the admin application itself, however that only protects one side of a Ghost site. If the front-end (the rendered site that anonymous visitors see) shares the same domain as the admin application then browsers do not offer sufficient protections to prevent successful XSS attacks by trusted users.

If you are concerned that trusted users you invite to create your site will act maliciously the best advice is to split your front-end and admin area onto different domains (e.g. `https://mysite.com` and `https://admin.mysite.com/ghost/`). This way browsers offer greater built-in protection because credentials cannot be read across domains. Even in this case it should be understood that you are giving invited users completely free reign in content creation so absolute security guarantees do not exist.

Anyone concerned about the security of their Ghost install should read our [hardening guide](/hosting/#server-hardening).

We take any attack vector where an untrusted user is able to inject malicious content very seriously and welcome any and all reports.

### How reports are handled

If you report a vulnerability to us through the [security@ghost.org](mailto:security@ghost.org) mailing list, we will:

* Acknowledge your email within a week
* Investigate and let you know our findings within two weeks
* Ensure any critical issues are resolved within a month
* Ensure any low-priority issues are resolved within three months
* Credit any open source commits to you
* Let you know when we have released fixes for issues you report


# Staff Users
Source: https://docs.ghost.org/staff

Staff users within Ghost have access to the admin area with varying levels of permissions for what they can do.

***

## Roles & permissions

There are five different staff user roles within Ghost

* **Contributors:** Can log in and write posts, but cannot publish
* **Authors:** Can create and publish new posts and tags
* **Editors:** Can invite, manage and edit authors and contributors
* **Administrators:** Have full permissions to edit all data and settings
* **Owner:** An admin who cannot be deleted and has access to billing details

## Author archives

Like [tags](/publishing/#tags), staff users are another resource by which content can be organised and sorted. Multiple authors can be assigned to any given post to generate bylines. Equally, author archives can be generated on the front end based on which posts an author is assigned to.

Also like tags, within Ghost Handlebars Themes author archives are automatically added to the Google XML Sitemap, and have their own pagination + RSS feeds.

Here’s an example of an [author archive](https://demo.ghost.io/author/martin/) in the default Ghost Theme:

<Frame>
  [  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/17caf60b-author-archive_hu89f6f73972391497d77bac6acdaa5b97_69300_1220x0_resize_q100_h2_box.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=369797677f6c5ba486bda7236029f8de" data-og-width="1220" width="1220" data-og-height="777" height="777" data-path="images/17caf60b-author-archive_hu89f6f73972391497d77bac6acdaa5b97_69300_1220x0_resize_q100_h2_box.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/17caf60b-author-archive_hu89f6f73972391497d77bac6acdaa5b97_69300_1220x0_resize_q100_h2_box.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=855f8fdcf2342df4a2cfb233d2e3dc21 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/17caf60b-author-archive_hu89f6f73972391497d77bac6acdaa5b97_69300_1220x0_resize_q100_h2_box.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f04e2b7c0d001b26489108857aeaf56b 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/17caf60b-author-archive_hu89f6f73972391497d77bac6acdaa5b97_69300_1220x0_resize_q100_h2_box.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=e8c414b816c930e7de6fab322a3e6bda 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/17caf60b-author-archive_hu89f6f73972391497d77bac6acdaa5b97_69300_1220x0_resize_q100_h2_box.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=204e58b8202f6ee076c0e517c551ac0b 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/17caf60b-author-archive_hu89f6f73972391497d77bac6acdaa5b97_69300_1220x0_resize_q100_h2_box.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=b209cdf9d67170abe9611106b812d60c 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/17caf60b-author-archive_hu89f6f73972391497d77bac6acdaa5b97_69300_1220x0_resize_q100_h2_box.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=f4c431938a3e2f6fd426541afd271784 2500w" />](https://demo.ghost.io/author/martin/)
</Frame>

Public author archives are only generated for staff users who are assigned to published posts, any other staff users are not publicly visible.

## Security & trust

If running the front-end of your site and the Ghost admin client on the same domain, there are certain permissions escalation vectors which are unavoidable.

Ghost considers staff users to be “trusted” by default - so if you’re running in an environment where users are untrusted, you should ensure that Ghost-Admin and your site’s front-end run on separate domains.

## Sample API data

Here’s a sample author object from the Ghost [Content API](/content-api/)

```json  theme={"dark"}
{
  "authors": [
    {
      "slug": "cameron",
      "id": "5ddc9b9510d8970038255d02",
      "name": "Cameron Almeida",
      "profile_image": "https://docs.ghost.io/content/images/2019/03/1c2f492a-a5d0-4d2d-b350-cdcdebc7e413.jpg",
      "cover_image": null,
      "bio": "Editor at large.",
      "website": "https://example.com",
      "location": "Cape Town",
      "facebook": "example",
      "twitter": "@example",
      "meta_title": null,
      "meta_description": null,
      "url": "https://docs.ghost.io/author/cameron/"
    }
  ]
}
```


# Ghost Handlebars Themes
Source: https://docs.ghost.org/themes

The Ghost theme layer has been engineered to give developers and designers the flexibility to build custom publications that are powered by the Ghost platform.

***

## Theme development

Ghost themes use the Handlebars templating language which creates a strong separation between templates (the HTML) and any JavaScript logic with the use of helpers. This allows themes to be super fast, with a dynamic client side app, and server side publication content that is sent to the browser as static HTML.

Ghost also makes use of an additional library called `express-hbs` which adds some additional features to Handlebars, such as layouts and partials.

If you’ve previously built themes for other popular platforms, working with the Ghost theme layer is extremely accessible. This documentation gives you the tools required to create static HTML and CSS for a theme, using Handlebars expressions when you need to render dynamic data.

Our tutorial on the [essential concepts to known when building a Ghost theme](https://ghost.org/tutorials/essential-concepts/), provides a fantastic introduction to everything you need to know to start building beautiful themes.

## Handlebars

The Handlebars templating language provides the power to build semantic templates effectively.

* [Handlebars documentation](https://handlebarsjs.com/guide/expressions.html)

Installation of Handlebars is already done for you in Ghost ✨

## Custom settings

Offering customization options to theme users can be done using custom settings. This allows theme developers to empower non-developers to make controlled changes.

Head to the [Custom settings documentation](/themes/custom-settings/) to learn more.

## GScan

Validating your Ghost theme is handled efficiently with the [GScan tool](https://gscan.ghost.org/). GScan will check your theme for errors, deprecations and compatibility issues.

* The [GScan site](https://gscan.ghost.org/) is your first port of call to test any themes that you’re building to get a full validation report

* When a theme is uploaded in Ghost admin, it will automatically be checked with `gscan` and any fatal errors will prevent the theme from being used

* `gscan` is also used as a command line tool

### Command line

To use GScan as a command line tool, globally install the `gscan` npm package:

```bash  theme={"dark"}
# Install the npm package
npm install -g gscan

# Use gscan <file path> anywhere to run gscan against a folder
gscan /path/to/ghost/content/themes/casper

# Run gscan on a zip file
gscan -z /path/to/download/theme.zip
```

## What’s next?

That’s all of the background context required to get started. From here, take a look at the [structure](/themes/structure/) of Ghost themes and templates, and learn everything you need to know about the `package.json` file.

For community led support about theme development, visit [the forum](https://forum.ghost.org/c/themes/).


# Assets
Source: https://docs.ghost.org/themes/assets

Ghost themes support automatic image resizing, allowing you to use a minimal handlebars helper to output different image sizes.

***

Ghost automatically compresses and resizes images added to your post content and generates automatic responsive assets for maximum performance.

For all other images, such as feature images and theme images, the responsive images feature builds responsive image srcsets into your theme, and displays scaled down images when required to improve your site’s overall performance.

## Responsive images configuration

Responsive images can be defined in the `package.json` file. Ghost automatically generates copies of images at the specified sizes, and works like a cache, so the image sizes can be changed at any time. It’s recommended to have no more than 10 image sizes so media storage doesn’t grow out of control.

Here’s a sample of [the image sizes in Ghost’s default Casper theme](https://github.com/TryGhost/Casper/blob/main/package.json).

```json  theme={"dark"}
// package.json

"config": {
    "image_sizes": {
        "xxs": {
            "width": 30
        },
        "xs": {
            "width": 100
        },
        "s": {
            "width": 300
        },
        "m": {
            "width": 600
        },
        "l": {
            "width": 1000
        },
        "xl": {
            "width": 2000
        }
    }
}
```

### Using image sizes

Once image sizes are defined, pass a `size` parameter to the [\{\{img\_url}}](/themes/helpers/data/img_url/) helper in your theme to output an image at a particular size.

```handlebars  theme={"dark"}
<img src="{{img_url feature_image size="s"}}">
```

To build [full responsive images](https://medium.freecodecamp.org/a-guide-to-responsive-images-with-ready-to-use-templates-c400bd65c433) create html srcsets passing in multiple image sizes, and let the browser do the rest.

Here’s an [example from Ghost default Casper theme](https://github.com/TryGhost/Casper/blob/main/partials/post-card.hbs) implementation:

```handlebars  theme={"dark"}
<!-- index.hbs -->

<img class="post-image"
    srcset="{{img_url feature_image size="s"}} 300w,
            {{img_url feature_image size="m"}} 600w,
            {{img_url feature_image size="l"}} 1000w,
            {{img_url feature_image size="xl"}} 2000w"
    sizes="(max-width: 1000px) 400px, 700px"
    src="{{img_url feature_image size="m"}}"
    alt="{{#if feature_image_alt}}{{feature_image_alt}}{{else}}{{title}}{{/if}}"
/>
```

### Converting images to smaller image types

Pass a `format` parameter to the [\{\{img\_url}}](/themes/helpers/data/img_url/) helper in your theme to output an image in a particular image format. This only works in combination with the `size` parameter.

```handlebars  theme={"dark"}
{{img_url feature_image size="s" format="webp"}}
```

By converting an image from PNG, GIF, or JPEG to WebP, you can reduce its size by \~25% without any visible loss of quality. An even better image compression can be obtained with the AVIF format, but this [isn’t supported in all browsers](https://caniuse.com/avif) (and doesn’t support animation yet).

*Note that while image conversion changes the file type, the file extension stays the same. For example, an AVIF image will retain the `.jpg` extension.*

WebP is supported by all modern browsers, but we recommend to always add a fallback to the original file type to achieve wider browser support. Use a `<picture>` tag for this, which allows the browser to choose the first format it supports:

```handlebars  theme={"dark"}
<picture>
    <!-- Serve the AVIF format if the browser supports it -->
    <!-- Remove this block when using animated images as feature images -->
    <source 
        srcset="{{img_url feature_image size="s" format="avif"}} 300w,
                {{img_url feature_image size="m" format="avif"}} 600w,
                {{img_url feature_image size="l" format="avif"}} 1000w,
                {{img_url feature_image size="xl" format="avif"}} 2000w"
        sizes="(min-width: 1400px) 1400px, 92vw" 
        type="image/avif"
    >
    <!-- Serve the WebP format if the browser supports it -->
    <source 
        srcset="{{img_url feature_image size="s" format="webp"}} 300w,
                {{img_url feature_image size="m" format="webp"}} 600w,
                {{img_url feature_image size="l" format="webp"}} 1000w,
                {{img_url feature_image size="xl" format="webp"}} 2000w"
        sizes="(min-width: 1400px) 1400px, 92vw" 
        type="image/webp"
    >
    <!-- Serve original file format as a fallback -->
    <img
        srcset="{{img_url feature_image size="s"}} 300w,
                {{img_url feature_image size="m"}} 600w,
                {{img_url feature_image size="l"}} 1000w,
                {{img_url feature_image size="xl"}} 2000w"
        sizes="(min-width: 1400px) 1400px, 92vw"
        src="{{img_url feature_image size="xl"}}"
        alt="{{#if feature_image_alt}}{{feature_image_alt}}{{else}}{{title}}{{/if}}"
    >
</picture>
```

## Compatibility

Unlike other platforms, there’s no manual work needed to manage image sizes in your theme, it’s all done in the background for you.

Image sizes are automatically generated for all feature images and theme images, and regenerated whenever an image is changed, the image sizes configuration is changed, or when theme changes are made. Images are generated on the first request for each image at a particular size.

Dynamic image sizes are *not* compatible with externally hosted images (except inserted images from [Unsplash](https://ghost.org/integrations/unsplash/)). If you store your image files on a third party storage adapter, then the image URL returned will be determined by the external source.


# Content
Source: https://docs.ghost.org/themes/content

The open-source Ghost editor is robust and extensible.

***

More than just a formatting toolbar, the rich editing experience within Ghost allows authors to pull in dynamic blocks of content like photos, videos, tweets, embeds, code and markdown.

For author-specified options to work, themes need to support the HTML markup and CSS classes that are output by the `{{content}}` helper. Use the following examples to ensure your theme is compatible with the latest version of the Ghost editor.

## `<figure>` and `<figcaption>`

Images and embeds will be output using the semantic `<figure>` and `<figcaption>` elements. For example:

```html  theme={"dark"}
{{/*  Output  */}}
<figure class="kg-image-card">
    <img class="kg-image" src="https://casper.ghost.org/v1.25.0/images/koenig-demo-1.jpg" width="1600" height="2400" loading="lazy" srcset="..." sizes="...">
    <figcaption>An example image</figcaption>
</figure>
```

The following CSS classes are used:

* `.kg-image-card` is used on the `<figure>` element for all image cards
* `.kg-image` is used on the `<img>` element for all image cards
* `.kg-embed-card` is used on the `<figure>` element on all embed cards

This is only relevant when authors use the built-in image and embed cards, and themes must also support images and embeds that are not wrapped in `<figure>` elements to maintain compatibility with the Markdown and HTML cards.

## Image size options

The editor allows three size options for images: normal, wide and full width. These size options are achieved by adding `kg-width-wide` and `kg-width-full` classes to the `<figure>` elements in the HTML output. Here’s an example for wide images:

```html  theme={"dark"}
{{/*  Output  */}}
<figure class="kg-image-card kg-width-wide">
    <img class="kg-image" src="https://casper.ghost.org/v1.25.0/images/koenig-demo-1.jpg" width="1600" height="2400" loading="lazy" srcset="..." sizes="...">
</figure>
```

Normal width image cards do not have any extra CSS classes.

Image cards have `width` and `height` attributes when that data is available. Width and height correspond to the size and aspect ratio of the source image and do not change when selecting different size options in the editor. *If your theme has a `max-width` style set for images it’s important to also have `height: auto` to avoid images appearing stretched or squashed.*

The specific implementation required for making images wider than their container width will depend on your theme’s existing styles. The default Ghost theme Casper uses flexbox to implement layout using the following HTML and CSS:

```html  theme={"dark"}
<!-- Output -->

<div class="content">
  <article>
    <h1>Image size implementation</h1>

    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce at interdum ipsum.</p>


    <figure class="kg-image-card kg-width-full">
      <img class="kg-image" src="https://casper.ghost.org/v1.25.0/images/koenig-demo-2.jpg" width="1600" height="2400" loading="lazy" srcset="..." sizes="...">
      <figcaption>A full-width image</figcaption>
    </figure>

    <p>Fusce interdum velit tristique, scelerisque libero et, venenatis nisi. Maecenas euismod luctus neque nec finibus.</p>

    <figure class="kg-image-card kg-width-wide">
      <img class="kg-image" src="https://casper.ghost.org/v1.25.0/images/koenig-demo-1.jpg" width="1600" height="2400" loading="lazy" srcset="..." sizes="...">
      <figcaption>A wide image</figcaption>
    </figure>

    <p>Suspendisse sed lacus efficitur, euismod nisi a, sollicitudin orci.</p>
  </article>
</div>

<footer>An example post</footer>
```

And the CSS:

```css  theme={"dark"}
/* style.css */

.content {
  width: 70%;
  margin: 0 auto;
 }

article {
  display: flex;
  flex-direction: column;
  align-items: center;
}

article img {
  display: block;
  max-width: 100%;
  height: auto;
}

.kg-width-wide img {
  max-width: 85vw;
}

.kg-width-full img {
  max-width: 100vw;
}

article figure {
  margin: 0;
}

article figcaption {
  text-align: center;
}

body {
  margin: 0;
}

header, footer {
  padding: 15px 25px;
  background-color: #000;
  color: #fff;
}

h1 {
  width: 100%;
}
```

### Negative margin and transforms example

Traditional CSS layout doesn’t support many elegant methods for breaking elements out of their container. The following example uses negative margins and transforms to achieve breakout. Themes that are based on Casper use similar techniques.

```css  theme={"dark"}
/* style.css */

.content {
  width: 70%;
  margin: 0 auto;
 }

article img {
  display: block;
  max-width: 100%;
  height: auto;
}

.kg-width-wide {
  position: relative;
  width: 85vw;
  min-width: 100%;
  margin: auto calc(50% - 50vw);
  transform: translateX(calc(50vw - 50%));
}

.kg-width-full {
  position: relative;
  width: 100vw;
  left: 50%;
  right: 50%;
  margin-left: -50vw;
  margin-right: -50vw;
}

article figure {
  margin: 0;
}

article figcaption {
  text-align: center;
}

body {
  margin: 0;
}

header, footer {
  padding: 15px 25px;
  background-color: #000;
  color: #fff;
}
```

### Responsive image sizes

Where possible images will have `srcset` and `sizes` attributes to allow for smaller images to be served to devices with smaller screens. Full output will look similar to this:

```html  theme={"dark"}
{{/*  Output  */}}
<figure class="kg-card kg-image-card">
    <img src="https://myghostsite.com/content/images/2021/03/coastline.jpg"
        class="kg-image"
        alt="A rugged coastline with small groups of people walking around rock pools"
        loading="lazy"
        width="2000"
        height="3000"
        srcset="https://myghostsite.com/content/images/size/w600/2021/03/coastline.jpg 600w,
                https://myghostsite.com/content/images/size/w1000/2021/03/coastline.jpg 1000w,
                https://myghostsite.com/content/images/size/w1600/2021/03/coastline.jpg 1600w,
                https://myghostsite.com/content/images/size/w2400/2021/03/coastline.jpg 2400w"
        sizes="(min-width: 720px) 720px">
</figure>
```

## Editor cards

Each of the content cards available in the editor require CSS and Javascript to display and function correctly. These default CSS and Javascript assets are provided automatically by Ghost, and output as `cards.min.css` and `cards.min.js` in the `{{ghost_head}}` helper.

You can override the default styles and behaviour for individual cards by configuring your theme’s `package.json` to exclude the assets for specific cards:

```json  theme={"dark"}
"card_assets": {
    "exclude": ["bookmark", "gallery"]
}
```

Alternatively you can disable all cards, by setting `card_assets` to false (the default is true).

```json  theme={"dark"}
"card_assets": false
```

The available cards are `audio`, `blockquote`, `bookmark`, `button`, `callout`, `file`, `gallery`, `header`, `nft`, `product`, `toggle`, `video`, and `signup`.

You can customize the styles of individual cards by using custom CSS. Each card has a unique class name that you can target to apply your own styles. Here’s a list of the class names for each card type:

* Audio: `.kg-audio-card`
* Blockquote: `blockquote` or `.kg-blockquote-alt`
* Bookmark: `.kg-bookmark-card`
* Button: `.kg-button-card`
* Callout: `.kg-callout-card`
* File: `.kg-file-card`
* Gallery: `.kg-gallery-card`
* Header: `.kg-header-card`
* NFT: `.kg-nft-card`
* Product: `.kg-product-card`
* Toggle: `.kg-toggle-card`
* Video: `.kg-video-card`
* Signup: `.kg-signup-card`

```css  theme={"dark"}
.kg-product-card .kg-product-card-container {
    background-color: #f0f0f0;
}
```

### Gallery card

The image gallery card requires some CSS and JS in your theme to function correctly. Themes will be validated to ensure they have styles for the gallery markup:

* `.kg-gallery-container`
* `.kg-gallery-row`
* `.kg-gallery-image`

Example gallery HTML:

```html  theme={"dark"}
{{/*  Output  */}}
<figure class="kg-card kg-gallery-card kg-width-wide">
    <div class="kg-gallery-container">
        <div class="kg-gallery-row">
            <div class="kg-gallery-image">
                <img src="/content/images/1.jpg" width="6720" height="4480" loading="lazy" srcset="..." sizes="...">
            </div>
            <div class="kg-gallery-image">
                <img src="/content/images/2.jpg" width="4946" height="3220" loading="lazy" srcset="..." sizes="...">
            </div>
            <div class="kg-gallery-image">
                <img src="/content/images/3.jpg" width="5560" height="3492" loading="lazy" srcset="..." sizes="...">
            </div>
        </div>
        <div class="kg-gallery-row">
            <div class="kg-gallery-image">
                <img src="/content/images/4.jpg" width="3654" height="5473" loading="lazy" srcset="..." sizes="...">
            </div>
            <div class="kg-gallery-image">
                <img src="/content/images/5.jpg" width="4160" height="6240" loading="lazy" srcset="..." sizes="...">
            </div>
            <div class="kg-gallery-image">
                <img src="/content/images/6.jpg" width="2645" height="3967" loading="lazy" srcset="..." sizes="...">
            </div>
        </div>
        <div class="kg-gallery-row">
            <div class="kg-gallery-image">
                <img src="/content/images/7.jpg" width="3840" height="5760" loading="lazy" srcset="..." sizes="...">
            </div>
            <div class="kg-gallery-image">
                <img src="/content/images/8.jpg" width="3456" height="5184" loading="lazy" srcset="..." sizes="...">
            </div>
        </div>
    </div>
</figure>
```

For a better view of how to support the gallery card in your theme, use the default implementation of the [CSS](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/gallery.css) and [Javascript](https://github.com/TryGhost/Ghost/blob/3d989eba2371235d41468f7699a08e46fc2b1e87/ghost/core/core/frontend/src/cards/js/gallery.js) assets provided by Ghost, which is a generic solution that works for most themes.

### Bookmark card

Here’s an example of the HTML structure that’s created by the editor:

```html  theme={"dark"}
{{/*  Output  */}}
<figure class="kg-card kg-bookmark-card">
    <a href="/" class="kg-bookmark-container">
        <div class="kg-bookmark-content">
            <div class="kg-bookmark-title">The bookmark card</div>
            <div class="kg-bookmark-description">Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce at interdum ipsum.</div>
            <div class="kg-bookmark-metadata">
                <img src="/content/images/author-icon.jpg" class="kg-bookmark-icon">
                <span class="kg-bookmark-author">David Darnes</span>
                <span class="kg-bookmark-publisher">Ghost</span>
            </div>
        </div>
        <div class="kg-bookmark-thumbnail">
            <img src="/content/images/article-image.jpg">
        </div>
    </a>
</figure>
```

The default CSS for the bookmark card [provided by Ghost](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/bookmark.css) should be used as a reference for custom implementations.

### Embed card

If a video is used with the theme then some CSS will be needed in order to maintain a good aspect ratio.

Example HTML:

```html  theme={"dark"}
<figure class="kg-card kg-embed-card">
    <iframe ...></iframe> <!-- <iframe> represents card content -->
</figure>
```

The CSS:

```css  theme={"dark"}
.fluid-width-video-wrapper {
    position: relative;
    overflow: hidden;
    padding-top: 56.25%;
}

.fluid-width-video-wrapper iframe,
.fluid-width-video-wrapper object,
.fluid-width-video-wrapper embed {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
}
```

### NFT card

NFT embeds are provided by [OpenSea](https://opensea.io).

Example HTML:

```html  theme={"dark"}
<figure class="kg-card kg-embed-card kg-nft-card">
    <a class="kg-nft-card"> <!-- Link to NFT on OpenSea -->
        <img class="kg-nft-image"> <!-- Image of NFT -->
        <div class="kg-nft-metadata">
            <div class="kg-nft-header">
                <h4 class="kg-nft-title"> NFT Name </h4>
            </div>
            <div class="kg-nft-creator">
                Created by <span class="kg-nft-creator-name"> Creator Name </span>
                • Collection
            </div>
        </div>
    </a>
</figure>
```

The default CSS for the NFT card [provided by Ghost](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/nft.css) should be used as a reference for custom implementations.

### Button card

Button cards insert a link that is styled like a button using the site’s configured accent color and can be left or center aligned.

Example HTML:

```html  theme={"dark"}
<div class="kg-card kg-button-card kg-align-center">
    <a href="https://example.com/signup/" class="kg-btn kg-btn-accent">Sign up now</a>
</div>
```

The default CSS for the button card [provided by Ghost](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/button.css) should be used as a reference for custom implementations.

### Callout card

Callout cards show a highlighted box with an emoji and a paragraph of text.

Example HTML:

```html  theme={"dark"}
<div class="kg-card kg-callout-card kg-callout-card-accent">
    <div class="kg-callout-emoji">💡</div>
    <div class="kg-callout-text">Did you know about the callout card?</div>
</div>
```

The default CSS for the callout card [provided by Ghost](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/callout.css) should be used as a reference for custom implementations.

### Toggle card

Toggle cards show a collapsible content box with heading and arrow icon.

Example HTML:

```html  theme={"dark"}
<div class="kg-card kg-toggle-card" data-kg-toggle-state="close">
    <div class="kg-toggle-heading">
        <h4 class="kg-toggle-heading-text">Do you give any discounts ?</h4>
        <button class="kg-toggle-card-icon">
            <svg id="Regular" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path class="cls-1" d="M23.25,7.311,12.53,18.03a.749.749,0,0,1-1.06,0L.75,7.311"/></svg>
        </button>
    </div>
    <div class="kg-toggle-content">Yes, we give 20% off on annual subscriptions.</div>
</div>
```

The default CSS for the toggle card [provided by Ghost](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/toggle.css) should be used as a reference for custom implementations.

### Alternative blockquote style

There are two styles of blockquote available that can by cycled through by repeatedly pressing the blockquote toolbar icon.

Example HTML:

```html  theme={"dark"}
<blockquote>Standard blockquote style</blockquote>

<blockquote class="kg-blockquote-alt">Alternative blockquote style</blockquote>
```

The default CSS for the alternative style [provided by Ghost](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/blockquote.css) should be used as a reference for custom implementations.

### Audio upload card

Audio card allows uploading custom audio files.

Example HTML:

```html  theme={"dark"}
<div class="kg-card kg-audio-card">
    <img src="https://example.com/blog/content/media/2021/12/file_example_MP3_thumb.png?v=1639412501826" alt="audio-thumbnail" class="kg-audio-thumbnail">
    <div class="kg-audio-thumbnail placeholder kg-audio-hide">
        <svg width="24" height="24" fill="none" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" d="M7.5 15.33a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5Zm-2.25.75a2.25 2.25 0 1 1 4.5 0 2.25 2.25 0 0 1-4.5 0ZM15 13.83a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5Zm-2.25.75a2.25 2.25 0 1 1 4.5 0 2.25 2.25 0 0 1-4.5 0Z"></path><path fill-rule="evenodd" clip-rule="evenodd" d="M14.486 6.81A2.25 2.25 0 0 1 17.25 9v5.579a.75.75 0 0 1-1.5 0v-5.58a.75.75 0 0 0-.932-.727.755.755 0 0 1-.059.013l-4.465.744a.75.75 0 0 0-.544.72v6.33a.75.75 0 0 1-1.5 0v-6.33a2.25 2.25 0 0 1 1.763-2.194l4.473-.746Z"></path><path fill-rule="evenodd" clip-rule="evenodd" d="M3 1.5a.75.75 0 0 0-.75.75v19.5a.75.75 0 0 0 .75.75h18a.75.75 0 0 0 .75-.75V5.133a.75.75 0 0 0-.225-.535l-.002-.002-3-2.883A.75.75 0 0 0 18 1.5H3ZM1.409.659A2.25 2.25 0 0 1 3 0h15a2.25 2.25 0 0 1 1.568.637l.003.002 3 2.883a2.25 2.25 0 0 1 .679 1.61V21.75A2.25 2.25 0 0 1 21 24H3a2.25 2.25 0 0 1-2.25-2.25V2.25c0-.597.237-1.169.659-1.591Z"></path></svg>
    </div>
    <div class="kg-audio-player-container" style="--buffered-width:0.757576%;">
        <audio src="https://example.com/content/media/2021/12/file_example_MP3.mp3" preload="metadata"></audio>
        <div class="kg-audio-title">File example MP3</div><div class="kg-audio-player">
            <button class="kg-audio-play-icon">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M23.14 10.608 2.253.164A1.559 1.559 0 0 0 0 1.557v20.887a1.558 1.558 0 0 0 2.253 1.392L23.14 13.393a1.557 1.557 0 0 0 0-2.785Z"></path></svg>
            </button>
            <button class="kg-audio-pause-icon kg-audio-hide">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="3" y="1" width="7" height="22" rx="1.5" ry="1.5"></rect><rect x="14" y="1" width="7" height="22" rx="1.5" ry="1.5"></rect></svg>
            </button>
            <span class="kg-audio-current-time">0:00</span>
            <div class="kg-audio-time">
                /<span class="kg-audio-duration">2:12</span>
            </div>
            <input type="range" class="kg-audio-seek-slider" max="132" value="0">
            <button class="kg-audio-playback-rate">1×</button>
            <button class="kg-audio-unmute-icon">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M15.189 2.021a9.728 9.728 0 0 0-7.924 4.85.249.249 0 0 1-.221.133H5.25a3 3 0 0 0-3 3v2a3 3 0 0 0 3 3h1.794a.249.249 0 0 1 .221.133 9.73 9.73 0 0 0 7.924 4.85h.06a1 1 0 0 0 1-1V3.02a1 1 0 0 0-1.06-.998Z"></path></svg>
            </button>
            <button class="kg-audio-mute-icon kg-audio-hide">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M16.177 4.3a.248.248 0 0 0 .073-.176v-1.1a1 1 0 0 0-1.061-1 9.728 9.728 0 0 0-7.924 4.85.249.249 0 0 1-.221.133H5.25a3 3 0 0 0-3 3v2a3 3 0 0 0 3 3h.114a.251.251 0 0 0 .177-.073ZM23.707 1.706A1 1 0 0 0 22.293.292l-22 22a1 1 0 0 0 0 1.414l.009.009a1 1 0 0 0 1.405-.009l6.63-6.631A.251.251 0 0 1 8.515 17a.245.245 0 0 1 .177.075 10.081 10.081 0 0 0 6.5 2.92 1 1 0 0 0 1.061-1V9.266a.247.247 0 0 1 .073-.176Z"></path></svg>
            </button>
            <input type="range" class="kg-audio-volume-slider" max="100" value="100">
        </div>
    </div>
</div>
```

The default [CSS](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/audio.css) and [Javascript](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/js/audio.js) for the audio card provided by Ghost should be used as a reference for custom implementations.

### Video upload card

Video card allows uploading custom video files.

Example HTML:

```html  theme={"dark"}
<figure class="kg-card kg-video-card"><div class="kg-video-container"><video src="https://example.com/video.mp4" poster="https://img.spacergif.org/v1/640x480/0a/spacer.png" width="640" height="480" playsinline preload="metadata" style="background: transparent url('https://example.com/video.png') 50% 50% / cover no-repeat;" /></video><div class="kg-video-overlay"><button class="kg-video-large-play-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M23.14 10.608 2.253.164A1.559 1.559 0 0 0 0 1.557v20.887a1.558 1.558 0 0 0 2.253 1.392L23.14 13.393a1.557 1.557 0 0 0 0-2.785Z"/></svg></button></div><div class="kg-video-player-container"><div class="kg-video-player"><button class="kg-video-play-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M23.14 10.608 2.253.164A1.559 1.559 0 0 0 0 1.557v20.887a1.558 1.558 0 0 0 2.253 1.392L23.14 13.393a1.557 1.557 0 0 0 0-2.785Z"/></svg></button><button class="kg-video-pause-icon kg-video-hide"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="3" y="1" width="7" height="22" rx="1.5" ry="1.5"/><rect x="14" y="1" width="7" height="22" rx="1.5" ry="1.5"/></svg></button><span class="kg-video-current-time">0:00</span><div class="kg-video-time">/<span class="kg-video-duration"></span></div><input type="range" class="kg-video-seek-slider" max="100" value="0"><button class="kg-video-playback-rate">1×</button><button class="kg-video-unmute-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M15.189 2.021a9.728 9.728 0 0 0-7.924 4.85.249.249 0 0 1-.221.133H5.25a3 3 0 0 0-3 3v2a3 3 0 0 0 3 3h1.794a.249.249 0 0 1 .221.133 9.73 9.73 0 0 0 7.924 4.85h.06a1 1 0 0 0 1-1V3.02a1 1 0 0 0-1.06-.998Z"/></svg></button><button class="kg-video-mute-icon kg-video-hide"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M16.177 4.3a.248.248 0 0 0 .073-.176v-1.1a1 1 0 0 0-1.061-1 9.728 9.728 0 0 0-7.924 4.85.249.249 0 0 1-.221.133H5.25a3 3 0 0 0-3 3v2a3 3 0 0 0 3 3h.114a.251.251 0 0 0 .177-.073ZM23.707 1.706A1 1 0 0 0 22.293.292l-22 22a1 1 0 0 0 0 1.414l.009.009a1 1 0 0 0 1.405-.009l6.63-6.631A.251.251 0 0 1 8.515 17a.245.245 0 0 1 .177.075 10.081 10.081 0 0 0 6.5 2.92 1 1 0 0 0 1.061-1V9.266a.247.247 0 0 1 .073-.176Z"/></svg></button><input type="range" class="kg-video-volume-slider" max="100" value="100"></div></div></div></figure>
```

The default [CSS](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/video.css) and [Javascript](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/js/video.js) for the video card provided by Ghost should be used as a reference for custom implementations.

### File upload card

File card allows uploading custom files for download.

Example HTML:

```html  theme={"dark"}

<div class="kg-card kg-file-card ">
    <a class="kg-file-card-container" href="https://ghost.org/uploads/2017/11/file_example_PDF.pdf" title="Download">
        <div class="kg-file-card-contents">
            <div class="kg-file-card-title">Sample File</div>
            <div class="kg-file-card-caption">Sample file caption</div>
            <div class="kg-file-card-metadata">
                <div class="kg-file-card-filename">file_example_PDF.pdf</div>
                <div class="kg-file-card-filesize">488 KB</div>
            </div>
        </div>
        <div class="kg-file-card-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><defs><style>.a{fill:none;stroke:currentColor;stroke-linecap:round;stroke-linejoin:round;stroke-width:1.5px;}</style></defs><title>download-circle</title><polyline class="a" points="8.25 14.25 12 18 15.75 14.25"/><line class="a" x1="12" y1="6.75" x2="12" y2="18"/><circle class="a" cx="12" cy="12" r="11.25"/></svg>
        </div>
    </a>
</div>
```

The default [CSS](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/file.css) for the file card provided by Ghost should be used as a reference for custom implementations.

### Header card

The header card gives you the ability to add headers to your posts and pages.

Example HTML:

```html  theme={"dark"}
<div class="kg-card kg-header-card kg-width-full kg-size-<size> kg-style-<style>" style="" data-kg-background-image="https://example.com/image.jpg">
    <h2 class="kg-header-card-header">Header</h2>
    <h3 class="kg-header-card-subheader">Subheader</h3>
    <a href="" class="kg-header-card-button">
        Button Text
    </a>
</div>
```

The main card can have a `kg-size-` class of either: `kg-size-small`, `kg-size-medium` or `kg-size-large` and a `kg-style-` class of either `kg-style-dark`, `kg-style-light`, `kg-style-accent, or `kg-style-image\`.

The default [CSS](https://github.com/TryGhost/Ghost/blob/c667620d8f2e32c96fe376ad0f3dabc79488532a/ghost/core/core/frontend/src/cards/css/header.css) for the card can be used as a reference implementation.

### Signup card

The signup card adds a customizable signup form to posts. (Only available in the [new beta editor](https://ghost.org/changelog/editor-beta/).)

```html  theme={"dark"}
<div
  class="kg-card kg-signup-card kg-width-<size>"
  data-lexical-signup-form=""
  style=""
>
  <div class="kg-signup-card-content">
    <!-- image in split layout -->
    <picture
      ><img
        class="kg-signup-card-image"
        src=""
        alt=""
    /></picture>

    <div class="kg-signup-card-text">
      <h2 class="kg-signup-card-heading" style="">
        <span>Heading</span>
      </h2>
      <h3 class="kg-signup-card-subheading" style="">
        <span>Subheading</span>
      </h3>

      <form class="kg-signup-card-form" data-members-form="signup">
        <div class="kg-signup-card-fields">
          <input
            class="kg-signup-card-input"
            id="email"
            data-members-email=""
            type="email"
            required="true"
            placeholder="Your email"
          />
          <button
            class="kg-signup-card-button kg-style-accent"
            style=""
            type="submit"
          >
            <span class="kg-signup-card-button-default">Subscribe</span>
            <span class="kg-signup-card-button-loading"
              ><!-- SVG loading icon --></span
            >
          </button>
        </div>
        <div class="kg-signup-card-success" style="">
          Email sent! Check your inbox to complete your signup.
        </div>
        <div
          class="kg-signup-card-error"
          style=""
          data-members-error=""
        ></div>
      </form>

      <p class="kg-signup-card-disclaimer" style="">
        <span>No spam. Unsubscribe anytime.</span>
      </p>
    </div>
  </div>
</div>
```

For `kg-width-<size>`, `size` can be `kg-width-regular`, `kg-width-wide`, or `kg-width-full`.

Full-width and split-layout with contained image cards provide a `kg-content-wide` class. Use this class to ensure card content is properly positioned and sized. See [Casper’s implementation](https://github.com/TryGhost/Casper/blob/2fafe722d1ee997f5f1b597de859fe2462090e42/assets/css/screen.css#L1298-L1312) for a guide.

Split-layout signup cards, which include an image adjacent to the text content, provide the `kg-layout-split` class.

See the [default CSS](https://github.com/TryGhost/Ghost/blob/4c72f4567600a59a64be10f38acf851bffaa6dec/ghost/core/core/frontend/src/cards/css/signup.css) included with this card.


# Contexts
Source: https://docs.ghost.org/themes/contexts

Each page in a Ghost theme belongs to a context, which determines which template is used, what data will be available and what content is output by the `{{body_class}}` helper.

***

A Ghost publication follows a structure that allows URLs or routes to be mapped to views which display specific data. This data could be a list of posts, a single post or an RSS feed. It is the route that determines what data is meant to be shown and what template is used to render it.

Rather than providing access to all data in all contexts, Ghost optimises what data is fetched using contexts to ensure publications are super fast!

### Using contexts

Contexts play a big part in the building blocks of a Ghost theme. Besides determining what data is available and what template to render, contexts also interact with [handlebars helpers](/themes/helpers/), since the context also determines what dynamic data the helper outputs.

For example, the `{{meta_title}}` helper outputs different things based on the current context. If the context is `post` then the helper knows it can use `post.meta_title` and in a `tag` context it uses `tag.meta_title`.

To detect a context in your theme, use the `{{#is}}` helper. For example, in a partial template that is shared between many contexts, using `{{#is}}` passes it a context and only executes the contained block when it is in that context.

## List of contexts

* [index](/themes/contexts/index-context/)
* [page](/themes/contexts/page/)
* [post](/themes/contexts/post/)
* [author](/themes/contexts/author/)
* [tag](/themes/contexts/tag/)
* [error](/themes/contexts/error/)


# Author
Source: https://docs.ghost.org/themes/contexts/author

Use: `{{#is "author"}}{{/is}}` to detect this context

***

Authors in Ghost each get their own page which outputs a list of posts that were published by that author. You’re in the `author` context when viewing the page thats lists all posts written by that user, as well as subsequent pages of posts. The `author` context is only set on the list of posts, and not on the individual post itself.

## Routes

The default URL for author pages is `/author/:slug/`. The `author` context is also set on subsequent pages of the post list, which live at `/author/:slug/page/:num/`. The `slug` part of the URL is based on the name of the author and can be configured in admin. To change the author URL structure, use [routing](/themes/#routing).

## Templates

The default template for an author page is `index.hbs` or you can use an `author.hbs` file in your theme to customise the author pages.

To provide a custom template for a *specific* author, name the file using `author-:slug.hbs`, file with the `:slug` matching the user’s slug. For example, if you have an author ‘John’ with the url `/author/john/`, adding a template called `author-john.hbs` will cause that template to be used for John’s list of posts instead of `author.hbs`, or `index.hbs`.

These templates exist in a hierarchy. Ghost looks for a template which matches the slug (`author-:slug.hbs`) first, then looks for `author.hbs` and finally uses `index.hbs` if neither is available.

## Data

When in the `author` context, a template gets access to 3 objects: the author object which matches the route, an array of post objects and a pagination object. As with all contexts, all of the `@site` global data is also available.

### Author object

When outputting the author attributes, use a block expression (`{{#author}}{{/author}}`) to drop into the author scope and access all of the attributes. See a full list of attributes below:

### Author object attributes

* **id** — incremental ID of the author
* **name** — name of the author
* **bio** — bio of the author
* **location** — author’s location
* **website** — author’s website
* **twitter** — the author’s twitter username
* **facebook** — the author’s facebook username
* **profile\_image** — the profile image associated with the author
* **cover\_image** — author’s cover image
* **url** - web address for the author’s page

### Post list

Each of the posts can be looped through using `{{#foreach posts}}{{/foreach}}`. The template code inside the block will be rendered for each post, and have access to all of the post object attributes.

### Pagination

The best way to output pagination is to use the pagination helper — the pagination object provided is the same everywhere.

## Helpers

The `{{#author}}{{/author}}` block expression is useful for accessing all of the author attributes. Once inside the author you can access the attributes and use helpers like `{{img_url}}` and `{{url}}` to output the author’s details.

Using `{{#foreach posts}}{{/foreach}}` is the best way to loop through your posts and output each one. If you’re using the Members feature, consider the [content visibility](/themes/members/#content-visibility) of your posts.

If your theme does have a `tag.hbs` and `author.hbs` file all outputting similar post lists to `index.hbs` you may wish to use a partial to define your post list item, e.g. `{{> "loop"}}`.

```html  theme={"dark"}
<!-- author.hbs -->

<!-- Everything inside the #author tags pulls data from the author -->
{{#author}}
  <header>
  	{{#if profile_image}}
    	<img src="{{img_url profile_image}}" alt="{{name}}'s Picture" />
    {{/if}}
  </header>

  <section class="author-profile">
  	<h1 class="author-title">{{name}}</h1>
    {{#if bio}}<h2 class="author-bio">{{bio}}</h2>{{/if}}

    <div class="author-meta">
      {{plural ../pagination.total empty='No posts' singular='% post' plural='% posts'}}
     </div>
  </section>
{{/author}}

<main role="main">
    <!-- includes the post loop - partials/loop.hbs -->
    {{> "loop"}}
</main>

<!-- Previous/next page links - displayed on every page -->
{{pagination}}
```


# Error
Source: https://docs.ghost.org/themes/contexts/error

Error templates used for all `4xx` and `5xx` errors that may arise on a site

***

The most common errors seen in Ghost are `404` errors. Depending on the complexity of your theme, your [routes file](/themes/routing/) and other factors, errors can range from `4xx` to `5xx`. Read more about error [status codes on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status).

## Routes

Errors can be rendered on any route.

## Templates

The default template for an error is `error.hbs`, this will be used to render any error if there are no specific templates provided.

Error classes, `4xx` and `5xx` can be captured using `error-4xx.hbs` and `error-5xx.hbs` respectively. For example a `404` error can be captured with `error-4xx.hbs`, and a `500` error can be captured with `error-5xx.hbs`.

Specific errors can be captured by naming the template with the status code. For example `404` errors can be captured using `error-404.hbs`.

If no custom error templates have been defined in the theme Ghost will use it’s default error template.

## Data

Error templates have access to the details of the error and the following attributes can be used:

### Error object attributes

* `{{statusCode}}` — The HTTP status code of the error

* `{{message}}` — The error message

* `{{errorDetails}}` — An object containing further error details

  * `{{rule}}` — The rule
  * `{{ref}}` — A reference
  * `{{message}}` — Further information about the issue captured

## Helpers

Error templates shouldn’t use any theme helpers, with the exception of `{{asset}}`, or extend the default template, to further avoid the use of template helpers. Using theme helpers inside error templates can lead to misleading error reports.

The only error template that is permitted to use helpers is the `error-404.hbs` template file.

### Example code

```html  theme={"dark"}
<!-- error.hbs -->

<!doctype html>
<!--[if (IE 8)&!(IEMobile)]><html class="no-js lt-ie9" lang="en"><![endif]-->
<!--[if (gte IE 9)| IEMobile |!(IE)]><!--><html class="no-js" lang="en"><!--<![endif]-->
  <head>
    <meta http-equiv="Content-Type" content="text/html" charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />

    <title>{{statusCode}} — {{message}}</title>

    <meta name="HandheldFriendly" content="True">
    <meta name="MobileOptimized" content="320">
    <meta name="viewport" content="user-scalable=no, width=device-width, initial-scale=1, maximum-scale=1">
    <meta name="apple-mobile-web-app-capable" content="yes" />

    <link rel="shortcut icon" href="{{asset "favicon.ico"}}">
    <meta http-equiv="cleartype" content="on">

    <link rel="stylesheet" href="{{asset "public/ghost.css" hasMinFile="true"}}"/>

  </head>
  <body>
    <main role="main" id="main">
      <div class="gh-app">
          <div class="gh-viewport">
              <div class="gh-view">
                <section class="error-content error-{{statusCode}} js-error-container">
                  <section class="error-details">
                    <section class="error-message">
                      <h1 class="error-code">{{statusCode}}</h1>
                      <h2 class="error-description">{{message}}</h2>
                      <a class="error-link" href="{{@site.url}}">Go to the front page →</a>
                    </section>
                  </section>
                </section>

                {{#if errorDetails}}
                    <section class="error-stack">
                        <h3>Theme errors</h3>

                        <ul class="error-stack-list">
                            {{#foreach errorDetails}}
                                <li>
                                    <em class="error-stack-function">{{{rule}}}</em>

                                    {{#foreach failures}}
                                        <p><span class="error-stack-file">Ref: {{ref}}</span></p>
                                        <p><span class="error-stack-file">Message: {{message}}</span></p>
                                    {{/foreach}}
                                </li>
                            {{/foreach}}
                        </ul>
                    </section>
                {{/if}}
              </div>
          </div>
      </div>
    </main>
  </body>
</html>
```


# Index
Source: https://docs.ghost.org/themes/contexts/index-context

Use: `{{#is "index"}}{{/is}}` to detect this context.

***

## Description

`index` is the name for the main post list in your Ghost site, the `index` context includes the home page and subsequent pages of the main post list. The `index` context is always paired with either the `home` context when on the first page of your site, or the `page` context when on subsequent pages.

## Routes

The index context is present on both the root URL of the site, e.g. `/` and also on subsequent pages of the post list, which live at `/page/:num/`. All routes are customisable with [dynamic routing](/themes/routing/).

## Templates

The index context is rendered with `index.hbs` by default. This template is required in all Ghost themes. If there is a `home.hbs` present in the theme, the home page will be rendered using that instead.

Note that the `index.hbs` template is also used to output the tag and author contexts, if no specific `tag.hbs` or `author.hbs` templates are provided.

## Data

The `index` context provides templates with access to an array of post objects and a pagination object. As with all contexts, all of the `@site` global data is also available.

The number of posts provided will depend on the `post per page` setting which you can configure [in your package.json](/themes/structure#additional-properties) file. The array will provide the correct posts for the current page number, with the posts ordered chronologically, newest first. Therefore on the home page, the theme will have access to the first 6 posts by default. On /page/2/ the theme will have access to posts 7-12.

Each of the posts can be looped through using `{{#foreach 'posts'}}{{/foreach}}`. The template code inside the block will be rendered for each post, and have access to all of the post object attributes.

The pagination object provided is the same everywhere. The best way to output pagination is to use the pagination helper.

## Helpers

Using `{{#foreach 'posts'}}{{/foreach}}` is the best way to loop through your posts and output each one.

If your theme does have a `tag.hbs` and `author.hbs` file all outputting similar post lists you may wish to use a partial to define your post list item, e.g. `{{> "loop"}}`. There’s an example showing this in detail below.

The [\{\{pagination}}](/themes/helpers/utility/pagination/) helper is the best way to output pagination. This is fully customisable.

## Example Code

```handlebars  theme={"dark"}
<!-- index.hbs -->
<header>
  <h1 class="page-title">{{@site.title}}</h1>
  <h2 class="page-description">{{@site.description}}</h2>
</header>

<main role="main">
<!-- This is the post loop - each post will be output using this markup -->
  {{#foreach posts}}
	<article class="{{post_class}}">
 		<header class="post-header">
   		<h2><a href="{{url}}">{{title}}</a></h2>
    </header>
    <section class="post-excerpt">
 			<p>{{excerpt words="26"}} <a class="read-more" href="{{url}}">...</a></p>
    </section>
    <footer class="post-meta">
      {{#if primary_author.profile_image}}<img src="{{primary_author.profile_image}}" alt="Author image" />{{/if}}
      {{primary_author}}
      {{tags prefix=" on "}}
      <time class="post-date" datetime="{{date format='YYYY-MM-DD'}}">{{date format="DD MMMM YYYY"}}</time>
    </footer>
  </article>
  {{/foreach}}

</main>

<!-- Previous/next page links - displayed on every page -->
{{pagination}}
```

## Home

`home` is a special context which refers to page 1 of the index. If `home` is set, `index` is always set as well. `home` can be used to detect that this is specifically the first page of the site and not one of the subsequent pages.

Use: `{{#is "home"}}{{/is}}` to detect this context.

### Routes

The route for the home page is always `/`.

### Templates

The default template for the home page is `index.hbs`. You can optionally add a `home.hbs` template to your theme which will be used instead.

### Data

The data available on the home page is exactly the same as described in the index context. The home page’s posts will always be the first X posts ordered by published date with the newest first, where X is defined by the `posts_per_page` setting in the `package.json` file.


# Page
Source: https://docs.ghost.org/themes/contexts/page

Use: `{{#is "page"}}{{/is}}` to detect this context

***

Whenever you’re viewing a static page, you’re in the `page` context. The `page` context is not set on posts, which uses the `post` context instead.

## Routes

The URL used to render a static page is always `/:slug/`. This cannot be customised, unlike post permalinks.

## Templates

The default template for a page is `post.hbs` and an optional `page.hbs` template can be used.

Custom templates for specific pages are determined using `page-:slug.hbs`, with the `:slug` matching the static page’s slug.

For example, if you have an ‘About’ page with the url `/about/`, adding a template called `page-about.hbs` will cause that template to be used instead of `page.hbs`, or `post.hbs`.

These templates exist in a hierarchy. Ghost looks for a template which matches the slug (`page-:slug.hbs`) first, then looks for `page.hbs` and finally uses `post.hbs` if neither is available.

## Data

The `page` context provides access to the post object which matches the route. A page is just a special type of post, so the data object is called a post, not a page. As with all contexts, all of the `@site` global data is also available.

When outputting the page, the block expression `{{#post}}{{/post}}` is used to drop into the post scope and access all of the attributes. All of the data available for a page is the same as the data for a post.

### Post (page) object attributes

* **id** — incremental ID of the page
* **title** — the title of your static page
* **excerpt** — a short preview of your page content
* **content** — the content of the page
* **url** — the web address for the static page
* **feature\_image** — the cover image associated with the page
* **feature\_image\_alt** — alt text for the cover image associated with the page
* **feature\_image\_caption** — caption for the cover image associated with the page (supports basic html)
* **featured** — indicates a featured page, defaults to `false`
* **page** — `true` if the post is a static page, defaults to `false`
* **meta\_title** — custom meta title for the page
* **meta\_description** — custom meta description for the page
* **published\_at** — date and time when the page was published
* **updated\_at** — date and time when the page was last updated
* **created\_at** — date and time when the page was created
* **primary\_author** — a formatted link to the first author. See [Authors for more information](/themes/helpers/data/authors/)
* **tags** - a list of tags associated with the page

## Helpers

Using the `{{#post}}{{/post}}` block expression is used to theme a static page. Once inside of the page, you can use any of these useful helpers (and many more) to output your page’s data:

`{{title}}`, `{{content}}`, `{{url}}`, `{{author}}`, `{{date}}`, `{{excerpt}}`, `{{img_url}}`, `{{post_class}}]`, `{{tags}}`.

```html  theme={"dark"}
<!-- page.hbs -->

<!-- Everything inside the #post tags pulls data from the static page -->
{{#post}}

<article class="{{post_class}}">
  <header class="page-header">
    <h1 class="page-title">{{title}}</h1>
    <section class="page-meta">
      <time class="page-date" datetime="{{date format='YYYY-MM-DD'}}">
        {{date format="DD MMMM YYYY"}}
      </time>
      {{tags prefix=" on "}}
    </section>
  </header>
  <section class="page-content">
    {{content}}
  </section>
</article>

{{/post}}
```


# Post
Source: https://docs.ghost.org/themes/contexts/post

Use: `{{#is "post"}}{{/is}}` to detect this context

***

Whenever you’re viewing a single site post, you’re in the `post` context. The `post` context is not set on static pages, which uses the page context instead.

## Routes

The URL used to render a single post is configurable in the Ghost admin. The default is `/:slug/`. Ghost also has an option for date-based permalinks, and can support many other formats using [routing](/themes/routing/).

## Templates

The default template for a post is `post.hbs`, which is a required template in all Ghost themes.

To provide a custom template for a specific post, use `post-:slug.hbs` as the template name, with `:slug` matching the post’s slug.

For example, if you have a ‘1.0 Announcement’ post with the url /1-0-announcement/, adding a template called `post-1-0-announcement.hbs` will cause that template to be used for the announcement post, instead of `post.hbs`.

Another option is to use a “global” custom post template. If you add a template to your theme called `custom-gallery.hbs` it will be available in a dropdown in the post settings menu so that it can be selected in any post or page.

These templates exist in a hierarchy. Ghost looks for a template which matches the slug (`post-:slug.hbs`) first, then looks for a custom template (`custom-gallery.hbs` if selected in the post settings) and finally uses `post.hbs` if no slug-specific template exists and no custom template is specified.

## Data

The `post` context provides access to the post object which matches the route. As with all contexts, all of the `@site` global data is also available.

When outputting the post, use a block expression (`{{#post}}{{/post}}`) to drop into the post scope and access all of the attributes.

### Post object attributes

* **id** — the Object ID of the post
* **comment\_id** — The old, pre-1.0 incremental id of a post if present, or else the new Object ID
* **title** — the title of your site post
* **slug** — slugified version of the title (used in urls and also useful for class names)
* **excerpt** — a short preview of your post content
* **content** — the content of the post
* **url** — the web address for the post page (see url helper) and special attributes
* **feature\_image** — the cover image associated with the post
* **feature\_image\_alt** — alt text for the cover image associated with the post
* **feature\_image\_caption** — caption for the cover image associated with the post (supports basic html)
* **featured** — indicates a featured post. Defaults to `false`
* **page** — `true` if the post is a page. Defaults to `false`
* **meta\_title** — custom meta title for the post
* **meta\_description** — custom meta description for the post
* **published\_at** — date and time when the post was published
* **updated\_at** — date and time when the post was last updated
* **created\_at** — date and time when the post was created
* **primary\_author** — a formatted link to the first author
* **tags** — a list of tags associated with the post
* **primary\_tag** — direct reference to the first tag associated with the post

## Helpers

The `{{#post}}{{/post}}` block expression is used to theme the post template. Once inside of the post, you can use any of these useful helpers (and many more) to output your post’s data:

`{{title}}`, `{{content}}`, `{{url}}`, `{{author}}`, `{{date}}`, `{{excerpt}}`, `{{img_url}}`, `{{post_class}}`, `{{tags}}`.

```html  theme={"dark"}
<!-- post.hbs -->

<!-- Everything inside the #post tags pulls data from the post -->
{{#post}}

<article class="{{post_class}}">
  <header class="post-header">
    <h1 class="post-title">{{title}}</h1>
    <section class="post-meta">
      <time class="post-date" datetime="{{date format='YYYY-MM-DD'}}">
        {{date format="DD MMMM YYYY"}}
      </time>
      {{tags prefix=" on "}}
    </section>
  </header>
  <section class="post-content">
    {{content}}
  </section>
</article>

{{/post}}
```

## Special attributes

The post model is the most complex model in Ghost, and it has special attributes, which are calculated by the API.

### URL

URL is a calculated, created based on the site’s permalink setting and the post’s other properties. It exists as a data attribute, but should always be output using the special `{{url}}` helper rather than referenced as a data attribute.

Always open a context and use `{{url}}` explicitly for *all* resources, especially in posts. For example, use `{{#post}}{{url}}{{/post}}` instead of `{{post.url}}`.

### Primary tag

Each post has a list of 0 or more tags associated with it, which is accessed via the `tags` property and `{{tags}}` helper. The first tag in the list is considered more important, and can be accessed using a `primary_tag` calculated property. This is a path expression, which points to a whole tag object, rather than a helper function.


# Tag
Source: https://docs.ghost.org/themes/contexts/tag

Use: `{{#is "tag"}}{{/is}}` to detect this context

***

Tags in Ghost each get their own tag archive which lists all posts associated with the tag. You’re in the `tag` context when viewing the page thats lists all posts with that tag, as well as subsequent pages of posts. The `tag` context is not set on posts or pages with tags, only on the list of posts for that tag.

## Routes

The default URL for tag pages is `/tag/:slug/`. The `tag` context is also set on subsequent pages of the post list, which live at `/tag/:slug/page/:num/`. The `slug` part of the URL is based on the name of the tag and can be configured from the **Tags** page in Admin. To change the tag URL structure, use [routing](/themes/routing/).

## Templates

The default template for a tag page is `index.hbs` — or an optional `tag.hbs` template can be used.

To provide a custom template for a specific tag, use `tag-:slug.hbs` where the `:slug` matches the tag’s slug.

For example, if you have a tag ‘photo’ with the url `/tag/photo/`, adding a template called `tag-photo.hbs` will cause that template to be used for the photo tag instead of `tag.hbs`, or `index.hbs`.

These templates exist in a hierarchy. Ghost looks for a template which matches the slug (`tag-:slug.hbs`) first, then looks for `tag.hbs` and finally uses `index.hbs` if neither is available.

## Data

When in the `tag` context, a template gets access to 3 objects: the tag object which matches the route, an array of post objects and a pagination object. As with all contexts, all of the `@site` global data is also available.

### Tag object

Use the block expression (`{{#tag}}{{/tag}}`) to drop into the tag scope and access all of the attributes.

#### Tag object attributes

* **id** — the incremental ID of the tag
* **name** — name of the tag
* **slug** — slugified version of the name (used in urls and also useful for class names)
* **description** — description of the tag
* **feature\_image** — the cover image associated with the tag
* **meta\_title** — custom meta title for the page
* **meta\_description** — custom meta description for the page
* **url** — the web address for the tag’s page
* **accent\_color** — the accent color of the tag

### Post list

Each of the posts can be looped through using `{{#foreach 'posts'}}{{/foreach}}`. The template code inside the block will be rendered for each post, and have access to all of the post object attributes.

### Pagination

The pagination object provided is the same everywhere. The best way to output pagination is to use the pagination helper.

## Helpers

The `{{#tag}}{{/tag}}` block expression is useful for accessing all attributes. Once inside the tag, use helpers like `{{img_url}}` and `{{url}}` to output the tag’s details.

Using `{{#foreach 'posts'}}{{/foreach}}` is the best way to loop through the list of posts and output each one. If you’re using the Members feature, consider the [content visibility](/themes/members/#content-visibility) of your posts

If your theme does have a `tag.hbs` and `author.hbs` file all outputting similar post lists to `index.hbs` you may wish to use a partial to define your post list item, for example: `{{> "loop"}}`.

```html  theme={"dark"}
<!-- tag.hbs -->

<!-- Everything inside of #tag pulls data from the tag -->
{{#tag}}
  <header>
  	{{#if feature_image}}
    	<img src="{{feature_image}}" alt="{{name}}" />
    {{/if}}
  </header>

  <section class="author-profile">
  	<h1>{{name}}</h1>
    {{#if description}}
      <h2>{{description}}</h2>
    {{/if}}
  </section>
{{/tag}}

<main role="main">
    <!-- includes the post loop - partials/loop.hbs -->
    {{> "loop"}}
</main>

<!-- Previous/next page links - displayed on every page -->
{{pagination}}
```


# Custom Settings
Source: https://docs.ghost.org/themes/custom-settings

Custom theme settings are a powerful tool that allows theme developers to configure custom settings that appear in Ghost Admin — making it easy for site owners to make stylistic choices without needing to edit theme files.

***

## Overview

Custom theme settings are specified by the theme developer in the `package.json` file at the `config.custom` key, and there are five types of custom theme settings available:

* `select`
* `boolean`
* `color`
* `image`
* `text`

```json  theme={"dark"}
{
    "config": {
        "custom": {
            "typography": {
                "type": "select",
                "options": ["Modern sans-serif", "Elegant serif"],
                "default": "Modern sans-serif"
            },
            "cta_text": {
                "type": "text",
                "default": "Sign up for more like this",
                "group": "post"
            }
        }
    }
}
```

Once defined in the `package.json` file, custom settings can be accessed in Handlebars templates using the `@custom` object.

```handlebars  theme={"dark"}
<body class="{{body_class}} {{#match @custom.typography "Elegant serif"}}font-alt{{/match}}">
    ...
    <section class="footer-cta">
        {{#if @custom.cta_text}}<h2>{{@custom.cta_text}}</h2>{{/if}}
        <a href="#portal/signup">Sign up now</a>
    </section>
</body>
```

Themes are limited to a total of 20 custom settings. See the [usage guidelines](#guidelines-for-theme-developers) for details on the most effective ways to use custom settings.

## Setting keys/names

The key given to each setting is used as the display name in Ghost Admin, and as the property name on the `@custom` object.

```json  theme={"dark"}
{
    "config": {
        "custom": {
            "cta_text": {
                "type": "text",
                "default": "Sign up for more like this",
                "group": "post",
                "description": "Used in a large CTA on the homepage and small one on the sidebar as well" 
            }
        }
    }
}
```

In this example, the `"cta_text"` key is displayed to site owners as **CTA Text** and can be referenced in Handlebars templates using `@custom.cta_text`.

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8188bddf1b9c1dfa7c8e5878f0438d8c" data-og-width="1644" width="1644" data-og-height="272" height="272" data-path="images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=9457e67d19baaa3aee546e1076fb8449 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=eae49e037b46679c413cac352c260417 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d705a444c800334586823da9a74525cd 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=349d564fcc0004f6b4e1cc2600607f19 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=bddd6c8ba301adaa00b14c9671159a6a 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a0c9a8e0d96377592a83a29e78aa6bfc 2500w" />
</Frame>

Setting keys must be all lowercase with no special characters and in `snake_case` where each space is represented by an `_`.

Changing a setting’s key when releasing a new theme version is a breaking change for site owners who upgrade from an older version. The setting with the old key is removed, losing any value entered by the site owner, and a new setting with the current key is created with its default value.

## Setting groups

Theme settings fall under the **Theme** tab in **Design & branding**, and are grouped into one of three categories:

* Site wide
* Homepage
* Post

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2b088467-setting-groups_hu9b3d4ebb234056755f3680e4fdc54d1b_2122069_4096x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=6b740f34b5f92d610cacb5a403317836" data-og-width="4096" width="4096" data-og-height="2331" height="2331" data-path="images/2b088467-setting-groups_hu9b3d4ebb234056755f3680e4fdc54d1b_2122069_4096x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2b088467-setting-groups_hu9b3d4ebb234056755f3680e4fdc54d1b_2122069_4096x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=4a9cea2000f7858520233954984762f2 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2b088467-setting-groups_hu9b3d4ebb234056755f3680e4fdc54d1b_2122069_4096x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=c87de0c8a2d208c70c5d5bded07be9ab 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2b088467-setting-groups_hu9b3d4ebb234056755f3680e4fdc54d1b_2122069_4096x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=aa041ad47725b188d4fd6b05ff3525ee 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2b088467-setting-groups_hu9b3d4ebb234056755f3680e4fdc54d1b_2122069_4096x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=906b7426b3238325c541c0ee69bc28c7 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2b088467-setting-groups_hu9b3d4ebb234056755f3680e4fdc54d1b_2122069_4096x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d7980b88fb8c5c6b4058e2cafd18feee 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2b088467-setting-groups_hu9b3d4ebb234056755f3680e4fdc54d1b_2122069_4096x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=36e29a4fd4bf5e80b798d77fe2703925 2500w" />
</Frame>

By default, all custom settings appear in the **Site wide** category. Custom settings that are specific to the homepage or post display are defined with an optional `"group"` property with the value `"homepage"` or `"post"`.

```json  theme={"dark"}
{
    "config": {
        "custom": {
            "typography": {
                "type": "select",
                "options": ["Modern sans-serif", "Elegant serif"],
                "default": "Modern sans-serif",
                "description": "Define the default font used for the publication"
            },
            "feed_layout": {
                "type": "select",
                "options": ["Dynamic grid", "Simple grid", "List"],
                "default": "Dynamic grid",
                "group": "homepage",
                "description": "The layout of the post feed on the homepage, tag, and author pages"
            },
            "cta_text": {
                "type": "text",
                "default": "Sign up for more like this",
                "group": "post",
                "description": "Used in a large CTA on the homepage and small one on the sidebar as well" 
            }
        }
    }
}
```

Settings should be organized into groups that will make sense for site owners based on your usage of the setting in the theme.

## Setting a description

Give users more information about what a custom setting does by providing a short description. The description will appear along with the setting in Ghost admin. Description must be fewer than 100 characters.

## Setting types

Each of the five custom setting types has particular fields and requirements.

All custom settings require a valid `"type"` — an unknown type causes a theme validation error.

### Select

Presents a select input with options defined by the theme developer.

Select settings are used to offer site owners multiple predefined options in combination with the `match` helper:

```json  theme={"dark"}
"feed_layout": {
    "type": "select",
    "options": ["Dynamic grid", "Simple grid", "List"],
    "default": "Dynamic grid"
}
```

```handlebars  theme={"dark"}
{{#match @custom.feed_layout "Dynamic grid"}}
    //
{{/match}}
```

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/66561604-setting-type-select_hu66e48d0a12b84f5270a886c24dc079fa_5437_1876x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=c7dd641040c4978420a7806c61d0d708" data-og-width="1876" width="1876" data-og-height="268" height="268" data-path="images/66561604-setting-type-select_hu66e48d0a12b84f5270a886c24dc079fa_5437_1876x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/66561604-setting-type-select_hu66e48d0a12b84f5270a886c24dc079fa_5437_1876x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=bcbdb2412413474abf91269540436db9 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/66561604-setting-type-select_hu66e48d0a12b84f5270a886c24dc079fa_5437_1876x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=77304c780af929c775ef386091d62493 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/66561604-setting-type-select_hu66e48d0a12b84f5270a886c24dc079fa_5437_1876x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=1685d36d688dfff5fd6b4479a85a51f6 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/66561604-setting-type-select_hu66e48d0a12b84f5270a886c24dc079fa_5437_1876x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=d6e3d9179f826b6c2d43d59bc44a1992 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/66561604-setting-type-select_hu66e48d0a12b84f5270a886c24dc079fa_5437_1876x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=dd81ccecd062f8dfd378de6b48bf5963 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/66561604-setting-type-select_hu66e48d0a12b84f5270a886c24dc079fa_5437_1876x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=053ed4c15538fa6606fd0b16d07c7ae1 2500w" />
</Frame>

#### Validation

* `options` is required and must be an array of strings
* `default` is required and must match one of the defined options

### Boolean

Presents a checkbox toggle.

```json  theme={"dark"}
"recent_posts": {
    "type": "boolean",
    "default": true
}
```

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5a2f53fd-setting-type-boolean_hu2ded47e2af98aad7bab23dbc5e0941ba_19117_1644x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=8ea82f3b2af43ea006f3d1e2d9a00faf" data-og-width="1644" width="1644" data-og-height="196" height="196" data-path="images/5a2f53fd-setting-type-boolean_hu2ded47e2af98aad7bab23dbc5e0941ba_19117_1644x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5a2f53fd-setting-type-boolean_hu2ded47e2af98aad7bab23dbc5e0941ba_19117_1644x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=27bdc7cac63a4233d617e31731de88ea 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5a2f53fd-setting-type-boolean_hu2ded47e2af98aad7bab23dbc5e0941ba_19117_1644x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=cfb5ec1161cb378b25dc30a18ee214f6 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5a2f53fd-setting-type-boolean_hu2ded47e2af98aad7bab23dbc5e0941ba_19117_1644x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=2f0599d8548142aa908597beac1450af 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5a2f53fd-setting-type-boolean_hu2ded47e2af98aad7bab23dbc5e0941ba_19117_1644x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=d03a8ddaecb3b35c3e3584026c87b3b7 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5a2f53fd-setting-type-boolean_hu2ded47e2af98aad7bab23dbc5e0941ba_19117_1644x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=c329bbd8790b021653d86b98ac92b1f9 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/5a2f53fd-setting-type-boolean_hu2ded47e2af98aad7bab23dbc5e0941ba_19117_1644x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a9ef10c0312a19f2d46f7aa33bc40d85 2500w" />
</Frame>

#### Validation

* `default` is required and must be either `true` or `false`

Boolean settings can simply be used with the `{{#if}}` helper:

```handlebars  theme={"dark"}
{{#if @custom.recent_posts}}
    //
{{/if}}
```

### Color

Presents a color picker.

```json  theme={"dark"}
"button_color": {
    "type": "color",
    "default": "#15171a"
}
```

<Frame>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e14f81a0-setting-type-color_hue94a37f604d47f4aebf527f78c55a34e_28164_1644x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=78fed444af5e3f60096319882738b571" data-og-width="1644" width="1644" data-og-height="208" height="208" data-path="images/e14f81a0-setting-type-color_hue94a37f604d47f4aebf527f78c55a34e_28164_1644x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e14f81a0-setting-type-color_hue94a37f604d47f4aebf527f78c55a34e_28164_1644x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=89c9ea5c2514f15e84ccbad5f61b2d1b 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e14f81a0-setting-type-color_hue94a37f604d47f4aebf527f78c55a34e_28164_1644x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f5768d9898816d4dc95f98d97af656b6 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e14f81a0-setting-type-color_hue94a37f604d47f4aebf527f78c55a34e_28164_1644x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=dd9f9f6e9200471a4041914931146ab9 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e14f81a0-setting-type-color_hue94a37f604d47f4aebf527f78c55a34e_28164_1644x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=20089e026403d3ff425851295c4fda30 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e14f81a0-setting-type-color_hue94a37f604d47f4aebf527f78c55a34e_28164_1644x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=0e31f103e872b53e84a61a8544acd374 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/e14f81a0-setting-type-color_hue94a37f604d47f4aebf527f78c55a34e_28164_1644x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=5680aa01261bb318d393141fc86904e7 2500w" />
</Frame>

#### Validation

* `default` is required and must be a valid hexadecimal string

Use the color setting value in the theme by accessing the custom setting directly.

```handlebars  theme={"dark"}
<style>
    :root {
        {{#if @custom.button_color}}
        --button-bg-color: {{@custom.button_color}};
        {{/if}}
    }
</style>
```

### Image

Presents an image uploader. When output in themes, the value will be blank or a URL.

```json  theme={"dark"}
"cta_background_image": {
    "type": "image"
}
```

<Frame>
  <img src="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b5f2629f-setting-type-image_huefef4eb9ddaf1abc8b7f625866424bc8_24847_1644x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=cb9438ebef296dfbafa405f28ad71fa5" data-og-width="1644" width="1644" data-og-height="232" height="232" data-path="images/b5f2629f-setting-type-image_huefef4eb9ddaf1abc8b7f625866424bc8_24847_1644x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b5f2629f-setting-type-image_huefef4eb9ddaf1abc8b7f625866424bc8_24847_1644x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=db5f7b3bd7758af2e9de6f36e9f35440 280w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b5f2629f-setting-type-image_huefef4eb9ddaf1abc8b7f625866424bc8_24847_1644x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=d6d128fc24dbaa75d1eda54f8b47ea0f 560w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b5f2629f-setting-type-image_huefef4eb9ddaf1abc8b7f625866424bc8_24847_1644x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=e0ba6f0539d135c2aaa0f8292249d781 840w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b5f2629f-setting-type-image_huefef4eb9ddaf1abc8b7f625866424bc8_24847_1644x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=df5587166b8edd53893568f11d4d735b 1100w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b5f2629f-setting-type-image_huefef4eb9ddaf1abc8b7f625866424bc8_24847_1644x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=d0ab0ee8ac0cae028672bce5519a1f87 1650w, https://mintcdn.com/ghost/KePyCzI5-bxtjueF/images/b5f2629f-setting-type-image_huefef4eb9ddaf1abc8b7f625866424bc8_24847_1644x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=KePyCzI5-bxtjueF&q=85&s=881488e7bfd8e27fd4eebf95d85a7e07 2500w" />
</Frame>

#### Validation

* `default` is not allowed

Use the image setting value in the theme by directly accessing the setting, or use with the `{{img_url}}` helper. You can pass in dynamic image sizes, if you would like to output the image in question at a resized resolution based on your theme config.

```handlebars  theme={"dark"}
<section class="footer-cta" {{#if @custom.cta_background_image}}style="background-image: url({{@custom.cta_background_image}});"{{/if}}>
    ...
</section>

// or
<img src="{{img_url @custom.cta_background_image size="large"}}" />
```

### Text

Presents a text input. The value may be blank or free-form text.

```json  theme={"dark"}
"cta_text": {
    "type": "text",
    "default": "Sign up for more like this."
}
```

<Frame>
  <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=8188bddf1b9c1dfa7c8e5878f0438d8c" data-og-width="1644" width="1644" data-og-height="272" height="272" data-path="images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=9457e67d19baaa3aee546e1076fb8449 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=eae49e037b46679c413cac352c260417 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d705a444c800334586823da9a74525cd 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=349d564fcc0004f6b4e1cc2600607f19 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=bddd6c8ba301adaa00b14c9671159a6a 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/0b4d2770-setting-type-text_hu878685915f7c6b65155992b4a20a3eac_25477_1644x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=a0c9a8e0d96377592a83a29e78aa6bfc 2500w" />
</Frame>

#### Validation

* `default` is optional

Remember to allow a use case with no text. For example, this link will only be displayed if text has been provided:

```handlebars  theme={"dark"}
{{#if @custom.cta_text}}
    <a href="#/portal/signup">{{@custom.cta_text}}</a>
{{/if}}
```

## Fallback settings

Regardless of the Ghost version, themes providing custom settings shouldn’t look broken, and should provide a fallback when necessary.

### Creating fallbacks for text settings

The default text for a text setting should be specified in `package.json` instead of adding it in the theme code as a fallback. This allows your theme to handle blank strings in the correct way:

```json  theme={"dark"}
"cta_text": {
    "type": "text",
    "default": "Sign up now."
}
```

```handlebars  theme={"dark"}
{{#if @custom.cta_text}}
    <h2>{{@custom.cta_text}}</h2>
{{/if}}
```

The only exception is when the theme **must** have text for a specific setting. In this situation, the default should be added in the theme as a fallback with an `{{else}}` statement:

```handlebars  theme={"dark"}
<h2>
  {{#if @custom.copyright_text_override}}
		{{@custom.copyright_text_override}}
	{{else}}
		{{@site.title}} © {{date format="YYYY"}}
	{{/if}}
</h2>
```

## Setting visibility

Configure setting dependencies to ensure that only relevant settings are displayed to the user in Ghost Admin. For example, a theme may offer several different header styles: `Landing`, `Highlight`, `Magazine`, `Search`, `Off`. If that value is `Landing` or `Search`, then an additional option becomes visible in Ghost Admin that allows the use of the publication’s cover image as the background. Otherwise, the option is hidden. By configuring setting dependencies, users get a better experience by only seeing settings that are relevant.

To control when settings are visible, include the `visibility` key on the dependent setting. This key specifies the conditions that must be met for the setting to be displayed. Typically, you’ll specify the name of the parent setting and value it should have for the dependent setting to be visible. You can also use any [NQL syntax](/content-api/#filtering) for this — the same syntax used for filtering with the `get` helper.

**Example: Header style and background image**

In the following example, the `use_publication_cover_as_background` is only visible when `header_style` is `Landing` or `Search`. Note that when the visibility condition isn’t met, the dependent setting will render as `null` in the theme (i.e., `@custom.use_publication_cover_as_background` will be `null`).

```json  theme={"dark"}
{
  "header_style": {
    "type": "select",
    "options": [
      "Landing",
      "Highlight",
      "Magazine",
      "Search",
      "Off"
    ],
    "default": "Landing",
    "group": "homepage"
  },
  "use_publication_cover_as_background": {
    "type": "boolean",
    "default": false,
    "description": "Cover image will be used as a background when the header style is Landing or Search",
    "group": "homepage",
    "visibility": "header_style:[Landing, Search]"
  }
}
```

**Example: Post feed style and thumbnails**

In this example, the `show_images_in_feed` setting is only visible when `post_feed_style` is set to `List`.

```json  theme={"dark"}
{
  "post_feed_style": {
    "type": "select",
    "options": [
      "List",
      "Grid"
    ],
    "default": "List",
    "group": "homepage"
  },
  "show_images_in_feed": {
    "type": "boolean",
    "default": true,
    "description": "Toggles thumbnails of the post cards when the post feed style is List",
    "group": "homepage",
    "visibility": "post_feed_style:List"
  }
}
```

## Setting up support for custom fonts

Custom fonts allow users to select heading and body fonts for their themes from a curated list. This provides the user with a broad range of font styles so your theme can appeal to a wider audience.

<Frame>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/dd51dba9-custom-fonts_hue91cf81b8a9b6eaec2ca5d2661927ae4_1137163_2000x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9ee16f71e47827ddd3c484549a8c1d46" data-og-width="2000" width="2000" data-og-height="1137" height="1137" data-path="images/dd51dba9-custom-fonts_hue91cf81b8a9b6eaec2ca5d2661927ae4_1137163_2000x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/dd51dba9-custom-fonts_hue91cf81b8a9b6eaec2ca5d2661927ae4_1137163_2000x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=50e2713c18ef82c87b103389cae2ead6 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/dd51dba9-custom-fonts_hue91cf81b8a9b6eaec2ca5d2661927ae4_1137163_2000x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9b46830f3afe06dc10b5d97347a06f0b 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/dd51dba9-custom-fonts_hue91cf81b8a9b6eaec2ca5d2661927ae4_1137163_2000x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=9d51d94f3a84f41f4bc5fb92e220447d 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/dd51dba9-custom-fonts_hue91cf81b8a9b6eaec2ca5d2661927ae4_1137163_2000x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=6fbfa473c2d877737931fe07e6232728 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/dd51dba9-custom-fonts_hue91cf81b8a9b6eaec2ca5d2661927ae4_1137163_2000x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=94ace2cf1e95b6ff303f832f5eea4a58 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/dd51dba9-custom-fonts_hue91cf81b8a9b6eaec2ca5d2661927ae4_1137163_2000x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=061394b33fa1c345045197608b3e067c 2500w" />
</Frame>

If you’d like to give users the possibility to select custom fonts, you’ll need make sure your theme supports it.

### How custom fonts are loaded

When a custom font is selected, Ghost loads the font files on the front-end via `{{ghost_head}}` and sets up two CSS variables that reference them:

```html  theme={"dark"}
<link rel="preconnect" href="https://fonts.bunny.net">
<link rel="stylesheet" href="https://fonts.bunny.net/css?family=fira-mono:400,700|ibm-plex-serif:400,500,600">
<style>
  :root {
    --gh-font-heading: Fira Mono;
    --gh-font-body: IBM Plex Serif;
  }
</style>
```

### Applying custom font variables

To use custom fonts in your theme, apply the provided variables within your theme’s CSS file:

```css  theme={"dark"}
<style>
  body {
    font-family: var(--gh-font-body);
  }

  h1, h2, h3, h4, h5, h6 {
    font-family: var(--gh-font-heading);
  }
</style>
```

Selected font names are also injected into `{{body_class}}`, allowing you to optionally fine-tune and make adjustments to any font:

```html  theme={"dark"}
<style>
  body.gh-font-heading-ibm-plex-serif h1 {
    font-size: 12rem;
    line-height: 1.05em;
  }
</style>

<body class="gh-font-heading-fira-mono gh-font-body-ibm-plex-serif">
  ...
</body>
```

### Setting fallbacks to your theme’s own font(s)

If custom fonts aren’t set, you can provide a fallback to your theme’s own font(s):

```css  theme={"dark"}
<style>
  body {
    font-family: var(--gh-font-body, Helvetica);
  }

  h1, h2, h3, h4, h5, h6 {
    font-family: var(--gh-font-heading, var(--theme-font-heading));
  }
</style>
```

Check out any of our official themes (e.g. [Source](https://github.com/Tryghost/Source)) to see it in action.

## Guidelines for theme developers

#### Custom settings should compliment the primary use case of the theme

Ghost Themes should always have a very **clear use case** and the implementation of custom settings should compliment that use case. For example, a theme that is designed for newsletters may have custom settings to make visual changes to button colors and typography, but shouldn’t include custom settings to turn the theme into a magazine layout.

✅ **Simple visual changes** — give site owners the ability to create a great visual impact without altering the primary use-case of the theme. For example, changing colors, fonts and images.

❌ **Complex layout settings** — using custom settings to alter the primary use case of the theme results in complicated code that is harder to manage in the future.

#### Custom settings should have a very clear visual impact

Custom settings are designed to allow site owners to make meaningful customizations to their theme, without needing to edit theme files or inject code.

**The total number of settings is limited to 20!**

Use your custom settings wisely to give publishers the tools they need to define the best visual fit for their brand.

✅ **Visual brand settings** — use custom settings to make brand adjustments that have a visual impact, such as changing the color of all buttons, changing the default CTA text on the homepage, or offering a dark mode toggle.

❌ **Repeated settings** — avoid using custom settings to make micro-adjustments to single elements of a theme, such as individual buttons.

❌ **Functional settings** — avoid using custom settings to change the way a theme functions, such as changing the pagination style, or removing the primary tag from posts — these are functional settings that should be determined based on the primary use case of the theme.

#### Using custom settings for external integrations

It’s possible to use custom settings to enable third-party integrations within your theme, such as commenting systems or website analytics. To use custom settings for this purpose, site owners should be asked to enter a simple piece of information such as a tracking ID, rather than adding HTML code into a custom text setting.

✅ Enter a Disqus shortname into a custom setting, and enabling the comment system only when the shortname is provided

✅ Enter a tracking ID into a custom setting, and enabling Google Analytics only when the ID is provided

❌ Ask users to add an embed code into custom settings to make an integration function.


# GScan
Source: https://docs.ghost.org/themes/gscan

Validating your Ghost theme is handled efficiently with the GScan tool. GScan will check your theme for errors, deprecations and compatibility issues. GScan is used in several ways:

***

* The [GScan site](https://gscan.ghost.org) is your first port of call to test any themes that you’re building to get a full validation report
* When a theme is uploaded in Ghost admin, it will automatically be checked with `gscan` and any fatal errors will prevent the theme from being used
* `gscan` is also used as a command line tool

### Command line

To use GScan as a command line tool, globally install the `gscan` npm package:

```bash  theme={"dark"}
# Install the npm package
npm install -g gscan

# Use gscan <file path> anywhere to run gscan against a folder
gscan /path/to/ghost/content/themes/casper

# Run gscan on a zip file
gscan -z /path/to/download/theme.zip
```


# Helpers
Source: https://docs.ghost.org/themes/helpers

Helpers add additional functionally to Handlebars, the templating language Ghost themes use.

<CardGroup cols={1}>
  <Card title="Functional" href="/themes/helpers/functional/">
    Functional helpers are used to work with data objects. Use this reference list to discover what each handlebars helper can do when building a custom Ghost theme.
  </Card>

  <Card title="Data" href="/themes/helpers/data/">
    Data helpers are used to output data from your site. Use this reference list to discover what each handlebars helper can do when building a custom Ghost theme.
  </Card>

  <Card title="Utility" href="/themes/helpers/utility/">
    Utility helpers are used to perform minor, optional tasks. Use this reference list to discover what each handlebars helper can do when building a custom Ghost theme.
  </Card>
</CardGroup>


# Data Helpers
Source: https://docs.ghost.org/themes/helpers/data

Data helpers are used to output data from your site. Use this reference list to discover what each handlebars helper can do when building a custom Ghost theme.

| Tag                                                              | Description                                                          |
| ---------------------------------------------------------------- | -------------------------------------------------------------------- |
| [@config](/themes/helpers/data/config/)                          | Provides access to global data properties                            |
| [@custom](/themes/helpers/data/custom/)                          | Provides access to custom theme settings                             |
| [@page](/themes/helpers/data/page/)                              | Provides access to page settings                                     |
| [@site](/themes/helpers/data/site/)                              | Provides access to global settings                                   |
| [@member](/themes/members/#the-member-object)                    | Provides access to member data                                       |
| [authors](/themes/helpers/data/authors/)                         | Outputs the post author(s)                                           |
| [comments](/themes/helpers/data/comments/)                       | Outputs Ghost's member-based commenting system                       |
| [content](/themes/helpers/data/content/)                         | Outputs the full post content as HTML                                |
| [date](/themes/helpers/data/date/)                               | Outputs the date in a format of your choosing                        |
| [excerpt](/themes/helpers/data/excerpt/)                         | Outputs the custom excerpt, or the post content with HTML stripped   |
| [social\_url](/themes/helpers/data/social_url/)                  | Outputs the full URL to a social profile                             |
| [img\_url](/themes/helpers/data/img_url/)                        | Outputs the correctly calculated URL for the provided image property |
| [link](/themes/helpers/data/link/)                               | Creates links with dynamic classes                                   |
| [meta\_data](/themes/helpers/data/meta_data/)                    | Outputs structured data for SEO                                      |
| [navigation](/themes/helpers/data/navigation/)                   | Helper which outputs formatted HTML for navigation links             |
| [post](/themes/helpers/data/post/)                               | More `object` than helper – Contains all data for a specific post    |
| [price](/themes/helpers/data/price/)                             | Outputs a price with formatting options                              |
| [readable\_url](/themes/helpers/data/readable_url/)              | Returns a human-readable URL                                         |
| [recommendations](/themes/helpers/data/recommendations/)         | Outputs a list of recommended sites                                  |
| [tags](/themes/helpers/data/tags/)                               | Outputs the post tags                                                |
| [tiers](/themes/helpers/data/tiers/)                             | Outputs the post tier(s)                                             |
| [title](/themes/helpers/data/title/)                             | The post title, when inside the `post` scope                         |
| [total\_members](/themes/helpers/data/total_members/)            | Outputs the number of members, rounded and humanised                 |
| [total\_paid\_members](/themes/helpers/data/total_paid_members/) | Outputs the number of paying members, rounded and humanised          |
| [url](/themes/helpers/data/url/)                                 | The post URL, when inside the `post` scope                           |


# authors
Source: https://docs.ghost.org/themes/helpers/data/authors



***

`{{authors}}` is a formatting helper for outputting a linked list of authors for a particular post. It defaults to a comma-separated list (without list markup) but can be customised to use different separators, and the linking can be disabled. The authors are output in the order they appear on the post, these can be reordered by dragging and dropping.

You can use the [translation helper](/themes/helpers/utility/translate/) for the `prefix` and `suffix` attribute.

### Example code

The basic use of the authors helper will output something like ‘sam, carl, tobias’ where each author is linked to its own author page:

```handlebars  theme={"dark"}
{{authors}}
```

You can customise the separator between authors. The following will output something like ‘sam | carl | tobias’

```handlebars  theme={"dark"}
{{authors separator=" | "}}
```

Additionally you can add an optional prefix or suffix. This example will output something like ‘More about: sam, carl, tobias’.

```handlebars  theme={"dark"}
{{authors separator=" | " prefix="More about:"}}
```

You can use HTML in the separator, prefix and suffix arguments. So you can achieve something like ‘sam • carl • tobias’.

```handlebars  theme={"dark"}
{{authors separator=" • "}}
```

If you don’t want your list of authors to be automatically linked to their author pages, you can turn this off:

```handlebars  theme={"dark"}
{{authors autolink="false"}}
```

If you want to output a fixed number of authors, you can add a `limit` to the helper. E.g. adding a limit of 1 will output just the first author:

```handlebars  theme={"dark"}
{{authors limit="1"}}
```

If you want to output a specific range of authors, you can use `from` and `to` either together or on their own. Using `to` will override the `limit` attribute.

E.g. using from=“2” would output all authors, but starting from the second author:

```handlebars  theme={"dark"}
{{authors from="2"}}
```

E.g. setting both from and to to `1` would do the same as limit=“1”

`{{authors from="1" to="1"}}` is the same as `{{authors limit="1"}}`

## The `visibility` attribute

As of Ghost 0.9 posts, tags and users all have a concept of `visibility`, which defaults to `public`.

By default the `visibility` attribute is set to the string “public”. This can be overridden to pass any other value, and if there is no matching value for `visibility` nothing will be output. You can also pass a comma-separated list of values, or the value “all” to output all items.

```handlebars  theme={"dark"}
{{authors visibility="all"}}
```

### Advanced example

If you want to output your authors completely differently, you can fully customise the output by using the foreach helper, instead of the authors helper. Here’s an example of how to output list markup:

```handlebars  theme={"dark"}
{{#post}}
  {{#if authors}}
    <ul>
    {{#foreach authors}}
      <li>
        <a href="{{url}}" title="{{name}}" class="author author-{{id}} {{slug}}">{{name}}</a>
      </li>
    {{/foreach}}
    </ul>
  {{/if}}
{{/post}}
```

### List of author attributes

* **id** - the incremental ID of the author
* **name** - the name of the author
* **slug** - slugified version of the name (used in urls and also useful for class names)
* **bio** - a bio of the author
* **website** - the website of the author
* **location** - the location of the author
* **twitter** - the author’s twitter username
* **facebook** - the author’s facebook username
* **profile\_image** - the profile image for the author
* **cover\_image** - the cover image for the author
* **meta\_title** - the tag’s meta title
* **meta\_description** - the tag’s meta description
* **url** - the web address for the tag’s page

## primary\_author

To output just the singular, first author, use the `{{primary_author}}` helper to output a simple link. You can also access all the same attributes as above if you need more custom output.

```handlebars  theme={"dark"}
{{#primary_author}}
<div class="author">
    <a href="{{url}}">{{name}}</a>
    <span class="bio">{{bio}}</span>
</div>
{{/primary_author}}
```


# comments
Source: https://docs.ghost.org/themes/helpers/data/comments

Usage: `{{comments}}`

***

The `{{comments}}`helper outputs Ghost’s member-based commenting system. [Learn more about comments.](https://ghost.org/help/commenting)

Comments are visibleonly when they have been (1) enabled by the publication owner and (2) the person visiting the page has access to the post.

### Basic example

```handlebars  theme={"dark"}
{{comments}}
```

By default,`{{comments}}`outputs a title and comment count. These elements, along with the color mode and the saturation of the avatar's background color, can be customized via attributes.

## Attributes

| Name         | Description                               | Options              | Default                                                        |
| ------------ | ----------------------------------------- | -------------------- | -------------------------------------------------------------- |
| `title`      | Header text for comment section           | Any string           | Member discussion                                              |
| `count`      | Boolean to toggle comment count on or off | `true` or `false`    | `true`                                                         |
| `mode`       | Set light or dark mode for comments       | auto, light, or dark | auto (determined by the parent element's CSS `color` property) |
| `saturation` | Set saturation of avatar background color | `number`             | `60`                                                           |

### Example with attributes

```handlebars  theme={"dark"}
{{comments title="Join the club" count=false mode="light" saturation=80}}
{{! Customizes header text, hides comment count, sets element to light mode and avatar background color saturation to 80% }}
```

## Comment count

Use`{{comment_count}}`to output the number of comments a post has. This option is useful for displaying the comment count on the homepage or at the top of the post. Developers can also use it to customize the output of the`{{comments}}`helper.

### Attributes

| Name       | Description                               | Options               | Default                                        |
| ---------- | ----------------------------------------- | --------------------- | ---------------------------------------------- |
| `singular` | The singular name for a comment           | Any string            | comment                                        |
| `plural`   | The plural name for comments              | Any string            | comments                                       |
| `empty`    | What to output when there are no comments | Any string            | Output is empty when comment count equals zero |
| `autowrap` | Wraps comment count in an HTML tag        | `HTML tag` or `false` | `span`                                         |
| `class`    | Add a custom class to wrapper element     | Any string            | ""                                             |

### Examples

```handlebars  theme={"dark"}
{{comment_count empty="" singular="comment" plural="comments" autowrap="span" class=""}}
{{! default output: <span>5 comments</span> }}

{{comment_count singular="" plural=""}}
{{! output: <span>5</span> }}

{{comment_count empty="0"}}
{{! output: <span>0</span>. (The default is an empty output.) }}

{{comment_count autowrap="div" class="style-me"}}
{{! output: <div class="style-me">5 comments</span> }}

{{comment_count autowrap="false"}}
{{! output: 5 comments (just text!) }}
```

## Additional customization

Use the `comments` helper with `{{#if}}` for more granular control over output. `{{#if comments}}` returns true when (1) comments have been enabled and (2) the reader has access to the post.

### Advanced example

```handlebars  theme={"dark"}
{{#if comments}}
   <h2>Discussion</h2>
   <a href="/guides">Community guidelines</a>
   {{comment_count}}
   {{comments title="" count=false mode="light" saturation=80}}
{{/if}}
```


# @config
Source: https://docs.ghost.org/themes/helpers/data/config

The `@config` property provides access to global data properties, which are available anywhere in your theme.

***

Specifically `@config` will pass through the special theme config that is added in the theme’s `package.json` so that it can be used anywhere in handlebars.

At the moment, there is only one property which will be passed through, as all other [properties](/themes/structure/#additional-properties) are accessed with their own helpers.

* `{{@config.posts_per_page}}` – the number of posts per page

### Example Code

Standard usage:

```handlebars  theme={"dark"}
<a href="{{page_url "next"}}">Show next {{@config.posts_per_page}} posts</a>
```

In the get helper limit field:

```handlebars  theme={"dark"}
{{#get "posts" filter="featured:true" limit=@config.posts_per_page}}
  {{#foreach posts}}
      <h1>{{title}}</h1>
	{{/foreach}}
{{/get}}
```

### Providing config

Config values can be provided by adding a `config` block to package.json

```json  theme={"dark"}
{
  "name": "my-theme",
  "version": 1.0.0,
  "author": {
    "email": "my@address.here"
  }
  "config": {
  }
}
```

There are currently four properties supported:

* `config.posts_per_page` — the default number of posts per page is 5
* `config.image_sizes` — see the [assets](/themes/assets/) guide for more details on responsive images
* `config.card_assets` — configure the [card CSS and JS](/themes/content/#editor-cards) that Ghost automatically includes
* `config.custom` - add [custom settings](/themes/custom-settings/) to your theme


# content
Source: https://docs.ghost.org/themes/helpers/data/content

Usage: `{{content}}`

***

`{{content}}` is a very simple helper used for outputting post content. It makes sure that your HTML gets output correctly.

You can limit the amount of HTML content to output by passing one of the options:

`{{content words="100"}}` will output just 100 words of HTML with correctly matched tags.

#### Default CTA

For visitors to members-enabled sites who don’t have access to the post in the current context, the `{{content}}` helper will output a [default upgrade/sign up CTA](/themes/members/#default-cta).


# @custom
Source: https://docs.ghost.org/themes/helpers/data/custom

The `@custom` property provides access to custom theme settings, which are available anywhere in your theme.

***

The attributes of the `@custom` property are set by individual themes in the `package.json` file. Depending on the type of setting, the `@custom` property can then be used with the `{{#if}}` or `{{#match}}` helpers to customise the theme behaviour based on user settings.

### Example code

```html  theme={"dark"}
<body class="{{body_class}} {{#match @custom.typography "Elegant serif"}}font-alt{{/match}}">
    ...
    <section class="footer-cta">
        {{#if @custom.cta_text}}<h2>{{@custom.cta_text}}</h2>{{/if}}
        <a href="#portal/signup">Sign up now</a>
    </section>
</body>
```

More information about creating and working with custom theme settings can be found [here](/themes/custom-settings/).


# date
Source: https://docs.ghost.org/themes/helpers/data/date

Usage: `{{date value format="formatString"}}`

***

`{{date}}` is a formatting helper for outputting dates in various formats. You can either pass it a date and a format string to be used to output the date like so:

```handlebars  theme={"dark"}
<!-- outputs something like 'July 11, 2016' -->
{{date published_at format="MMMM DD, YYYY"}}
```

See the [Moment.js Display tokens](https://momentjs.com/docs/#/displaying/format/) for more options.

Timezone and locale may be overridden from your site’s defaults by passing the `timezone` and `locale` parameters:

```handlebars  theme={"dark"}
<!-- outputs something like 'mar., 31 déc. 2013 22:58:58 +0100' -->
{{date published_at locale="fr-fr" timezone="Europe/Paris"}}
```

Or you can pass it a date and the `timeago` flag:

```handlebars  theme={"dark"}
<!-- outputs something like '5 mins ago' -->
{{date published_at timeago="true"}}
```

If you use the `timeago` flag on a site that uses caching - as on [Ghost(Pro)](https://ghost.org/pricing/) - dates will be displayed relative to when the page gets cached rather than relative to the visitor’s current time.

If you call `{{date}}` without a format, it will default to a short localised format, `ll`.

If you call `{{date}}` without telling it which date to display, it will default to one of two things:

1. If there is a `published_at` property available (i.e. you’re inside a post object) it will use that
2. Otherwise, it will default to the current date

`date` uses moment.js for formatting dates. See their documentation for a full explanation of all the different format strings that can be used.

### Example Code

```handlebars  theme={"dark"}
<main role="main">
  {{#foreach posts}}
    <h2><a href="{{url}}">{{title}}</a></h2>

   <p>{{excerpt words="26"}}</p>

    {{!-- Here `published_at` is set, so this will show the article date --}}
    <time datetime="{{date format="YYYY-MM-DD"}}">{{date format="DD MMMM YYYY"}}</time>
  {{/foreach}}
</main>
<footer>
  {{!-- Here there is no `published_at` so this will show the current year --}}
  <p class="small">© {{date format="YYYY"}}</p>
</footer>
```


# excerpt
Source: https://docs.ghost.org/themes/helpers/data/excerpt

Usage: `{{excerpt}}`

***

`{{excerpt}}` outputs content but strips all HTML. This is useful for creating excerpts of posts.

If the post’s `custom_excerpt` property is set, then the helper will always output the `custom_excerpt` content ignoring the `words` & `characters` attributes.

When both `html` and `custom_excerpt` properties are not set (for example, when member content gating strips the `html`) the output is generated from post’s `excerpt` property.

You can limit the amount of text to output by passing one of the options:

`{{excerpt characters="140"}}` will output 140 characters of text (rounding to the end of the current word).


# img_url
Source: https://docs.ghost.org/themes/helpers/data/img_url

Usage: `{{img_url value}}`

***

The img url helper outputs the correctly calculated URL for the provided image property.

You **must** tell the `{{img_url}}` helper which image you would like to output. For example, to output a URL for a post’s feature image inside of post.hbs, use `{{img_url feature_image}}`.

Force the image helper to output an absolute URL by using the absolute option: `{{img_url profile_image absolute="true"}}`. This is almost never needed.

To output the image in question at a resized resolution based on your theme config, pass in [dynamic image sizes](/themes/responsive-images/) via the `size` option.

Convert an image to a different image format (`webp`, `avif`, `png`, `jpg`, `jpeg`, or `gif`) by using the `format` option. (This only works in combination with the `size` option.)

## Example code

Below is a set of examples of how to output various images that belong to posts, authors, or keywords:

```handlebars  theme={"dark"}
{{#post}}

  {{!-- Outputs post's feature image if there is one --}}
  {{#if feature_image}}
      <img src="{{img_url feature_image}}">
  {{/if}}

  {{!-- Output feature image at small size from theme package.json --}}
  <img src="{{img_url feature_image size="small"}}">

  {{!-- Output feature image at small size, formatted as a WebP image (size is required) --}}
  <img src="{{img_url feature_image size="small" format="webp"}}">

  {{!-- Output post author's profile image as an absolute URL --}}
  <img src="{{img_url author.profile_image absolute="true"}}">

  {{!-- Open author context instead of providing full path --}}
  {{#author}}
      <img src="{{img_url profile_image}}">
  {{/author}}

{{/post}}
```


# link
Source: https://docs.ghost.org/themes/helpers/data/link

Usage: `{{#link href="/about/"}}About{{/link}}`

***

`{{#link}}` is a block helper that creates links with dynamic classes. In its basic form it will create an anchor element that wraps around any kind of string, HTML or handlebars constructed HTML.

With additional options it can have an active `class` or `target` behaviour, or `onclick` JavaScript events. A `href` attribute must be included or an error will be thrown.

## Simple example

```handlebars  theme={"dark"}
{{#link href="/about/"}}..linked content here..{{/link}}

Will output:

<a href="/about/">..linked content here..</a>
```

All attributes associated with the `<a></a>` element can be used in `{{#link}}`. Check out the MDN documentation on [the anchor element for more information](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a).

## Variables

Handlebars variables can be used for attribute values as well as strings. Variables do not need be wrapped with quotations:

### Simple variables example

```handlebars  theme={"dark"}
{{#link href=@site.url}}Home{{/link}}
```

### Advanced variables example

```handlebars  theme={"dark"}
{{#foreach posts}}
  {{#link href=(url) class="post-link" activeClass="active"}}
    {{title}}
  {{/link}}
{{/foreach}}
```

## Dynamic attributes

### `activeClass`

By default the active class outputted by `{{#link}}` will be `nav-current`, this is consistent with our [navigation helper](/themes/helpers/data/navigation/). However it can be overwritten with the `activeClass` attribute:

### `activeClass` Example

```handlebars  theme={"dark"}
{{#link href="/about/" activeClass="current"}}About{{/link}}

When on the "/about/" URL it will output:

<a href="/about/" class="current">About</a>
```

`activeClass` can also be given `false` value (`activeClass=false`), which will output an empty string. Effectively turning off the behaviour.


# meta data
Source: https://docs.ghost.org/themes/helpers/data/meta_data

Usage: `{{meta_title}}` and `{{meta_description}}` and `{{canonical_url}}`

***

Ghost generates automatic meta data by default, but it can be overridden with custom content in the post settings menu. Meta data is output by default in [ghost\_head](/themes/helpers/utility/ghost_head_foot/), and can also be used in themes with the following helpers:

* `{{meta_title}}` – the meta title specified for the post or page in the post settings
* `{{meta_description}}` – the meta description specified for the post or page in the post settings
* `{{canonical_url}}` – the custom canonical URL set for the post


# navigation
Source: https://docs.ghost.org/themes/helpers/data/navigation

Usage: `{{navigation}}` and `{{navigation type="secondary"}}`

***

`{{navigation}}` is a template-driven helper which outputs formatted HTML of menu items defined in the Ghost admin panel (Settings > Design > Navigation). By default, the navigation is marked up using a [preset template](https://github.com/TryGhost/Ghost/blob/3d989eba2371235d41468f7699a08e46fc2b1e87/ghost/core/core/frontend/helpers/tpl/navigation.hbs).

There are two types of navigation, primary and secondary, which you can access using `{{navigation}}` and `{{navigation type="secondary"}}`.

### Default template

By default, the HTML output by including `{{navigation}}` in your theme, looks like the following:

```html  theme={"dark"}
<ul class="nav">
    <li class="nav-home nav-current"><a href="/">Home</a></li>
    <li class="nav-about"><a href="/about/">About</a></li>
    <li class="nav-contact"><a href="/contact/">Contact</a></li>
    ...
</ul>
```

### Changing The Template

If you want to modify the default markup of the navigation helper, this can be achieved by creating a new file at `./partials/navigation.hbs`. If this file exists, Ghost will load it instead of the default template. Example:

```handlebars  theme={"dark"}
<div class="my-fancy-nav-wrapper">
    <ul class="nav">
        <!-- Loop through the navigation items -->
        {{#foreach navigation}}
        <li class="nav-{{slug}}{{#if current}} nav-current{{/if}}"><a href="{{url absolute="true"}}">{{label}}</a></li>
        {{/foreach}}
        <!-- End the loop -->
    </ul>
</div>
```

Creating a new `navigation.hbs` will overwrite both the main navigation as and secondary navigation. To customise the secondary navigation differently use the `{{#if isSecondary}}...{{/if}}` helper. Example:

```handlebars  theme={"dark"}
{{#if isSecondary}}
    <ul class="nav" role="menu">
        {{#foreach navigation}}
            <li class="nav-{{slug}}" role="menuitem">
                <a href="{{url}}">
                    <svg class="icon" role="img" aria-label="{{slug}} icon">
                        <title>{{slug}}</title>
                        <use xlink:href="#{{slug}}"></use>
                    </svg>
                </a>
            </li>
        {{/foreach}}
    </ul>
{{else}}
    <ul class="nav" role="menu">
        {{#foreach navigation}}
            <li class="{{link_class for=(url) class=(concat "nav-" slug)}}" role="menuitem">
                <a href="{{url absolute="true"}}">{{label}}</a>
            </li>
        {{/foreach}}
    </ul>
{{/if}}
```

The up-to-date default template in Ghost is always available [here](https://github.com/TryGhost/Ghost/blob/3d989eba2371235d41468f7699a08e46fc2b1e87/ghost/core/core/frontend/helpers/tpl/navigation.hbs).

### List of Attributes

A navigation item has the following attributes which can be used inside your `./partials/navigation.hbs` template file…

* **\{\{label}}** - The text to display for the link
* **\{\{url}}** - The URL to link to - see the url helper for more options
* **\{\{current}}** - Boolean true / false - whether the URL matches the current page
* **\{\{slug}}** - Slugified name of the page, eg `about-us`. Can be used as a class to target specific menu items with CSS or jQuery.

These attributes can only be used inside the `{{#foreach navigation}}` loop inside `./partials/navigation.hbs`. A navigation loop will not work in other partial templates or theme files.

### Examples

The navigation helper doesn’t output anything if there are no navigation items to output, so there’s no need to wrap it in an `{{#if}}` statement to prevent an empty list. However, it’s a common pattern to want to output a link to open the main menu, but only if there are items to show.

The data used by the `{{navigation}}` helper is also stored as a global variable called `@site.navigation`. You can use this global variable in any theme file to check if navigation items have been added by a user in the Ghost admin panel.

```handlebars  theme={"dark"}
{{#if @site.navigation}}
    <a class="menu-button" href="#"><span class="word">Menu</span></a>
{{/if}}
```

This is also possible with the secondary navigation:

```handlebars  theme={"dark"}
{{#if @site.secondary_navigation}}
    <a class="menu-button" href="#"><span class="word">Menu</span></a>
{{/if}}
```


# @page
Source: https://docs.ghost.org/themes/helpers/data/page

The `@page` object provides access to page properties, which are available anywhere in your theme.

***

* `@page.show_title_and_feature_image` - true (default) or false value from Ghost Editor

This toggle, only available for pages, lets users hide a page’s title and feature image to create pages that look radically different than posts (for example, full-width headers, CTAs, and landing pages).

This setting is only available when using the [new Beta editor](https://ghost.org/changelog/editor-beta/). However, since the `@page.show_title_and_feature_image` is always present and defaults to `true`, supporting this feature in your theme won’t break anything for anyone using the old editor.

Using the `@page` object is **not backward-compatible** with earlier versions of Ghost: once implemented the theme will only be compatible with Ghost 5.54.1 or later.

## Example code

```handlebars  theme={"dark"}
{{#match @page.show_title_and_feature_image}}
...content...
{{/match}}
```

## Styling tips when hiding the title and feature image

1. Whenever the page title and feature image are hidden, and the page content starts with a full-width card (such cards will have the class `.kg-width-full`), remove spacing between the top navigation and content (on pages only).
2. Whenever multiple full-width cards are stacked, remove spacing between them (on posts and pages).
3. Whenever content ends with a full-width card, remove spacing between the content and the footer (on pages only, posts often have additional content at the bottom such as comments, CTAs, related posts, etc.).

As a reminder, cards that have the ability to be set to full width are header cards, signup cards, image cards, and video cards. When an image or video has a caption, it will have the class `.kg-card-hascaption`, and maintaining spacing is desirable in this case.

The implementation of these changes will look different on every theme. Find examples of these recommended changes in Casper [here](https://github.com/TryGhost/Casper/commit/d9c9390e17c1df1322ebfec774886058a56a0891) (1 and 3) and [here](https://github.com/TryGhost/Casper/blob/a60e3e976a341df462ba948d395bc52c37faffa4/assets/css/screen.css#L1345-L1348) (2).


# post
Source: https://docs.ghost.org/themes/helpers/data/post

Usage: `{{#post}}{{/post}}` or `{{#foreach posts}}{{/foreach}}`

***

When on a single post template such as `post.hbs` or `page.hbs`, outputting the details of your posts can be done with a block expression.

The block expression `{{#post}}{{/post}}` isn’t strictly a ‘helper’. You can do this with any object in a template to access the nested attributes e.g. you can also use `{{#primary_author}}{{/primary_author}}` inside of the post block to get to the primary author’s name and other attributes.

When inside a post list such as `index.hbs` or `tag.hbs` where there is more than one post, it is common to use the `{{#foreach post}}{{/foreach}}` to iterate through the list.

When inside a `{{#foreach posts}}{{/foreach}}` or `{{#post}}{{/post}}` block (i.e. when inside the post scope), theme authors have access to all of the properties and helpers detailed on this page.

## Post Attributes

The full list of post attributes and more information about outputting posts can be found in the post context documentation.

## Static pages

When outputting a static page, you can use the same `{{#post}}{{/post}}` block expression, and all the same helpers you can use for a post.

## Featured posts

Featured posts get an extra class so that they can be styled differently. They are not moved to the top of the post list or displayed separately to the normal post list.

Use `{{#if featured}}{{/if}}` to test if the current post is featured.


# price
Source: https://docs.ghost.org/themes/helpers/data/price

Usage: `{{price plan}}`

***

The `{{price}}` helper formats monetary values from their smallest denomination to a human readable denomination with currency formatting. Example:

```handlebars  theme={"dark"}
{{price plan}}
```

This will output `$5`.

The `{{price}}` helper accepts a number of optional attributes:

* `currency` - defaults to `plan.currency` when passed a `plan` object
* `locale` - defaults to `@site.locale`
* `numberFormat` - defaults to “short”, and can be either “short” (\$5) or “long” (\$5.00)
* `currencyFormat` - defaults to “symbol” and can be one of “symbol” (\$5), “code” (EUR 5) or “name” (5 euros)

`{{price}}` can be used with static values as well, `{{price 4200}}` will output `42`.

The default behaviour of the `price` helper is the same as:

```handlebars  theme={"dark"}
{{price plan.amount
  currency=plan.currency
  locale=@site.locale
  numberFormat="short"
  currencyFormat="symbol"
}}
```

Passing a `currency` without a price will output the symbol for that currency:

```handlebars  theme={"dark"}
{{price currency="USD"}} <!-- Outputs: $ -->
```

### Example Code

Outputting prices for all tiers.

```handlebars  theme={"dark"}
{{#get "tiers" include="monthly_price,yearly_price,benefits" limit="100" as |tiers|}}
    {{! Loop through our tiers collection }}
    {{#foreach tiers}}
        {{#if monthly_price}}
            <div>
                <a href="javascript:" data-portal="signup/{{id}}/monthly">Monthly – {{price monthly_price currency=currency}}</a>
            </div>
        {{/if}}
          {{#if yearly_price}}
            <div>
                <a href="javascript:" data-portal="signup/{{id}}/monthly">Monthly – {{price yearly_price currency=currency}}</a>
            </div>
        {{/if}}

    {{/foreach}}
{{/get}}
```

Outputting prices for a member’s subscriptions.

```html  theme={"dark"}
<!-- account.hbs -->

{{#foreach @member.subscriptions}}
  <div class="subscription">
    <label class="subscriber-detail-label">Your plan</label>
    <span class="subscriber-detail-content">{{price plan}}/{{plan.interval}}</span>
  </div>
{{/foreach}}
```


# readable_url
Source: https://docs.ghost.org/themes/helpers/data/readable_url

Usage: `{{readable_url URL}}`

***

The `readable_url` helper outputs a human-readable URL by stripping out its protocol, www, query paramters, and hash fragments. It doesn’t strip out any subdomains or pathnames. This helper pairs well with the [`recommendations` helper](/themes/helpers/data/recommendations) to output more readable URLs.

See the examples below to understand the helper’s expected output:

```handlebars  theme={"dark"}
{{readable_url "https://google.com"}}
<!-- removes the "https://" protocol. Outputs: "google.com" -->

{{readable_url "www.google.com"}}
<!-- removes "www". Outputs: "google.com" -->

{{readable_url "https://google.com?foo=bar&dog=love"}}
<!-- removes query parameters. Outputs: "google.com" -->

{{readable_url "https://google.com#section-1"}}
<!-- removes hash fragments. Outputs: "google.com" -->

{{readable_url "https://ghost.org/about"}}
<!-- pathnames are not removed. Outputs: "ghost.org/about" -->

{{readable_url "https://account.ghost.org"}}
<!-- subdomains are not removed. Outputs: "account.ghost.org" -->
```


# recommendations
Source: https://docs.ghost.org/themes/helpers/data/recommendations

Usage: `{{recommendations}}`

***

Use the `{{recommendations}}` helper anywhere in a theme to output a list of recommended sites as configured in Ghost Admin.

## Default template

Ghost uses the following [default template](https://github.com/TryGhost/Ghost/blob/e8fec418227085d1418f45b49e800c753c40fa83/ghost/core/core/frontend/helpers/tpl/recommendations.hbs) to render recommendations.

```handlebars  theme={"dark"}
{{#if recommendations}}
    <ul class="recommendations">
        {{#each recommendations as |rec|}}
        <li class="recommendation">
            <a href="{{rec.url}}" data-recommendation="{{rec.id}}" target="_blank" rel="noopener">
                <div class="recommendation-favicon">
                    {{#if rec.favicon}}
                        <img src="{{rec.favicon}}" alt="{{rec.title}}" loading="lazy" onerror="this.style.display='none';">
                    {{/if}}
                </div>
                <h5 class="recommendation-title">{{rec.title}}</h5>
                <span class="recommendation-url">{{readable_url rec.url}}</span>
                <p class="recommendation-description">{{rec.description}}</p>
            </a>
        </li>
        {{/each}}
    </ul>
{{/if}}
```

The template loops over recommendations and outputs an HTML list item for each recommendation. Use the CSS class names to style the content.

Alternatively, override the default template altogether with a custom one by adding a file called `recommendations.hbs` to the theme’s `partials` folder.

When building a custom template, the `recommendation` object contains the following data:

* `id`: Recommendation ID used to track the number of clicks.
* `url`: The recommended site’s URL. Use the [`readable_url` helper](/themes/helpers/data/readable_url) to make a more human-readable URL.
* `favicon`: The recommended site’s favicon, output as an image URL
* `featured_image`: The recommended site’s feature image, output as an image URL
* `title`: The recommended site’s title
* `description`: The recommended site’s description
* `created_at`: The date the recommendation was created
* `updated_at`: The date the recommendation was updated

## Attributes

Combine the `{{recommendations}}` helper with the attributes listed below to customize its behavior.

### Limit

Specify the maximum number of recommendations to display. The default is 5.

```handlebars  theme={"dark"}
{{recommendations limit="10"}}
<!-- outputs 10 recommendations -->
```

### Order

Order recommendations based on any valid resource field (like `title`) in ascending (`asc`) or descending (`desc`) order. The default order is `created_at desc` (or newest recommendations on top).

```handlebars  theme={"dark"}
{{recommendations order="title asc"}}
<!-- outputs recommendations by title in alphabetical order -->
```

### Page

When the total number of recommendations exceeds the number defined in `limit`, recommendations become paginated. Use the `page` attribute to access subsequent pages of recommendations.

```handlebars  theme={"dark"}
{{recommendations limit="5" page="2"}}
<!-- outputs the second page of recommendations when total recommendations are greater than 5 -->
```

### Filter

Use logic-based queries to filter recommendations. For a guide to filtering syntax, see our [Content API docs](/content-api/#filtering).

```handlebars  theme={"dark"}
{{recommendations filter="favicon:-null"}}
<!-- only output recommendations with a favicon >
```

## Advanced options

### Only show recommendations when enabled

Use `@site.recommendations_enabled` to only show recommendations when they’ve been enabled in Ghost Admin. This is useful when adding additional markup that should only be shown when recommendations are enabled:

```handlebars  theme={"dark"}
{{#match @site.recommendations_enabled}}
    <h2>Recommendations</h2>
    {{recommendations}}
{{/match}}
```

### Open the recommendations modal

When Portal is enabled on a Ghost site, recommendations are displayed at `site.com/#/portal/recommendations`. Let users open the recommendations modal by adding the `data-portal="recommendations"` attribute to a button.

```handlebars  theme={"dark"}
{{recommendations limit="5"}}
<!-- outputs 5 recommendations -->

<button data-portal="recommendations">Show all recommendations</button>
<!-- open the recommendations portal when clicked -->
```


# @site
Source: https://docs.ghost.org/themes/helpers/data/site

The `@site` property provides access to global settings, which are available anywhere in your theme:

***

* `{{@site.accent_color}}` - Hex code for the theme’s accent color as [defined in Design settings](https://ghost.org/help/branding-settings/#accent-colour)
* `{{@site.codeinjection_head}}` - Site header global code injection
* `{{@site.codeinjection_foot}}` - Site footer global code injection
* `{{@site.cover_image}}` – Site cover image from General settings
* `{{@site.description}}` – Site description from General settings
* `{{@site.facebook}}` – Facebook URL from General settings
* `{{@site.icon}}` - Publication icon from General settings
* `{{@site.locale}}` - Configured site language.
* `{{@site.logo}}` – Site logo from General settings
* `{{@site.navigation}}` – Navigation information configured in Navigation settings
* `{{@site.timezone}}` – Timezone as configured in General settings
* `{{@site.title}}` – Site title from General settings
* `{{@site.twitter}}` – Twitter URL from General settings
* `{{@site.url}}` – URL specified for this site in your custom config file

### Example Code

```html  theme={"dark"}
<!-- default.hbs -->
<html lang="{{@site.locale}}">
...

<nav class="main-nav overlay clearfix">
    {{#if @site.logo}}
        <a class="blog-logo" href="{{@site.url}}"><img src="{{@site.logo}}" alt="Blog Logo" /></a>
    {{/if}}
    <a class="subscribe-button icon-feed" href="{{@site.url}}/rss/">Subscribe</a>
 </nav>

 ...

</html>
```

## @site member data and options

The `@site` helper offers data related to membership

* `{{@site.allow_self_signup}}` - True if new members can sign up themselves (membership is not private or turned off)
* `{{@site.comments_access}}` - Level of membership required to comment (`all`, `paid`, `off`)
* `{{@site.comments_enabled}}` - True if comments enabled
* `{{@site.members_enabled}}` - True if subscription access is not set to “Nobody”
* `{{@site.members_invite_only}}` - True if subscription access is set to “Only people I invite”
* `{{@site.members_support_address}}` - Email set for member support
* `{{@site.paid_members_enabled}}` - True if members is enabled and Stripe is connected
* `{{@site.portal_button_icon}}` - Image URL when using a custom Portal button icon
* `{{@site.portal_button_signup_text}}` - Sign-up text for the Portal button
* `{{@site.portal_button_style}}` - Portal button style (`Icon and text`, `Icon only`, or `Text only`)
* `{{@site.portal_button}}` - True if Portal button is enabled
* `{{@site.portal_name}}` - True if name field is included in signup form
* `{{@site.portal_plans}}` - Portal plan names
* `{{@site.recommendations_enabled}}` - True if recommendations are enabled
* `{{@site.portal_signup_checkbox_required}}` - True if signup requires accepting agreement to terms
* `{{@site.portal_signup_terms_html}}` - HTML of the signup terms as set in Portal
* `{{@site.signup_url}}` - URL for members signup via Portal or Feedly RSS subscription based on subscription access setting

### Example code

```html  theme={"dark"}
{{#unless @site.members_invite_only}}
<form data-members-form>
  <input data-members-email type="email" required="true"/>
  <button type="submit">Continue</button>
</form>
{{/if}}
```

## @site meta data

The `@site` helper provides more extensive attributes around site metadata as well. The `@site` meta data values can be set in the Ghost admin under Site Meta Settings within General Settings:

* `{{@site.meta_title}}` – Site meta title
* `{{@site.meta_description}}` – Site meta description
* `{{@site.twitter_image}}` – Site Twitter card image
* `{{@site.twitter_title}}` – Site Twitter card title
* `{{@site.twitter_description}}` – Site Twitter card description
* `{{@site.og_image}}` – Site open graph image (used when shared on Facebook and across the web)
* `{{@site.og_title}}` – Site open graph title (used when shared on Facebook and across the web)
* `{{@site.og_description}}` – Site open graph description (used when shared on Facebook and across the web)

Here’s how these helpers correspond with the settings in the Ghost admin:

<Frame>
  <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4e85d8e6-site-meta-settings_hubfec6e8b851ef54ba239915a235e7831_581483_1894x0_resize_q100_h2_box.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=e3b7cc922ab3fdd29dde05dcdac02335" data-og-width="1894" width="1894" data-og-height="3409" height="3409" data-path="images/4e85d8e6-site-meta-settings_hubfec6e8b851ef54ba239915a235e7831_581483_1894x0_resize_q100_h2_box.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4e85d8e6-site-meta-settings_hubfec6e8b851ef54ba239915a235e7831_581483_1894x0_resize_q100_h2_box.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=87a6021edb4a365b9b3dffb9a0d2348d 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4e85d8e6-site-meta-settings_hubfec6e8b851ef54ba239915a235e7831_581483_1894x0_resize_q100_h2_box.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=80f5d75240e04f6d5c69074d2b01c2e8 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4e85d8e6-site-meta-settings_hubfec6e8b851ef54ba239915a235e7831_581483_1894x0_resize_q100_h2_box.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=df55266e1b9402e8bcb491743b8f3e93 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4e85d8e6-site-meta-settings_hubfec6e8b851ef54ba239915a235e7831_581483_1894x0_resize_q100_h2_box.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=a7e85785c4f966e8eba33aa796958d6e 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4e85d8e6-site-meta-settings_hubfec6e8b851ef54ba239915a235e7831_581483_1894x0_resize_q100_h2_box.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=142eea81da21bd11f9fe045093d489f6 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4e85d8e6-site-meta-settings_hubfec6e8b851ef54ba239915a235e7831_581483_1894x0_resize_q100_h2_box.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=0992dfd06ad62b798158c6f77d1e48f8 2500w" />
</Frame>


# social_url
Source: https://docs.ghost.org/themes/helpers/data/social_url

Usage: `{{social_url type="platform"}}` (e.g., `{{social_url type="facebook"}}`, `{{social_url type="bluesky"}}`)

***

The `{{social_url}}` helper generates a URL for a specified social media platform based on the provided platform type. It takes a single argument, `type`, which specifies the social media platform (e.g., `facebook`, `mastodon`, etc.). The helper looks for the specified platform in the given context (usually author) and constructs the appropriate URL.

For facebook and twitter, the helper will fall back to the sitewide values if they’re not set on the local context.

For the remaining platforms the fallback behaviour is to output nothing.

Supported platforms include: `facebook`, `twitter`, `linkedin`, `threads`, `bluesky`, `mastodon`, `tiktok`, `youtube`, `instagram`.

### Examples

Output the author’s Threads URL, using an `author` block:

```handlebars  theme={"dark"}
{{#author}}
  {{#if threads}}<a href="{{social_url type="threads"}}">Follow me on Threads</a>{{/if}}
{{/author}}
```

Globally, Twitter and Facebook are available and can be accessed from anywhere in the theme.

```handlebars  theme={"dark"}
{{#if @site.twitter}}<a href="{{social_url type="twitter"}}">Follow us on Twitter</a>{{/if}}
{{#if @site.facebook}}<a href="{{social_url type="facebook"}}">Follow us on Facebook</a>{{/if}}
```


# tags
Source: https://docs.ghost.org/themes/helpers/data/tags

Usage: `{{tags}}` or `{{#foreach tags}}{{/foreach}}` in `tag.hbs` you can use `{{#tag}}{{/tag}}` to access tag properties

***

`{{tags}}` is a formatting helper for outputting a linked list of tags for a particular post. It defaults to a comma-separated list (without list markup) but can be customised to use different separators, and the linking can be disabled. The tags are output in the order they appear on the post, these can be reordered by dragging and dropping.

The `{{tags}}` helper does not output internal tags. This can be changed by passing a different value to the `visibility` attribute.

You can use the [translation helper](/themes/helpers/utility/translate/) for the `prefix` and `suffix` attribute.

### Example code

The basic use of the tags helper will output something like ‘my-tag, my-other-tag, more-tagging’ where each tag is linked to its own tag page:

```handlebars  theme={"dark"}
{{tags}}
```

You can customise the separator between tags. The following will output something like ‘my-tag | my-other-tag | more tagging’

```handlebars  theme={"dark"}
{{tags separator=" | "}}
```

Additionally you can add an optional prefix or suffix. This example will output something like ‘Tagged in: my-tag | my-other-tag | more tagging’

```handlebars  theme={"dark"}
{{tags separator=" | " prefix="Tagged in:"}}
```

You can use HTML in the separator, prefix and suffix arguments. So you can achieve something like ‘my-tag • my-other-tag • more tagging’.

```handlebars  theme={"dark"}
{{tags separator=" • "}}
```

If you don’t want your list of tags to be automatically linked to their tag pages, you can turn this off:

```handlebars  theme={"dark"}
{{tags autolink="false"}}
```

If you want to output a fixed number of tags, you can add a `limit` to the helper. E.g. adding a limit of 1 will output just the first tag:

```handlebars  theme={"dark"}
{{tags limit="1"}}
```

If you want to output a specific range of tags, you can use `from` and `to` either together or on their own. Using `to` will override the `limit` attribute.

E.g. using from=“2” would output all tags, but starting from the second tag:

```handlebars  theme={"dark"}
{{tags from="2"}}
```

E.g. setting both from and to to `1` would do the same as limit=“1”

`{{tags from="1" to="1"}}` is the same as `{{tags limit="1"}}`

## The `visibility` attribute

As of Ghost 0.9 posts, tags and users all have a concept of `visibility`, which defaults to `public`. The key feature build on this so far is Internal Tags, which are tags where the `visibility` is marked as `internal` instead of `public`. These tags will therefore not be output by the `{{tags}}` helper unless you specifically ask for them.

By default the `visibility` attribute is set to the string “public”. This can be overridden to pass any other value, and if there is no matching value for `visibility` nothing will be output. E.g. you can set `visibility` to be “internal” to *only* output internal tags. You can also pass a comma-separated list of values, or the value “all” to output all items.

```handlebars  theme={"dark"}
{{tags visibility="all"}}
```

### Advanced example

If you want to output your tags completely differently, you can fully customise the output by using the foreach helper, instead of the tags helper. Here’s an example of how to output list markup:

```handlebars  theme={"dark"}
{{#post}}
  {{#if tags}}
    <ul>
    {{#foreach tags}}
      <li>
        <a href="{{url}}" title="{{name}}" class="tag tag-{{id}} {{slug}}">{{name}}</a>
      </li>
    {{/foreach}}
    </ul>
  {{/if}}
{{/post}}
```

### List of Attributes

* **id** - the incremental ID of the tag
* **name** - the name of the tag
* **slug** - slugified version of the name (used in urls and also useful for class names)
* **description** - a description of the tag
* **feature\_image** - the cover image for the tag
* **meta\_title** - the tag’s meta title
* **meta\_description** - the tag’s meta description
* **url** - the web address for the tag’s page
* **accent\_color** - the accent color of the tag

## primary\_tag

To output only the singular, first tag, use the `{{primary_tag.name}}`. You can also access all the same attributes in the object as above if you need more custom output.

```handlebars  theme={"dark"}
{{#primary_tag}}
<div class="primary-tag">
    <a href="{{url}}">{{name}}</a>
    <span class="description">{{description}}</span>
<div>
{{/primary_tag}}
```

### Tag objects

In similar fashion to `primary_tag`, single subsequent tags can be outputted using `{{tags.[1].name}}`. Tags can be referenced using a 0 indexed array, for example using `tags.[1]` will reference the second tag (the tag immediately after `primary_tag`). All the attributes on the tag can be accessed as well.

```handlebars  theme={"dark"}
{{#tags.[1]}}
    <div class="secondary-tag">
        <a href="{{url}}">{{name}}</a>
        <span class="description">{{description}}</span>
    <div>
{{/tags.[1]}}
```


# tiers
Source: https://docs.ghost.org/themes/helpers/data/tiers

Usage: `{{tiers}}`/ `{{tiers prefix=":" separator=" - " lastSeparator=", " suffix='options'}}`

***

`{{tiers}}`is a formatting helper for outputting tier names. It defaults to a comma-separated list with `and` as the last separator and `tier(s)` as the suffix. Customize the helper by using a custom prefix, separator, last separator, and/or suffix. Note that values are white-space sensitive.

### Example code

Use the tiers helper to output tier names in ascending order by price. The examples below use tier names of “bronze,” “silver,” and “gold.”

```handlebars  theme={"dark"}
{{tiers}}
{{! output: "bronze, silver and gold tiers" }}
```

#### Custom prefix

Use a custom prefix to add text before tier names.

```handlebars  theme={"dark"}
{{tiers prefix="Access with:"}}
{{! output: "Access with: bronze, silver and gold tiers" }}
```

#### Custom separator

Use a custom separator to change the text between tier names.

```handlebars  theme={"dark"}
{{tiers separator=" | "}}
{{! output: "bronze | silver and gold tiers" }}
```

#### Custom last separator

With multiple tiers, customize the last separator.

```handlebars  theme={"dark"}
{{tiers lastSeparator=" plus "}}
{{! output: "bronze, silver plus gold tiers" }}
```

#### Custom suffix

Change the term “tier” with a custom suffix.

```handlebars  theme={"dark"}
{{tiers suffix="options"}}
{{! output: "bronze, silver and gold options" }}
```

#### HTML values

`separator`, `prefix` , `lastSeparator`, and `suffix` accept HTML values.

```handlebars  theme={"dark"}
{{tiers separator=" • "}}
{{! output: "bronze • silver and gold tiers }}
```

## Fetching tiers with the `{{#get}}` helper

`{{tiers}}` helps with *formatting* your tier names. To fetch tier data, use the `{{#get}}` helper.

```handlebars  theme={"dark"}
{{! Get all tiers with monthly price, yearly price, and benefits data }}
{{#get "tiers" include="monthly_price,yearly_price,benefits" limit="100" as |tiers|}}
    {{! Loop through our tiers collection }}
    {{#foreach tiers}}
        {{name}}
        {{#if monthly_price}}
            <div>
                <a href="javascript:" data-portal="signup/{{id}}/monthly">Monthly – {{price monthly_price currency=currency}}</a>
            </div>
        {{/if}}
        {{#if benefits}}
            {{#foreach benefits as |benefit|}}
                {{benefit}}
            {{/foreach}}
        {{/if}}
    {{/foreach}}
{{/get}}
```

See our [\{\{#get}} helper docs](/themes/helpers/functional/get/) to learn more about using this helper with tiers.


# title
Source: https://docs.ghost.org/themes/helpers/data/title

Usage: `{{title}}`

***

The title helper outputs a post title ensuring it displays correctly.


# total_members
Source: https://docs.ghost.org/themes/helpers/data/total_members

Usage: `{{total_members}}`

***

The total\_members helper outputs a rounded number of total members from your Ghost publication in a human readable format. Example:

```handlebars  theme={"dark"}
{{total_members}}
```

If you have 1225 members, it will output `1,200+`.

For values above 100,000 it will output `100k+` and `3m+` respectively.


# total_paid_members
Source: https://docs.ghost.org/themes/helpers/data/total_paid_members

Usage: `{{total_paid_members}}`

***

The total\_paid\_members helper outputs a rounded number of total paid members from your Ghost publication in a human readable format. Example:

```handlebars  theme={"dark"}
{{total_paid_members}}
```

If you have 1225 paying members, it will output `1,200+`.

For values above 100,000 it will output `100k+` and `3m+` respectively.


# url
Source: https://docs.ghost.org/themes/helpers/data/url

Usage: `{{url}}`

***

`{{url}}` outputs the relative url for a post when inside the post scope.

You can force the url helper to output an absolute url by using the absolute option, E.g. `{{url absolute="true"}}`


# Functional Helpers
Source: https://docs.ghost.org/themes/helpers/functional

Functional helpers are used to work with data objects. Use this reference list to discover what each handlebars helper can do when building a custom Ghost theme.

| Tag                                            | Description                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------ |
| [foreach](/themes/helpers/functional/foreach/) | Loop helper designed for working with lists of posts               |
| [get](/themes/helpers/functional/get/)         | Special block helper for custom queries                            |
| [has](/themes/helpers/functional/has/)         | Like `{{#if}}` but with the ability to do more than test a boolean |
| [if](/themes/helpers/functional/if/)           | Test very simple conditionals                                      |
| [is](/themes/helpers/functional/is/)           | Check the context of the current route                             |
| [match](/themes/helpers/functional/match/)     | Compare two values for equality                                    |
| [unless](/themes/helpers/functional/unless/)   | The opposite of `{{#if}}`                                          |


# foreach
Source: https://docs.ghost.org/themes/helpers/functional/foreach

Usage: `{{#foreach data}}{{/foreach}}`

***

`{{#foreach}}` is a special loop helper designed for working with lists of posts. It can also iterate over lists of tags or users if needed. The foreach helper will output the content placed between its opening and closing tags `{{#foreach}}{{/foreach}}` once for each item in the collection passed to it.

The `{{#foreach}}` helper is context-aware and should **always** be used instead of Handlebars `each` when working with Ghost themes.

### Simple Example

The main use of the `{{#foreach}}` helper in Ghost is iterating over the posts to display a list of posts on your home page, etc:

```handlebars  theme={"dark"}
{{#foreach posts}}
<article class="{{post_class}}">
  <h2 class="post-title"><a href="{{url}}">{{title}}</a></h2>
  <p>{{excerpt words="26"}} <a class="read-more" href="{{url}}">»</a></p>
  <p class="post-footer">
    Posted by {{primary_author}} {{tags prefix=" on "}} at <time class="post-date" datetime="{{date format='YYYY-MM-DD'}}">{{date format="DD MMMM YYYY"}}</time>
  </p>
</article>
{{/foreach}}
```

## Data Variables

When inside a `{{#foreach}}` block, you have access to a set of data variables about the current iteration. These are:

* **@index** (number) - the 0-based index of the current iteration
* **@number** (number) - the 1-based index of the current iteration
* **@key** (string) - if iterating over an object, rather than an array, this contains the object key
* **@first** (boolean) - true if this is the first iteration of the collection
* **@last** (boolean) - true if this is the last iteration of the collection
* **@odd** (boolean) - true if the @index is odd
* **@even** (boolean) - true if the @index is even
* **@rowStart** (boolean) - true if `columns` is passed and this iteration signals a row start
* **@rowEnd** (boolean) - true if `columns` is passed and this iteration signals a row’s end

## Usage

`{{#foreach}}` is a block helper. The most common use case in Ghost is looping through posts.

```handlebars  theme={"dark"}
{{#foreach posts}}
<h2><a href="{{url}}">{{title}}</a></h2>
<p>{{excerpt}}</p>
{{/foreach}}
```

### \{\{else}} and negation

Like all block helpers, `{{#foreach}}` supports adding an `{{else}}` block, which will be executed if there is no data to iterate over:

```handlebars  theme={"dark"}
{{#foreach tags}}
<a href="{{url}}">{{name}}</a>
{{else}}
<p>There were no tags...</p>
{{/foreach}}
```

### The `limit` attribute

Passing `{{#foreach}}` a `limit` attribute will tell it to stop after a certain number of iterations.

```handlebars  theme={"dark"}
{{#foreach posts limit="3"}}
<a href="{{url}}">{{name}}</a>
{{/foreach}}
```

Note that as the `{{#foreach}}` helper is only passively iterating over data, not actively fetching it, if you set the limit to a number higher than the number of items in the collection, it will have no effect.

### The `from` and `to` attributes

Passing `{{#foreach}}` a `from` or `to` attribute will change the items that are output. Both attributes are 1-indexed and inclusive, so `from="2"` means from and including the 2nd post.

```handlebars  theme={"dark"}
{{#foreach posts from="2" to="5"}}
<a href="{{url}}">{{name}}</a>
{{/foreach}}
```

### The `visibility` attribute

By default, `foreach` only displays data that is public. This means that data like hidden tiers and internal tags won’t be included. Set `visibility` to `all` to show all data or to `none` to show hidden data.

````handlebars  theme={"dark"}
{{#foreach tags visibility="all"}}
  <p>{{name}}</p>
{{/foreach}}

## Data variable examples

### `@index`, `@number` and `@key`

`{{@index}}` is the 0-based index of the collection - that is the "count" of the loop. It starts at 0 and then each time around the loop, `{{@index}}` increases by 1. This is useful for adding numbered classes:

```handlebars
{{#foreach posts}}
  <div class="post-{{@index}}">{{title}}</div>
{{/foreach}}
````

`{{@number}}` is very similar to `@index`, but starts at 1 instead of 0, which is useful for outputting numbers you want users to see, e.g. in styled numbered lists:

```handlebars  theme={"dark"}
<ol>
{{#foreach posts}}
  <li>
    <a href="{{url}}">
      <span class="number" aria-hidden="true">{{@number}}</span>{{title}}
    </a>
  </li>
{{/foreach}}
</ol>
```

`{{@key}}` will contain the object key, in the case where you iterate over an object, rather than an array. There’s no real use case for this in Ghost at present.

#### `@first` & `@last`

The following example checks through an array or object, `posts`, and tests for the first entry.

```handlebars  theme={"dark"}
{{#foreach posts}}
  {{#if @first}}
    <div>First post</div>
  {{/if}}
{{/foreach}}
```

We can also nest `if` statements to check multiple properties. In this example, we separate the output of the first and last posts from the other posts.

```handlebars  theme={"dark"}
{{#foreach posts}}
    {{#if @first}}
    <div>First post</div>
    {{else}}
        {{#if @last}}
            <div>Last post</div>
        {{else}}
            <div>All other posts</div>
        {{/if}}
    {{/if}}
{{/foreach}}
```

#### `@even` & `@odd`

The following example adds a class of even or odd, which could be used for zebra striping content:

```handlebars  theme={"dark"}
{{#foreach posts}}
    <div class="{{#if @even}}even{{else}}odd{{/if}}">{{title}}</div>
{{/foreach}}
```

#### `@rowStart` & `@rowEnd`

`@rowStart` and `@rowEnd` return `true` at the beginning and end of a column respectively when the `columns` value is set in a `#foreach`. In the following example, the posts are being grouped up in threes with a wrapping `div` element:

```handlebars  theme={"dark"}
{{#foreach posts columns="3"}}
    {{#if @rowStart}}<div class="column">{{/if}}
        <a href="{{url}}">{{title}}</a>
    {{#if @rowEnd}}</div>{{/if}}
{{/foreach}}
```

## Block Params

Block params allow you to name the individual item being operated on inside the loop, For example:

```handlebars  theme={"dark"}
{{#foreach posts as |my_post|}}
   {{#my_post}}
      <h1>{{title}}</h1>
    {{/my_post}}
{{/foreach}}
```

Which is much the same as doing `posts.forEach(function (my_post) {}` in JavaScript. Useful with advanced features like the `{{get}}` helper.


# get
Source: https://docs.ghost.org/themes/helpers/functional/get

Usage: `{{#get "posts"}}{{/get}}`

***

`{{#get}}` is a special block helper that makes a custom query to the Ghost API to fetch publicly available data. These requests are made server-side before your templates are rendered. This means you can fetch additional data, separate from what is provided by [default in each context](/themes/contexts/).

In its most basic form, the `{{#get}}` helper performs a “browse” query that creates a block of data that represents a list of your **posts**, **authors**, **tags**, or **tiers**. Use the `{{#foreach}}` helper to iterate over this block of data.

The `{{#get}}` helper can also be used to perform a “read” query that fetches one specific author, post, tag, or tier when the relevant *resource field* - e.g., **id** or **slug** – is provided as an attribute.

### Basic examples

Get the 15 newest posts from the API.

```handlebars  theme={"dark"}
{{#get "posts"}}
    {{#foreach posts}}
        {{title}}
    {{/foreach}}
{{/get}}
```

Get a single post with the id of 2, including its related tags and author data, using a block parameter. Learn more about [block parameters](#block-parameters) below.

```handlebars  theme={"dark"}
{{#get "posts" id="2" include="tags,authors" as |post|}}
    {{#post}}
        {{title}}
    {{/post}}
{{/get}}
```

Fetch all tags and output them using the [tags helper](/themes/helpers/data/tags).

```handlebars  theme={"dark"}
{{#get "tags" limit="100"}}{{tags}}{{/get}}
```

## Usage

The `{{#get}}` helper has several more options that greatly extend its functionality. The following section walks through these options and how to use them.

## Resources

The first parameter passed in is the name of the resource you want to query. Available resources include: `"posts"`, `"tags"`, `"authors"`, and `"tiers"`.

**posts** - any published post

**tags** - any tag that has a post associated with it

**authors** - any author who has published a post

**tiers** - any membership tier

**newsletters** - any newsletter

**Example:**

```handlebars  theme={"dark"}
{{#get "authors"}}
    {{! Loop through authors }}
    {{#foreach authors}}
        {{name}}
    {{/foreach}}
{{/get}}
```

## Block parameters

As with the `{{#foreach}}` helper, use block parameters to rename your returned data collection to make it easier to reference or more distinguishable.

<Note>
  Block parameters are entered between pipe symbols (`|`)
</Note>

The `{{#get}}` helper supports two parameters. The first entry refers to your returned data collection. The second entry refers to your [pagination object](/themes/helpers/utility/pagination/).

**Block parameters example:**

Get posts and rename the collection `articles`. The additional pagination object, `pages`, outputs the total number of posts in the collection.

```handlebars  theme={"dark"}
{{#get "posts" as |articles pages|}}
    {{! Loop through our articles collection }}
    {{#foreach articles}}
        {{title}}
    {{/foreach}}
    {{! Use the pages (pagination) object }}
    {{pages.total}}
{{/get}}
```

## Using `{{else}}`

All block helpers support the `{{else}}` helper, which outputs content when the first block doesn’t match. In the case of the `{{get}}` helper, this only happens if there’s an error and is mostly useful for debugging while developing.

To output different content when there are no results returned from the `{{#get}}` request, use `{{else}}` with the `{{#foreach}}` helper.

```handlebars  theme={"dark"}
{{#get "posts" filter="featured:true"}}
    {{! Loop through our featured posts }}
    {{#foreach posts}}
        {{title}}
    {{else}}
    {{! If there are no featured posts}}
       <p>No posts!</p>
    {{/foreach}}
{{else}}
  <p class="error">{{error}}</p>
{{/get}}
```

## Attributes

Use `{{#get}}` helper attributes to specify which data is returned. Available attributes are identical to those used with the [Ghost Content API](/content-api/#parameters).

“Browse” requests (fetching multiple items) accept any or all of these attributes. “Read” requests (fetching a single item by **id** or **slug**) only accept the **include** attribute.

### *limit*

How many items to return

Allowed values: 1-100

Default value: 15

Requesting more than 100 items will return a maximum of 100 items

It’s possible to use the global `posts_per_page` setting, which is **5** by default. Configure the setting in the active theme’s `package.json` file. This global value is available via the `@config` global as `@config.posts_per_page`.

**Examples:**

```handlebars  theme={"dark"}
{{! Get the 20 most recently published posts }}
{{#get "posts" limit="20"}}{{/get}}

{{! Use the posts_per_page setting}}
{{#get "posts" limit=@config.posts_per_page}}{{/get}}
```

### *page*

when the total number of posts exceeds the number of post initially requested, the resulting collection from the `{{#get}}` query will be paginated. Choose which page of that collection you want to get with the `page` attribute.

**Example:**

```handlebars  theme={"dark"}
{{! Get the 4th page of results.  In this case, where limit = 5, we are accessing posts 16 - 20}}
{{#get "posts" limit="5" page="4"}}{{/get}}
```

### *order*

Specify how your data is ordered before being returned. You can choose any valid resource *field* in ascending (`asc`) or descending (`desc`) order.

**Examples:**

```handlebars  theme={"dark"}
{{! Get the 5 oldest posts }}
{{#get "posts" limit="5" order="published_at asc"}}{{/get}}

{{! Get posts in alphabetical order by title }}
{{#get "posts" limit="5" order="title asc"}}{{/get}}
```

### *include*

By default, the `{{#get}}` helper will only fetch the base data from a resource. Use *include* to expand the data that is returned. Separate multiple *include* values with a comma.

Base resource data:

* **posts**
* **tags**
* **authors**
* **tiers**

Include options for *Post*:

* “authors” – adds author data
* “tags – adds tag data

Include option for *Author* and *Tag*

* “count.posts” – adds the post count for each resource

<Note>
  Use `count.posts` to **order** your collection.
</Note>

Include options for *Tiers*

* “monthly\_price” - add monthly price data
* “yearly\_price” – add yearly price data
* “benefits” – add benefits data

**Examples:**

```handlebars  theme={"dark"}
{{! Get posts with author }}
{{#get "posts" limit="5" include="authors"}}
    {{#foreach posts}}
        <span>Written by: {{authors}}</span>
    {{/foreach}}
{{/get}}

{{! Get posts with author and tags }}
{{#get "posts" limit="5" include="authors,tags"}}
    {{#foreach posts}}
        <p>Written by: {{authors separator=", "}}</p>
        <p>keywords: {{tags separator=", "}}</p>
    {{/foreach}}
{{/get}}

{{! Get all tags and order them by post count }}
{{#get "tags" limit="100" include="count.posts" order="count.posts desc"}}
    {{#foreach tags}}
        <p>{{name}} ({{count.posts}})</p>
    {{/foreach}}
{{/get}}

{{! Get all tiers with monthly price, yearly price, and benefits data }}
{{#get "tiers" include="monthly_price,yearly_price,benefits" limit="100" as |tiers|}}
    {{! Loop through our tiers collection }}
    {{#foreach tiers}}
        {{name}}
        {{#if monthly_price}}
            <div>
                <a href="javascript:" data-portal="signup/{{id}}/monthly">Monthly – {{price monthly_price currency=currency}}</a>
            </div>
        {{/if}}
        {{#if yearly_price}}
            <div>
                <a href="javascript:" data-portal="signup/{{id}}/yearly">Yearly – {{price yearly_price currency=currency}}</a>
            </div>
        {{/if}}
        {{#if benefits}}
            {{#foreach benefits as |benefit|}}
                {{benefit}}
            {{/foreach}}
        {{/if}}
    {{/foreach}}
{{/get}}

{{! Create a dynamic sign-up form that allows members to subscribe to specific newsletters}}
<form data-members-form=>
  <input type="email" required data-members-email>
  {{#get "newsletters"}}
      {{#foreach newsletters}}
        <label>
          <input type="checkbox" value="{{name}}" data-members-newsletter />
					{{name}}
        </label>
      {{else}}
  {{/get}}
  <button type="submit">Subscribe</button>
</form>
```

### *filter*

Use `filter` to make complex, logic-based queries on the data to fetch. In its most basic form, use `filter` to get posts that meet a simple boolean condition.

```handlebars  theme={"dark"}
{{! Only get posts that are featured }}
{{#get "posts" limit="25" filter="featured:true"}}
    {{#foreach posts}}
        <a href="{{slug}}">{{title}}</a>
    {{/foreach}}
{{/get}}
```

Specify multiple rules for the `filter` attribute by using `,` for *or*, `+` for *and*, and `-` for *negation*. It’s possible to check for booleans, match against strings, look for items within a group, and much more. For a full breakdown of the filtering syntax and how to use it, please see the [filter documentation in the API docs](/content-api/#filtering).

#### Passing data to `filter`

Data already available within your theme template can be passed to the `filter` attribute.

```handlebars  theme={"dark"}
{{! Get three more posts by the author of the current post when in post.hbs }}
{{#post}}
    <h3><a href="{{url}}">{{title}}</a></h3>
    <section class="author-meta">
        <p>Post by: {{primary_author}}</p>
    </section>
    {{! Prevent the current post from being returned by filtering against its id }}
    {{#get "posts" filter="authors:{{primary_author.slug}}+id:-{{id}}" limit="3"}}
        <p>More posts by this author:
            <ol>
                {{#foreach posts}}
                <li><a href="{{url}}">{{title}}</a></li>
                {{/foreach}}
            </ol>
        </p>
    {{/get}}
{{/post}}
```

When passing `title`, `dates`, or other values with spaces to `filter`–wrap the data in single quotes.

```handlebars  theme={"dark"}
{{#post}}
    {{#get "posts" filter="published_at:<='{{published_at}}'+id:-{{id}}" limit="3"}}
    ...
    {{/get}}
{{/post}}
```

<Note>
  Tip: To filter based on dates, use the data attributes, e.g.`{{published_at}}`, not the `{{date}}` helper, as helper functions do not get called inside of a filter.
</Note>

#### Filtering by primary tag

The `primary_tag` represents the first tag on a post. See the available [attributes](/themes/helpers/data/tags/#list-of-attributes).

```handlebars  theme={"dark"}
{{! Get three posts that have the same primary tag as the current post}}
{{#post}}
    {{#get "posts" filter="primary_tag:{{primary_tag.slug}}" limit="3"}}
        {{#foreach posts}}
            <li><a href="{{url}}">{{title}}</a></li>
        {{/foreach}}
    {{/get}}
{{/post}}
```

#### Filtering by primary author

The `primary_author` represents the first author listed on a post. See the available [attributes](/themes/contexts/author/#author-object-attributes).

```handlebars  theme={"dark"}
{{! Get three posts that have the same primary author as the current post}}
{{#post}}
    {{#get "posts" filter="primary_author:{{primary_author.slug}}" limit="3"}}
        {{#foreach posts}}
            <li><a href="{{url}}">{{title}}</a></li>
        {{/foreach}}
    {{/get}}
{{/post}}
```

#### Filtering by membership type

To restrict the type of tiers returned by the `{{#get}}` helper, filter the collection using the `type` attribute with either *free* or *paid*.

```handlebars  theme={"dark"}
{{! Only get tiers that are paid}}
{{#get "tiers" filter="type:paid"}}
    {{#foreach tiers}}
        <p>{{name}}</p>
    {{/foreach}}
{{/get}}
```

#### Filtering by tier visibility

To restrict the visibility of tiers returned by the `{{#get}}` helper, filter the collection using the `visibility` attribute with either *public* or *none*. Visibility here refers to whether the tier is selected or not in Portal settings.

```handlebars  theme={"dark"}
{{! Only get tiers that are public}}
{{#get "tiers" filter="visibility:public"}}
    {{#foreach tiers}}
        <p>{{name}}</p>
    {{/foreach}}
{{/get}}
```


# has
Source: https://docs.ghost.org/themes/helpers/functional/has

Usage:

***

`{{#has tag="value1,value2" author="value"}}`

`{{#has slug=../slug}}`

`{{#has number="nth:3"}}`

`{{#has any="twitter, facebook"}}`

`{{#has all="twitter, facebook"}}`

## Description

`{{#has}}` is like `{{#if}}` but with the ability to do more than test a boolean. It allows theme developers to ask questions about the current context and provide more flexibility for creating different layouts.

Like all block helpers, `{{#has}}` supports adding an `{{else}}` block or using `^` instead of `#` for negation - this means that the `{{#has}}` and `{{else}}` blocks are reversed if you use `{{^has}}` and `{{else}}` instead. In addition, it is possible to do `{{else has ...}}`, to chain together multiple options like a switch statement.

### Simple Example

The `{{#has}}` helper can be combined with internal tags, to display different information for different types of posts. E.g. implementing a link-style post by adding an internal tag of `#link` and using the has helper to detect it:

```handlebars  theme={"dark"}
{{#post}}
  {{#has tag="#link"}}
     {{> "link-card"}}
  {{else}}
    {{> "post-card"}}
  {{/has}}
{{/post}}
```

## Usage

The `{{#has}}` helper supports four different types of “questions”:

* Post has tag or author
* Context has slug or id
* Context has any or all properties set
* Foreach loop number or index

Questions are asked by providing attribute-value pairs, e.g. `tag="tag name"`. You can pass multiple attributes, and the `{{#has}}` helper will always treat this as an `OR`.

E.g. You can look for a post with a slug of “welcome” OR a tag of “getting started”:

```handlebars  theme={"dark"}
{{#has slug="welcome" tag="getting started"}}
  ...Will execute if the slug is welcome OR the tag is getting-started...
{{/has}}
```

### Post tag or author

#### Comma Separated List

```handlebars  theme={"dark"}
{{#has tag="photo"}}{{/has}}
{{#has tag="photo, video"}}{{/has}}
{{#has author="Joanna Bloggs"}}{{/has}}
```

Specifically when inside the context of a post, you can use the `{{#has}}` helper to find out if the post has a particular tag or author. Both the `tag` and `author` attributes take a comma separated list. If you pass multiple values separated by a comma, these will be treated as an OR.

```handlebars  theme={"dark"}
{{#has tag="General, News"}}
  ...Will execute if the post has a tag of General or News...
 {{/has}}
```

Tag and author matching is a lowercase match on the tag name or author name, which ignores special characters.

#### Counting

The `author` and `tag` attribute accepts a counting value. You can choose between:

* `count:[number]`
* `count:>[number]`
* `count:<[number]`

This functionality can be helpful when designing a theme. You can change the behaviour if a post has only one author or more than 1.

```handlebars  theme={"dark"}
{{#has tag="count:1"}}{{/has}}
{{#has tag="count:>1"}}{{/has}}
{{#has author="count:<2"}}{{/has}}
```

### Slug or id

```handlebars  theme={"dark"}
{{#has slug="welcome"}}{{/has}}
{{#has slug=../../slug}}{{/has}}
{{#has id=post.id}}{{/has}}
```

If you’re in the context of an object that has a slug (e.g. post, author, tag and navigation items) you can use the `{{#has}}` helper to do an exact match. Similarly for all objects that have an ID.

You can either pass the `{{#has}}` helper a string wrapped in quotes, or a path to a data value from else where in the template data. For example, the following code does an exact match on the string “welcome”. If the post’s slug is the same, the code inside the has helper will execute.

```handlebars  theme={"dark"}
{{#has slug="welcome"}}
  ... do something..
{{/has}}
```

Alternatively, you can pass a handlebars path, which references a different piece of data to match against:

```handlebars  theme={"dark"}
{{#has slug=../post.slug}}
  ...do something...
{{/has}}
```

### Any or all

The `any` comparison will return true if **any** one of the properties is set in the current context, with support for paths and globals:

```handlebars  theme={"dark"}
{{#has any="twitter, facebook, website"}}
{{#has any="author.facebook, author.twitter,author.website"}}
{{#has any="@site.facebook, @site.twitter"}}
```

Similarly, the `all` comparison will return true only when **all** of the properties are set:

```handlebars  theme={"dark"}
{{#has all="@labs.subscribers,@labs.publicAPI"}}
```

### Foreach loop number or index

```handlebars  theme={"dark"}
{{#has number="3"}}{{/has}} // A single number
{{#has number="3, 6, 9"}}{{/has}} // list of numbers
{{#has number="nth:3"}}{{/has}} // special syntax for nth item
{{!-- All of these work exactly the same for index --}}
```

When you’re inside a `{{#foreach}}` loop of any kind, you have access to two special data variables called `@index` and `@number`. `@index` contains the 0-based index or count of the loop, and `@number` contains a 1-based index. That is each time around the loop these values increase by 1, but `@index` starts at 0, and `@number` starts at 1.

The `{{#has}}` helper will let you check which number/index of the iteration you are on using the 3 different styles of matching shown above. For example, if you have a list of posts and want to inject a special widget partial every 3rd post, you could do so using the `nth:3` pattern:

```handlebars  theme={"dark"}
{{#foreach posts}}
  {{#has number="nth:3"}}
     {{> "widget"}}
  {{/has}}

  {{> "post-card"}}
{{/foreach}}
```

## Example Code

To determine if a post has a particular tag:

```handlebars  theme={"dark"}
{{#post}}
    {{#has tag="photo"}}
        ...do something if this post has a tag of photo...
    {{else}}
        ...do something if this posts doesn't have a tag of photo...
    {{/has}}
{{/post}}
```

You can also supply a comma-separated list of tags, which is the equivalent of an OR query, asking if a post has any one of the given keywords:

```handlebars  theme={"dark"}
{{#has tag="photo, video, audio"}}
    ...do something if this post has a tag of photo or video or audio...
{{else}}
    ...do something with other posts...
{{/has}}
```

You can do an AND query by nesting your `{{#has}}` helpers:

```handlebars  theme={"dark"}
{{#has tag="photo"}}
    ...do something if this post has a tag of photo..
    {{#has tag="panorama"}}
       ...if the post has both the photo and panorama tags
    {{/has}}
{{else}}
    ...do something with other posts...
{{/has}}
```


# if
Source: https://docs.ghost.org/themes/helpers/functional/if

Usage: `{{#if featured}}{{/if}}`

***

The `{{#if}}` block helper comes built in with Handlebars.

`{{#if}}` allows for testing very simple conditionals, and executing different template blocks depending on the outcome.

The conditionals that can be tested are very simple, essentially only checking for ’truthiness’. The evaluation rules are explained in the section below.

Like all block helpers, `{{#if}}` supports adding an `{{else}}` block or using `^` instead of `#` for negation - this means that the `{{#if}}` and `{{else}}` blocks are reversed if you use `{{^if}}` and \{\{else}} instead. In addition, it is possible to do `{{else if ...}}`, to chain together multiple options like a switch statement.

#### Evaluation rules

The if helper takes a single value, and evaluates whether it is true or false. Any passed in value which is equivalent to `false`, `0`, `undefined`, `null`, `""` (an empty string) or `[]` (an empty array) is considered false, and any other value is considered true.

* Any boolean value, like the featured flag on a post, will evaluate to true or false as you expect.
* Any string value will be true, as long as it is not null or empty
* All numerical values, with the exception of `0` evaluate to true, 0 is the same as false
* Any property which doesn’t exist or is not set will always evaluate false
* Empty arrays or objects will be false

### Example code

When in the scope of a post, `featured` is a boolean flag. The following code example will evaluate to true only if the post is marked as featured.

```handlebars  theme={"dark"}
{{#post}}
  {{#if featured}}
   ...do something if the post is featured...
  {{/if}}
{{/post}}
```

You can also use this to test if any property is set. Strings, like image URLs will evaluate to true as long as one is present, and will be null (false) otherwise:

```handlebars  theme={"dark"}
{{#post}}
  {{#if feature_image}}
     <img src="{{img_url feature_image}}" />
  {{else}}
		 <img src="{{asset "img/default-img.jpg"}}" />
  {{/if}}
{{else}}
<p>No posts to display!</p>
{{/post}}
```


# is
Source: https://docs.ghost.org/themes/helpers/functional/is

Usage: `{{#is "contexts"}}`

***

The `{{#is}}` helper allows you to check the context of the current route, i.e. is this the home page, or a post, or a tag listing page. This is useful when using shared partials or layouts, to output slightly different context in different places on your theme.

### Usage

The `is` helper takes a single parameter of a comma-separated list containing the contexts to check for. Similar to the `has` helper, the comma behaves as an `or` statement, with `and` being achieved by nesting helpers.

```handlebars  theme={"dark"}
{{#is "post, page"}}
   ... content to render if the current route represents a post or a page ...
{{/is}}
```

As with all block helpers, it is possible to use an else statement:

```handlebars  theme={"dark"}
{{#is "home"}}
  ... output something special for the home page ...
{{else}}
  ... output something different on all other pages ...
{{/is}}
```

If you only want the reverse, or negation, you can use the `^` character:

```handlebars  theme={"dark"}
{{^is "paged"}}
 ...if this is *not* a 2nd, 3rd etc page of a list...
{{/is}}
```

### Contexts

The following contexts are supported:

* **home** - true only on the home page
* **index** - true for the main post listing, including the home page
* **post** - true for any individual post page, where the post is not a static page
* **page** - true for any static page
* **tag** - true for any page of the tag list
* **author** - true for any page of the author list
* **paged** - true if this is page 2, page 3 of a list, but not on the first page
* **private** - true if this is the private page shown for password protected sites


# match
Source: https://docs.ghost.org/themes/helpers/functional/match

Usage: `{{#match @custom.color_scheme "=" "Dark"}} class="dark-mode"{{/match}}`

***

`{{#match}}` allows for simple comparisons, and executing different template blocks depending on the outcome.

Like all block helpers, `{{#match}}` supports adding an `{{else}}` block or using `^` instead of `#` for negation - this means that the `{{#match}}` and `{{else}}` blocks are reversed if you use `{{^match}}` and `{{else}}` instead. In addition, it is possible to do `{{else match ...}}`, to chain together multiple options like a switch statement.

### Example usage

The `match` helper is handy when paired with [custom theme settings](/themes/custom-settings/) using `@custom`:

```handlebars  theme={"dark"}
{{!-- Adds the 'font-alt' class when the Typography setting is set to 'Elegant serif' --}}
<body class="{{body_class}} {{#match @custom.typography "Elegant serif"}}font-alt{{/match}}">
```

Supports various operators and else blocks:

```handlebars  theme={"dark"}
{{#match @custom.color_scheme "!=" "Dark"}}...{{else}}...{{/match}}
```

## Operators

Match supports the following operators

* `=` - equals (default when no operator provided)
* `!=` - not equals
* `>` - greater than
* `>=` - greater than or equals
* `<` - less than
* `<=` - less than or equals
* `~` - contains
* `~^` - starts with
* `~$` - ends with

### Equality

`match` supports comparing values for equality, which is the default behaviour:

```handlebars  theme={"dark"}
{{#match @custom.color_scheme "=" "Dark"}}...{{else}}...{{/match}}

{{!-- Can be shortened to: --}}
{{#match @custom.color_scheme "Dark"}}...{{else}}...{{/match}}
```

The equality test can also be negated:

```handlebars  theme={"dark"}
{{#match @custom.color_scheme "!=" "Dark"}}...{{else}}...{{/match}}
```

### String comparisons

Support for contains `~`, starts with `~^` and ends with `~$`, using the same syntax as [NQL filtering](/content-api/filtering#operators)

```handlebars  theme={"dark"}
{{!-- slug starts with #episode- --}}
{{#match slug "~^" "hash-episode-"}}{{/match}}
```

### Numeric comparisons

The match handler supports `>`, `<`, `>=` and `<=` operators for numeric comparisons.

```handlebars  theme={"dark"}
{{#match posts.length ">" 1}}...{{else}}...{{/match}}
```

### Evaluation rules

Values passed to `match` are tested according to their *value* as well as their *type*. For example:

```handlebars  theme={"dark"}
{{!-- Returns true/false --}}
{{#match feature_image true}}...{{else}}...{{/match}}

{{!-- Always returns false --}}
{{#match feature_image 'true'}}...{{else}}...{{/match}}
```

`match` can also be used to test boolean values similar to `if`:

```handlebars  theme={"dark"}
{{!-- Default behaviour is to test if a value is truthy --}}
{{#match featured}}...{{else}}...{{/match}}
```


# unless
Source: https://docs.ghost.org/themes/helpers/functional/unless

Usage: `{{#unless featured}}{{/unless}}`

***

The `{{#unless}}` block helper comes built in with Handlebars.

`{{#unless}}` is essentially the opposite of `{{#if}}`. If you want to test a negative conditional only, i.e. if you only need the `{{else}}` part of an `{{#if}}` statement, then `{{#unless}}` is what you need.

It works exactly the same as `{{#if}}` and supports both `{{else}}` and `^` negation if you want to get really confusing!

Unless also uses the exact same conditional evaluation rules as `{{#if}}`.

### Example code

Basic unless example, will execute the template between its start and end tags only if `featured` evaluates to false.

```handlebars  theme={"dark"}
{{#unless featured}}
  ...do something...
{{/unless}}
```

If you want, you can also include an else block, although in the majority of cases, if you need an else, then using `{{#if}}` is more readable:

```handlebars  theme={"dark"}
<!-- This is identical to if, but with the blocks reversed -->
{{#unless featured}}
  ...do thing 1...
{{else}}
  ...do thing 2...
{{/unless}}
```


# Utility Helpers
Source: https://docs.ghost.org/themes/helpers/utility

Utility helpers are used to perform minor, optional tasks. Use this reference list to discover what each handlebars helper can do when building a custom Ghost theme.

| Tag                                                                                                               | Description                                                                      |
| ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| [asset](/themes/helpers/utility/asset/)                                                                           | Outputs cachable and cache-busting relative URLs to various asset types          |
| [block](/themes/helpers/utility/block/)                                                                           | Used along with `{{contentFor}}` to pass data up and down the template hierarchy |
| [body\_class](/themes/helpers/utility/body_class/)                                                                | Outputs dynamic CSS classes intended for the `<body>` tag                        |
| [concat](/themes/helpers/utility/concat/)                                                                         | Concatenate and link multiple things together                                    |
| [encode](/themes/helpers/utility/encode/)                                                                         | Encode text to be safely used in a URL                                           |
| [ghost\_head](/themes/helpers/utility/ghost_head_foot/) / [ghost\_foot](/themes/helpers/utility/ghost_head_foot/) | Outputs vital system information at the top and bottom of the document           |
| [link\_class](/themes/helpers/utility/link_class/)                                                                | Add dynamic classes depending on the currently viewed page                       |
| [log](/themes/helpers/utility/log/)                                                                               | In development mode, output data in the console                                  |
| [pagination](/themes/helpers/utility/pagination/)                                                                 | Helper which outputs formatted HTML for pagination links                         |
| [partials](/themes/helpers/utility/partials/)                                                                     | Include chunks of reusable template code                                         |
| [plural](/themes/helpers/utility/plural/)                                                                         | Output different text based on a given input                                     |
| [post\_class](/themes/helpers/utility/post_class/)                                                                | Outputs classes intended for your post container                                 |
| [prev\_post](/themes/helpers/utility/prev_next_post/) / [next\_post](/themes/helpers/utility/prev_next_post/)     | Within the `post` scope, returns the URL to the previous or next post            |
| [reading\_time](/themes/helpers/utility/reading_time/)                                                            | Renders the estimated reading time for a post                                    |
| [search](/themes/helpers/utility/search/)                                                                         | Output a working, pre-styled search button & icon                                |
| [split](/themes/helpers/utility/split/)                                                                           | Split a string into one or more iterable strings                                 |
| [translate](/themes/helpers/utility/translate/)                                                                   | Output text in your site language (the backbone of i18n)                         |


# asset
Source: https://docs.ghost.org/themes/helpers/utility/asset

Usage: `{{asset "asset-path"}}`

***

The `{{asset}}` helper exists to take the pain out of asset management. Firstly, it ensures that the relative path to an asset is always correct, regardless of how Ghost is installed. So if Ghost is installed in a subdirectory, the paths to the files are still correct, without having to use absolute URLs.

Secondly, it allows assets to be cached. All assets are served with a `?v=#######` query string which currently changes when Ghost is restarted and ensures that assets can be cache busted when necessary.

Thirdly, it provides stability for theme developers so that as Ghost’s asset handling and management evolves and matures, theme developers should not need to make further adjustments to their themes as long as they are using the asset helper.

Finally, it imposes a little bit of structure on themes by requiring an `assets` folder, meaning that Ghost knows where the assets are, and theme installing, switching live reloading will be easier in future.

### Examples

To use the `{{asset}}` helper to output the path for an asset, simply provide it with the path for the asset you want to load, relative to the `assets` folder.

For example:

```handlebars  theme={"dark"}
<!-- Styles -->
<link rel="stylesheet" type="text/css" href="{{asset 'css/style.css'}}" />

<!-- Serving a minified asset in production and unminified file in development using hasMinFile -->
<link rel="stylesheet" type="text/css" href="{{asset 'css/style.css' hasMinFile='true'}}" />

<!-- Scripts -->
<script type="text/javascript" src="{{asset 'js/index.js'}}"></script>

<!-- Images -->
<img src="{{asset 'images/my-image.jpg'}}" />
```


# block
Source: https://docs.ghost.org/themes/helpers/utility/block

Usage: `{{{block "section"}}}` and `{{#contentFor "section"}} content {{/contentFor}}`

***

`{{{block "block-name"}}}` is a helper for creating a placeholder within a custom handlebars template. Adding the helper along with a unique ID creates a slot within the template, which can be optionally filled when the template is inherited by another template file.

The `{{#contentFor "block-name"}}...{{/contentFor}}` helper is used to access and populate the block definitions within the template that’s being inherited. The inherited template is referenced with `{{!< template-name}}` at the top of the file. If the `contentFor` is not used then the block will be gracefully skipped.

### Example

```handlebars  theme={"dark"}
<!-- default.hbs -->

<body>
    <!-- ... -->
    {{{block "scripts"}}}
</body>
```

***

```handlebars  theme={"dark"}
<!-- page.hbs -->

{{!< default}}

{{#contentFor "scripts"}}
    <script>
        runPageScripts();
    </script>
{{/contentFor}}
```

## `{{{body}}}` helper

The `{{{body}}}` helper behaves in a similar fashion to a defined block helper, but doesn’t require a corresponding `contentFor` helper in the inheriting template file.

### `{{{body}}}` example

```handlebars  theme={"dark"}
<!-- default.hbs -->

<div class="site-wrapper">
    {{{body}}}
    <!-- ... -->
</div>
```

***

```handlebars  theme={"dark"}
<!-- post.hbs -->

{{!< default}}

<section class="post-full-content">
    <div class="post-content">
        {{content}}
    </div>
</section>
```

Inherited template files, files that contain `{{{block "block-name"}}}`, cannot be templates used directly by Ghost. `post.hbs`, `page.hbs` `index.hbs` can inherit other template files and used the `contentFor` helper but cannot contain block definitions. See our [theme structure documentation](/themes/structure/#templates) for more information.


# body_class
Source: https://docs.ghost.org/themes/helpers/utility/body_class

Usage: `{{body_class}}`

***

`{{body_class}}` – outputs dynamic CSS classes intended for the `<body>` tag in your `default.hbs` or other layout file, and is useful for targeting specific pages (or contexts) with styles.

The `{{body_class}}` helper outputs different classes on different pages, depending on what context the page belongs to. For example the home page will get the class `.home-template`, but a single post page would get `.post-template`.

Ghost provides a series of both static and dynamic `body_class` classes:

#### Static classes

* `home-template` – The class applied when the template is used for the home page
* `post-template` – The class applied to all posts
* `page-template` – The class applied to all pages
* `tag-template` – The class applied to all tag index pages
* `author-template` – The class applied to all author pages
* `private-template` – The class applied to all page types when password protected access is activated

#### Dynamic classes

* `page-{slug}` – A class of `page-` plus the page slug added to all pages
* `tag-{slug}` – A class of `tag-` plus the tag page slug added to all tag index pages
* `author-{slug}` – A class of `author-` plus the author page slug added to all author pages

### Examples

```handlebars  theme={"dark"}
<!-- default.hbs -->

<html>
    <head>...</head>
    <body class="{{body_class}}">
    ...
    {{{body}}}
    ...
    </body>
</html>
```


# concat
Source: https://docs.ghost.org/themes/helpers/utility/concat

Usage: `{{concat "a" "b" "c"}}`

***

The `{{concat}}` helper is designed to concatenate and link multiple things together.

The `{{concat}}` helper will take all of the items passed to it, treat them as strings, and concatenate them together without any spaces. There can be an unlimited amount of items passed to the helper.

Strings, variables and other helpers can be passed into the `{{concat}}` helper.

## Simple examples

```handlebars  theme={"dark"}
{{concat "hello world" "!" }}

Outputs:

hello world!
```

```handlebars  theme={"dark"}
{{concat "my-class" slug }}

Outputs:

my-classmy-post
```

`{{concat}}` is designed for strings. If an object is passed it will output `[object Object]` in true JavaScript™️ fashion. To make it error proof, if `{{concat}}` is passed an empty variable, the output will be an empty string.

## The separator attribute

By default, strings are concatenated together with nothing in between them. The `separator=""` attribute inserts the value provided between each string.

### Separator example

```handlebars  theme={"dark"}
{{concat "hello" "world" separator=" "}}

Outputs:

hello world
```


# encode
Source: https://docs.ghost.org/themes/helpers/utility/encode

Usage: `{{encode value}}`

***

`{{encode}}` is a simple output helper which will encode a given string so that it can be used in a URL.

The most obvious example of where this is useful is shown in Casper’s `post.hbs`, for outputting a twitter share link:

```handlebars  theme={"dark"}
<a class="icon-twitter" href="https://twitter.com/share?text={{encode title}}&url={{url absolute='true'}}"
    onclick="window.open(this.href, 'twitter-share', 'width=550,height=235');return false;">
    <span class="hidden">Twitter</span>
</a>
```

Without using the `{{encode}}` helper on the post’s title, the spaces and other punctuation in the title will not be handled correctly.


# ghost_head & ghost_foot
Source: https://docs.ghost.org/themes/helpers/utility/ghost_head_foot

Usage: `{{ghost_head}}` and `{{ghost_foot}}`

***

These helpers output vital system information at the top and bottom of the document, and provide hooks to inject additional scripts and styles.

### ghost\_head

`{{ghost_head}}` – belongs just before the `</head>` tag in `default.hbs`, outputs the following:

* Meta description
* Structured data Schema.org microformats in JSON/LD - no need to clutter your theme markup!
* Structured data tags for Facebook Open Graph and Twitter Cards.
* RSS url paths to make your feeds easily discoverable by external readers.
* Scripts to enable the Ghost API
* Anything added in the `Code Injection` section globally, or at a page-level

### ghost\_foot

`{{ghost_foot}}` – belongs just before the `</body>` tag in `default.hbs`, outputs the following:

* Anything added in the `Code Injection` section globally, or at a page-level


# link_class
Source: https://docs.ghost.org/themes/helpers/utility/link_class

Usage: `{{link_class for="/about/"}}`

***

The `{{link_class}}` helper adds dynamic classes depending on the currently viewed page. If the page slug (e.g. `/about/`) matches the value given to the `for` attribute the helper will output a `nav-current` class. A `for` value must be provided.

## Simple example

```html  theme={"dark"}
<li class="nav {{link_class for="/about/"}}">About</li>

When on the "/about/" URL it will output:

<li class="nav nav-current">About</li>

By default it will output:

<li class="nav ">About</li>
```

### `activeClass`

By default the active class outputted by `{{link_class}}` will be `nav-current`, this is consistent with our [navigation helper](/themes/helpers/data/navigation/). However it can be overwritten with the `activeClass` attribute:

```html  theme={"dark"}
<li class="nav {{link_class for="/about/" activeClass="active"}}">About</li>

Will output:

<li class="nav active">About</li>
```

`activeClass` can also be given `false` value (`activeClass=false`), which will output an empty string. Effectively turning off the behaviour.

### `class`

Optionally `{{link_class}}` can have additional active classes. Using the `class` attribute will add whatever value has been provided when the link is the active URL, `nav-current` (the default active class value) will be added last:

```html  theme={"dark"}
<li class="nav {{link_class for="/about/" class="current-about"}}">About</li>

Will output:

<li class="nav current-about nav-current">About</li>
```

## Parent URLs

Not only can `{{link_class}}` add active classes to current URLs, but it can also apply classes to parent URLs. If a user navigates to `/tags/toast/` then `{{link_class}}` can provide an active class to `/tags/` as well as `/tags/toast/`.

### Example

```html  theme={"dark"}
<li class="nav {{link_class for="/tags/"}}">Tags</li>

When on the "/tags/" URL it will output:

<li class="nav nav-current">Tags</li>

When on the "/tags/toast/" URL it will output:

<li class="nav nav-parent">Tags</li>
```


# log
Source: https://docs.ghost.org/themes/helpers/utility/log

Usage: `{{log value}}`

***

When running Ghost in development mode, you can use the `{{log}}` helper to output debug messages to the server console. In particular you can get handlebars to output the details of objects or the current context

For example, to output the full ‘context’ that handlebars currently has access to:

`{{log this}}`

Or, to log each post in the loop:

```handlebars  theme={"dark"}
{{#foreach posts}}
   {{log post}}
{{/foreach}}
```

If you’re developing a theme and running an install [using Ghost-CLI](/install/local/), you must use `NODE_ENV=development ghost run` to make debug output visible in the console.


# pagination
Source: https://docs.ghost.org/themes/helpers/utility/pagination

Usage: `{{pagination}}`

***

`{{pagination}}` is a template driven helper which outputs HTML for ’newer posts’ and ‘older posts’ links if they are available and also says which page you are on.

You can override the HTML output by the pagination helper by placing a file called `pagination.hbs` inside of `content/themes/your-theme/partials`. Details of the default template are below.

The data used to output the `{{pagination}}` helper is generated based on the post list that is being output (index, tag posts, author posts etc) and always exists at the top level of the data structure.

## Pagination Attributes

* **page** - the current page number
* **prev** - the previous page number
* **next** - the next page number
* **pages** - the number of pages available
* **total** - the number of posts available
* **limit** - the number of posts per page

## Default Template

The [default template](https://github.com/TryGhost/Ghost/blob/3d989eba2371235d41468f7699a08e46fc2b1e87/ghost/core/core/frontend/helpers/tpl/pagination.hbs) output by Ghost is shown below. You can override this by placing a file called `pagination.hbs` in the partials directory of your theme.

```html  theme={"dark"}
<nav class="pagination" role="navigation">
    {{#if prev}}
        <a class="newer-posts" href="{{page_url prev}}">← Newer Posts</a>
    {{/if}}
    <span class="page-number">Page {{page}} of {{pages}}</span>
    {{#if next}}
        <a class="older-posts" href="{{page_url next}}">Older Posts →</a>
    {{/if}}
</nav>
```

## Unique helpers within this context

* `{{page_url}}` - accepts `prev`, `next` and `$number` to link to a particular page
* `{{page}}` - outputs the current page number
* `{{pages}}` - outputs the total number of pages


# partials
Source: https://docs.ghost.org/themes/helpers/utility/partials

Usage: `{{> "partial-name"}}`

***

`{{> "partials"}}` is a helper for reusing chunks of template code in handlebars files. This can be useful for any repeating elements, such as a post card design, or for splitting out components like a header for easier to manage template files.

All partials are stored in the `partials/` directory of the theme. Partials will inherit context and make that context available within the partial file.

### Example

```handlebars  theme={"dark"}
{{#foreach posts}}

  {{> "post-card"}}

{{/foreach}}
```

```html  theme={"dark"}
<!-- partials/post-card.hbs -->
<article class="post-card.hbs">
  <h2 class="post-card-title">
    <a href="{{url}}">{{title}}</a>
  </h2>
  <p>{{excerpt words="30"}}</p>
</article>
```

### Partial properties

Partials can take properties as well which provide the option to set contextual values per use case.

#### Properties example

```handlebars  theme={"dark"}
{{> "call-to-action" heading="Sign up now"}}
```

```html  theme={"dark"}
<!-- partials/call-to-action.hbs -->
<aside>
  {{#if heading}}
    <h2>{{heading}}</h2>
  {{/if}}
  <form>
    <!-- ... -->
  </form>
</aside>
```


# plural
Source: https://docs.ghost.org/themes/helpers/utility/plural

Usage: `{{plural value empty="" singular="" plural=""}}`

***

`{{plural}}` is a formatting helper for outputting strings which change depending on whether a number is singular or plural.

The most common use case for the plural helper is outputting information about how many posts there are in total in a collection. For example, themes have access to `pagination.total` on the homepage, a tag page or an author page. You can override the default text.

### Examples

```handlebars  theme={"dark"}
{{plural pagination.total empty='No posts' singular='% post' plural='% posts'}}
```

`%` is parsed by Ghost and will be replaced by the number of posts. This is a specific behaviour for the helper.


# post_class
Source: https://docs.ghost.org/themes/helpers/utility/post_class

Usage: `{{post_class}}`

***

`{{post_class}}` outputs classes intended for your post container, useful for targeting posts with styles.

The classes are as follows:

* `post` - All posts automatically get a `post` class.
* `featured` - All posts marked as featured get the `featured` class.
* `page` - Any static page gets the `page` class.
* `tag-:slug` - For each tag associated with the post, the post get a tag in the format `tag-:slug`.

For example:

A post which is not featured or a page, but has the tags `photo` and `panoramic` would get `post tag-photo tag-panoramic` as post classes.

A featured post with a tag of `photo` would get `post tag-photo featured`.

A featured page with a tag of `photo` and `panoramic` would get `post tag-photo tag-panoramic featured page`.

Setting a post as featured or as a page can be done from the post settings menu.

### Example Code

```html  theme={"dark"}
<article class="{{post_class}}">
  {{content}}
</article>
```


# prev_post & next_post
Source: https://docs.ghost.org/themes/helpers/utility/prev_next_post

Usage: `{{#prev_post}}{{title}}{{/prev_post}}` - `{{#next_post}}{{title}}{{/next_post}}`

***

When in the scope of a post, you can call the next or previous post helper, which performs a query against the API to fetch the next or previous post in accordance with the chronological order of the site.

Inside of the opening and closing tags of the `{{#next_post}}{{/next_post}}` or `{{#prev_post}}{{/prev-post}}` helper, the normal helpers for outputting posts will work, but will output the details of the post that was fetched from the API, rather than the original post.

```handlebars  theme={"dark"}
{{#post}}
	{{#prev_post}}
		<a href="{{url}}">{{title}}</a>
	{{/prev_post}}

	{{#next_post}}
		<a href="{{url}}">{{title}}</a>
	{{/next_post}}
{{/post}}
```

You can also scope where to pull the previous and next posts from using the `in` parameter

```handlebars  theme={"dark"}
{{#post}}
	{{#prev_post in="primary_tag"}}
		<a href="{{url}}">{{title}}</a>
	{{/prev_post}}

	{{#next_post in="primary_tag"}}
		<a href="{{url}}">{{title}}</a>
	{{/next_post}}
{{/post}}
```


# reading_time
Source: https://docs.ghost.org/themes/helpers/utility/reading_time

Usage: `{{reading_time}}`

***

`{{reading_time}}` renders the estimated reading time for a post.

The helper counts the words in the post and calculates an average reading time of 275 words per minute. For the first image present, 12s is added, for the second 11s is added, for the third 10, and so on. From the tenth image onwards every image adds 3s.

By *default* the helper will render a text like this:

* `x min read` for estimated reading time longer than one minute
* `1 min read` for estimated reading time shorter than or equal to one minute

You can override the default text.

### Example Code

```handlebars  theme={"dark"}
{{#post}}
    {{reading_time}}
{{/post}}
```

## Custom labelling

Singular minute and plural minutes labelling can be customised using the options `minute` and `minutes`, using `%` as the plural minutes value.

### Example

```handlebars  theme={"dark"}
{{reading_time minute="Only a minute" minutes="Takes % minutes"}}
```

[See our full tutorial](https://ghost.org/tutorials/reading-time/) on how to customise and build upon the `reading_time` Handlebars helper.


# search
Source: https://docs.ghost.org/themes/helpers/utility/search

Usage: `{{search}}`

***

The `{{search}}` helper outputs a search icon button that launches Ghost search when clicked.

The color of the icon uses the `currentColor` CSS property, meaning it will match the color of text around it. The styling can be overriden by using the `.gh-search-icon` class plus `!important`.

### Example Code

```html  theme={"dark"}
{{search}}
```

The helper will output the following markup:

```html  theme={"dark"}
<button class="gh-search-icon" aria-label="search" data-ghost-search style="display: inline-flex; justify-content: center; align-items: center; width: 32px; height: 32px; padding: 0; border: 0; color: inherit; background-color: transparent; cursor: pointer; outline: none;">
    <svg width="20" height="20" fill="none" viewBox="0 0 24 24"><path d="M14.949 14.949a1 1 0 0 1 1.414 0l6.344 6.344a1 1 0 0 1-1.414 1.414l-6.344-6.344a1 1 0 0 1 0-1.414Z" fill="currentColor"/><path d="M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm-9 7a9 9 0 1 1 18 0 9 9 0 0 1-18 0Z" fill="currentColor"/></svg>
</button>
```

For other ways to launch Ghost search and to learn more about this feature, [see the Ghost search documentation](/themes/search/).


# split
Source: https://docs.ghost.org/themes/helpers/utility/split

Usage: `{{split "apple-banana-pear" separator="-"}}`

***

The `{{split}}` helper is designed to split a string into separate strings.  It can be used in block or inline mode.

The `{{split}}` helper returns an array, suitable for iteration with `{{#foreach}}`, with individual elements of the array suitable for any helper that expects a string.

Individual elements of the array may be addressed as `{{this}}` within a `{{#foreach}}` loop.

## Examples

### Block mode:

```handlebars  theme={"dark"}
{{#split "hello,world" as |elements|}}
  {{#foreach elements}}
    |{{this}}|
  {{/foreach}}
{{/split}}

Outputs:

|hello||world|
```

```handlebars  theme={"dark"}
{{#foreach (split "hello, world" separator=",")}}
   {{this}} {{#unless @last}}<br>{{/unless}}
{{/foreach}}

Outputs:

hello<br> world
```

`{{split}}` is designed for strings. If it receives a non-string, it attempts to convert it to a string first.

## The separator attribute

By default, strings are split at each ",". The `separator=""` attribute allows settings the split location to an arbitrary value.

Passing an empty string for the separator results in splitting to single characters.

Separators may be multiple characters.

### Additional examples

```handlebars  theme={"dark"}
{{#foreach (split "my-slug-is-long-too-long" separator="-")}}
  {{#unless @first}}{{#unless @last}}-{{/unless}}{{/unless}}{{#unless @last}}
    {{this}}
  {{/unless}}
{{/foreach}}

Outputs: 

my-slug-is-long-too

```

```handlebars  theme={"dark"}
{{#foreach (split "remove-this-from-my-slug" separator="remove-this-")}}
  {{this}}
{{/foreach}}

Outputs:

from-my-slug
```

```handlebars  theme={"dark"}
{{!-- custom.list-of-tags is a comma-separated list like apple,banana,pear --}}
{{#foreach (split @custom.list-of-tags)}} 
   {{> tag-loop slug=this}}
{{/foreach}}
```


# translate
Source: https://docs.ghost.org/themes/helpers/utility/translate

Usage: `{{t}}`

***

`{{t}}` is a helper to output text in your site language.

Ghost’s front-end and themes are fully translatable by enabling a publication language in the setting in Ghost admin, and using the translate helper to wrap around any plain text in your theme.

Learn more about [translation in Ghost at our FAQ](/faq/translation/).

## Making a theme translatable

Follow these steps to make your theme fully translatable:

#### 1. Create a `locales` folder and add language files

Create a folder called `locales`. If using a theme that is already translatable, this may exist already.

Inside the `locales` folder, add target language files for each translatable language used on your site. For example `locales/en.json` for English and `locales/es.json` for Spanish. [A valid language](https://www.w3schools.com/tags/ref_language_codes.asp) code must be used.

#### 2. Translate included sentences

Translate the sentences used in your theme inside your new language files.

For example, in `locales/en.json`:

```json  theme={"dark"}
{
    "Back": "Back",
    "Newer Posts": "Newer Posts",
    "Older Posts": "Older Posts",
    "Page {page} of {pages}": "Page {page} of {pages}",
    "Subscribe": "Subscribe",
    "Subscribe to {blogtitle}": "Subscribe to {blogtitle}",
    "Subscribed!": "Subscribed!",
    "with the email address": "with the email address",
    "Your email address": "Your email address",
    "You've successfully subscribed to": "You've successfully subscribed to",
    "A collection of posts": "A collection of posts",
    "A collection of 1 post": "A collection of 1 post",
    "A collection of % posts": "A collection of % posts",
    "Get the latest posts delivered right to your inbox": "Get the latest posts delivered right to your inbox",
    "Latest Posts": "Latest Posts",
    "<a href='{url}'>More posts</a> by {name}": "<a href='{url}'>More posts</a> by {name}",
    "No posts": "No posts",
    " (Page %)": " (Page %)",
    "Read More": "Read More",
    "Read <a href='{url}'>more posts</a> by this author": "Read <a href='{url}'>more posts</a> by this author",
    "See all % posts": "See all % posts",
    "Share this": "Share this",
    "Stay up to date! Get all the latest & greatest posts delivered straight to your inbox": "Stay up to date! Get all the latest & greatest posts delivered straight to your inbox",
    "This post was a collaboration between": "This post was a collaboration between",
    "youremail@example.com": "youremail@example.com",
    "1 post": "1 post",
    "% posts": "% posts",
    "1 min read": "1 min read",
    "% min read": "% min read"
}
```

And edited to translate into Spanish for `locales/es.json`:

```json  theme={"dark"}
{
    "Back": "Volver",
    "Newer Posts": "Artículos Siguientes",
    "Older Posts": "Artículos Anteriores",
    "Page {page} of {pages}": "Página {page} de {pages}",
    "Subscribe": "Suscríbete",
    "Subscribe to {blogtitle}": "Suscríbete a {blogtitle}",
    "Subscribed!": "¡Suscrito!",
    "with the email address": "con el correo electrónico",
    "Your email address": "Tu correo electrónico",
    "You've successfully subscribed to": "Te has suscrito con éxito a",
    "A collection of posts": "Una colección de artículos",
    "A collection of 1 post": "Una colección de 1 artículo",
    "A collection of % posts": "Una colección de % artículos",
    "Get the latest posts delivered right to your inbox": "Recibe los últimos artículos directamente en tu buzón",
    "Latest Posts": "Últimos Artículos",
    "<a href='{url}'>More posts</a> by {name}": "<a href='{url}'>Más artículos</a> de {name}",
    "No posts": "No hay artículos",
    " (Page %)": " (Página %)",
    "Read More": "Lee Más",
    "Read <a href='{url}'>more posts</a> by this author": "Lee <a href='{url}'>más artículos</a> de este autor",
    "See all % posts": "Ver todos los % artículos",
    "Share this": "Comparte",
    "Stay up to date! Get all the latest & greatest posts delivered straight to your inbox": "¡Mantente al día! Recibe todos los últimos y mejores artículos directamente en tu buzón",
    "This post was a collaboration between": "Este artículo fue una colaboración entre",
    "youremail@example.com": "tucorreo@ejemplo.com",
    "1 post": "1 artículo",
    "% posts": "% artículos",
    "1 min read": "1 min de lectura",
    "% min read": "% min de lectura",
    "< 1 min read": "< 1 min de lectura"
}
```

In your theme template, use the translate helper as follows:

```handlebars  theme={"dark"}
    <a href="#/portal/signup" data-portal="signup">{{t "Subscribe"}}</a>

    {{! output when Ghost Admin is set to "en" for English }}
    <a href="#/portal/signup" data-portal="signup">Subscribe</a>

    {{! output when Ghost Admin is set to "es" for Spanish }}
    <a href="#/portal/signup" data-portal="signup">Suscríbete</a>
```

It’s possible to use any translation key on the left, but readable English is advised in order to take advantage of the fallback option inside the `{{t}}` translation helper when no translation is available.

Dates, with month names, are automatically translated. You don’t need to include them in the translation files.

Use HTML entities instead of characters, for example `<` instead of `<`.

#### 3. Enable blog language

Verify that the `.json` translation file for your active theme is in place and then activate the language in the General settings of Ghost admin. Enter the correct language code into your settings menu and hit save.

#### 4. Ensure templates exist

To ensure that your theme is fully translatable, two core templates must exist in your theme. Check the following templates exist:

**pagination.hbs** - exists in `content/themes/mytheme/partials`, copy the [template](https://github.com/TryGhost/Ghost/blob/3d989eba2371235d41468f7699a08e46fc2b1e87/ghost/core/core/frontend/helpers/tpl/pagination.hbs)

**navigation.hbs** - exists in `content/themes/mytheme/partials`, copy the [template](https://github.com/TryGhost/Ghost/blob/3d989eba2371235d41468f7699a08e46fc2b1e87/ghost/core/core/frontend/helpers/tpl/navigation.hbs)

#### 5. Use the translation helper

Any plain text in your theme must be wrapped in the `{{t}}` translation helper, with `{{t` to the left of the text and `}}` to the right.

Look for any plain text in all of your theme’s `.hbs` template files and ensure the translation helper is present.

#### 6. Declare language in HTML

It’s advisable to add the HTML lang attribute to the `<html>` tag at the start of the theme’s `default.hbs` template, using Ghost’s `{{@site.locale}}` helper: `<html lang="{{@site.locale}}">`. `{{@site.locale}}` will automatically be replaced on the site with the corresponding language locale tag set in Ghost Admin.

#### 7. Reactivate the theme

To make the new changes effective, run `ghost restart`.

## Optional features

The translation helper can interact with many other handlebars expressions in order to implement more advanced translations within your theme.

Here are some of the most commonly used advanced translation features:

#### Placeholders

Placeholders are dynamic values that are replaced on runtime, and can be implemented using single braces. This is useful for translations if you need to insert dynamic data attributes to your translations.

For example, here is a placeholder in the theme translation file:

```json  theme={"dark"}
"Proudly published with {ghostlink}": "Publicado con {ghostlink}",
```

Which is defined in the theme template `default.hbs` using:

```handlebars  theme={"dark"}
{{{t "Proudly published with {ghostlink}" ghostlink="<a href=\"https://ghost.org\">Ghost</a>"}}}
```

Placeholders with data attributes can also be used, for example:

```handlebars  theme={"dark"}
{{t "Subscribe to {blogtitle}" blogtitle=@site.title}}
```

#### Subexpressions

The concept of subexpressions allows you to invoke multiple helpers in one expression.

For example, a `(t)` subexpression (instead of normal `{{t}}` helper) can be used as a parameter inside another helper such as `{{tags}}`.

This can be used to translate the prefix or suffix attribute of the `{{tags}}`, `{{authors}}` or `{{tiers}}` helper.

#### Plural helper

`{{plural}}` is a [formatting helper](/themes/helpers/utility/plural/) for outputting strings which change depending on whether a number is singular or plural.

This can be used in translations to output information such as number of posts:

```json  theme={"dark"}
"No posts": "No hay artículos",
"1 post": "1 artículo",
"% posts": "% artículos",
```

In the theme template `author.hbs`, several (t) subexpressions instead of normal `{{t}}` helpers can be used as parameters inside

```json  theme={"dark"}
{{plural ../pagination.total empty=(t "No posts") singular=(t "1 post") plural=(t "% posts")}}
```

#### Reading time helper

The [reading time helper](/themes/helpers/utility/reading_time/) can be used in translations to provide a reading time for your posts in the desired language.

For example, in `es.json`:

“1 min read”: “1 min de lectura”, “% min read”: “% min de lectura”, And in theme template post.hbs

And in the theme template `post.hbs`:

```handlebars  theme={"dark"}
{{reading_time minute=(t "1 min read") minutes=(t "% min read")}}
```

#### Pagination

The [`{{meta_title}}`](/themes/helpers/data/meta_data/) helper accepts a page parameter that can be used in conjunction with translations. By using the follow it’s possible to translate the word “Page” shown in the title of paginated pages:

```handlebars  theme={"dark"}
<title>{{meta_title page=(t "Page %")}}</title>
```


# Members
Source: https://docs.ghost.org/themes/members

The Members feature allows you to turn any site into a membership business with member signup, paid subscriptions and email newsletters.

***

Members can be activated using any theme by using the Portal feature — an embeddable memberships feature that can be enabled and customised from the Admin UI. Portal screens can also be accessed in your theme via URLs or data attributes.

<Frame>
    <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/324b141a-portal-links-admin_hu72ea77dfe2902b5b8f1e717e5c1c751c_474136_2376x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=5a3f3d34c0bd3fef3e915e7402d81278" alt="" data-og-width="2376" width="2376" data-og-height="1574" height="1574" data-path="images/324b141a-portal-links-admin_hu72ea77dfe2902b5b8f1e717e5c1c751c_474136_2376x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/324b141a-portal-links-admin_hu72ea77dfe2902b5b8f1e717e5c1c751c_474136_2376x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=1619de9ab2a78c83121784618265cc40 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/324b141a-portal-links-admin_hu72ea77dfe2902b5b8f1e717e5c1c751c_474136_2376x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7d3592560de9cbe5cbb22b10d9fb684c 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/324b141a-portal-links-admin_hu72ea77dfe2902b5b8f1e717e5c1c751c_474136_2376x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d6875f840ef2c727f67d25d26ea8c331 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/324b141a-portal-links-admin_hu72ea77dfe2902b5b8f1e717e5c1c751c_474136_2376x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=7a0b4464c8d592494438637ad3f45877 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/324b141a-portal-links-admin_hu72ea77dfe2902b5b8f1e717e5c1c751c_474136_2376x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d94e7ea5470a936f435f3dd2e2a1cf7e 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/324b141a-portal-links-admin_hu72ea77dfe2902b5b8f1e717e5c1c751c_474136_2376x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=aa701134ac4fa7188c6d1c443815017b 2500w" />
</Frame>

Portal links can use absolute or relative links, for example:

```html  theme={"dark"}
// Absolute URLs takes readers to the homepage and opens a Portal screen.
<a href="https://example.com/#/portal/signup">Subscribe</a>

// Relative URLs open Portal on the current page.
<a href="#/portal/signup">Subscribe</a>
```

When using the `data-portal` data attribute to control the Portal UI, additional classes `gh-portal-open` and `gh-portal-close` are added to the element to allow custom styling of open and closed states.

Alternatively, it’s possible to build entirely custom membership and signup flows directly into a theme using this guide.

***

## Signup forms

Add the `data-members-form` attribute to the form element and `data-members-email` to the email input field to create a standard email collection signup form:

```html  theme={"dark"}
<form data-members-form>
  <input data-members-email type="email" required="true"/>
  <button type="submit">Continue</button>
</form>
```

Add `data-members-name` to an input element to capture a member’s name at signup:

```html  theme={"dark"}
<form data-members-form>
  <label>
    Name
    <input data-members-name />
  </label>
  <label>
    Email
    <input data-members-email type="email" required="true"/>
  </label>
  
  <button type="submit">Subscribe</button>
</form>
```

Capture form errors with `data-members-error`. Errors could include too many attempts to sign up or trying to subscribe to a newsletter that no longer exists (see below):

```html  theme={"dark"}
<p data-members-error></p>
```

### Newsletter subscriptions

When a member signs up via the form, they are subscribed to the site’s default newsletter. However, it’s also possible to specify which newsletters members are subcribed to on signup by adding `data-members-newsletter` to an input element. In the example below, the member is subscribed to the Weekly Threads newsletter.

```html  theme={"dark"}
<form data-members-form>
  ...
  <input data-members-newsletter type="hidden" value="Weekly Threads" />
  
  <button type="submit">Subscribe</button>
</form>
```

Subscribe a member to multiple newsletters by including additional `input` elements:

```html  theme={"dark"}
<form data-members-form>
  ...
  <input data-members-newsletter type="hidden" value="Weekly Threads" />
  <input data-members-newsletter type="hidden" value="Shocking Revelations" />

  
  <button type="submit">Subscribe</button>
</form>
```

By using `hidden` inputs in the examples above, newsletter details are hidden from the user. But, you can allow users to choose which newsletters to subscribe to by using `radio` or `checkbox` elements:

```html  theme={"dark"}
<form data-members-form>
  ...
  <label>
    Newsletter Name
    <input data-members-newsletter type="checkbox" value="Newsletter Name" />
  </label>
  <label>
    Newsletter Two
    <input data-members-newsletter type="checkbox" value="Newsletter Two" />
  </label>
  
  <button type="submit">Subscribe</button>
</form>
```

Create a dynamic signup form at the theme level by using the [`get helper`](/themes/helpers/functional/get/) to fetch a site’s `newsletters`. Then, loop through the newsletters and add the `name` property to an `input` element. See below for an example implementation:

```handlebars  theme={"dark"}
<form data-members-form=>
  <input type="email" required data-members-email>
  {{#get "newsletters"}}
      {{#foreach newsletters}}
        <label>
          <input type="checkbox" value="{{name}}" data-members-newsletter />
					{{name}}
        </label>
      {{/foreach}}
  {{/get}}
  <button type="submit">Subscribe</button>
</form>
```

### Apply labels from a form

Labels are useful for managing, segmenting and auditing a members list, and can be applied manually in Ghost Admin, or automatically via a form, an integration or the API.

Apply labels from a specific a signup form using a hidden HTML input element, for example:

```html  theme={"dark"}
<form data-members-form="subscribe">
  <input data-members-label type="hidden" value="Early Adopters" />
  <input data-members-email type="email" required="true"/>
  <button type="submit">Subscribe</button>
</form>
```

### Extending forms

The `data-members-form` accepts a series of optional values to customise user flows:

* `data-members-form="signin"` – sends a signin email to existing members when a valid email is entered.
* `data-members-form="signup"` – sends a signup email to new members. Uses “sign up” in email text. If a valid email is present, a signin email is sent instead.
* `data-members-form="subscribe"` – sends a subscribe email. Uses “subscription” in email text. If a valid email is present, a signin email is sent instead.
* `data-members-autoredirect="false"` - when set to `false`, the user will be redirected to the publication’s homepage when logging in. When set to `true` (the default), the user will be redirected to the page where they signed up.

### Form states

Member forms pass a series of states, which are reflected in the HTML as classes for when the submission is loading, when the submission was successful, or when there is an error.

```html  theme={"dark"}
<form data-members-form class="loading">...</form>

<form data-members-form class="success">...</form>

<form data-members-form class="error">...</form>
```

### Error messages

Implement error messages when a form or subscription button causes an error by adding a child element to the `<form>` or `<a>` element with the attribute `data-members-error`.

```html  theme={"dark"}
<form data-members-form>
  ...
  <p data-members-error><!-- error message will appear here --></p>
</form>
```

### Sign-in forms

Custom sign-in forms in Ghost support both **magic link** authentication and **one-time codes**.

By default, sign-in forms send a magic link to the member’s email address. To also include a one-time code option, add the following attribute to your form element: `data-members-otc="true"`

**Example**

```html  theme={"dark"}
<form data-members-form="signin" data-members-otc="true">
  <input data-members-email type="email" required="true" placeholder="jamie@example.com" />
  <button type="submit">Sign in</button>
</form>
```

When `data-members-otc="true"` is present, successful submission of the form will display a modal via portal, no custom handling necessary, that lets the user enter their one-time code directly.

This allows members to choose whichever sign-in method works best — one-click via email, or by entering a code manually.

### Signing out

Give members the option to sign out of your site by creating a sign out button or link using the `data-members-signout` data attribute.

```html  theme={"dark"}
<a href="javascript:" data-members-signout>Sign out</a>
```

Using the `@member` object in conjunction with a sign out button allows you to show the signin link when the member is logged out, and a sign out link if a member is logged in.

```handlebars  theme={"dark"}
{{#if @member}}
  <a href="javascript:" data-members-signout>Sign out</a>
{{else}}
  <form data-members-form="signin">
    <input data-members-email type="email" required="true"/>
    <button type="submit">Sign in</button>
  </form>
{{/if}}
```

***

## Content visibility

Control how members access content on your site, and what content they’re able to read in full as a logged in member.

### Content

All members that are logged in to your site have an access level attached to them. To correspond, all posts have a `visibility` setting attached to the `content`.

This setting is applied in the Admin UI as the [post access level](https://ghost.org/help/protected-content/) on each individual post.

### Access

`access` is a variable that calculates the access level of the member viewing the post and the access level setting applied to the post. `access` will return `true` if the member’s access matches, or exceeds, the access level of the post, and `false` if it doesn’t match.

```handlebars  theme={"dark"}
{{#post}}
  <h1>{{title}}</h1>

  {{#if access}}
    <p>Thanks for being a member...</p>
  {{else}}
    <p>You need to become a member in order to read this post... </p>
  {{/if}}

  {{content}}
{{/post}}
```

### Default CTA

With the `{{content}}` helper, visitors who don’t have access to a post (determined by the `access` property) will see a default call to action in the content area instead, prompting users to upgrade their subscription. Used in conjunction with a free public preview in post content, the CTA will be displayed after the free preview.

<Frame>
    <img src="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2d462c05-content-cta_hu3d640371aa932b7b360881a3df965f9b_54918_1462x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=ab826e92b8835bfb4d4ee8e3b126a36a" alt="" data-og-width="1462" width="1462" data-og-height="476" height="476" data-path="images/2d462c05-content-cta_hu3d640371aa932b7b360881a3df965f9b_54918_1462x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2d462c05-content-cta_hu3d640371aa932b7b360881a3df965f9b_54918_1462x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=2eb05fc9d0c46e2a5a4f5e0bd68663f4 280w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2d462c05-content-cta_hu3d640371aa932b7b360881a3df965f9b_54918_1462x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=3e113b921090cf416c9c8b10b0318c8f 560w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2d462c05-content-cta_hu3d640371aa932b7b360881a3df965f9b_54918_1462x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d79a51dde9d444c0eb1da0b858f1cd9e 840w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2d462c05-content-cta_hu3d640371aa932b7b360881a3df965f9b_54918_1462x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=d3f24369ead7ac15718e5b71bdd19086 1100w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2d462c05-content-cta_hu3d640371aa932b7b360881a3df965f9b_54918_1462x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=fb516a32342f083579547b46a6ab49a4 1650w, https://mintcdn.com/ghost/5_xpDDjqLTzEezAK/images/2d462c05-content-cta_hu3d640371aa932b7b360881a3df965f9b_54918_1462x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=5_xpDDjqLTzEezAK&q=85&s=c654cf5111b4765c3a1c5c17cc9939dd 2500w" />
</Frame>

The default CTA can be overridden by providing a `./partials/content-cta.hbs` template file in your theme. The default content CTA [provided by Ghost](https://github.com/TryGhost/Ghost/blob/3d989eba2371235d41468f7699a08e46fc2b1e87/ghost/core/core/frontend/helpers/tpl/content-cta.hbs) may be used as a reference.

### The `@member` object

The `@member` object can be used to determine which content within the theme is exposed depending on the access level of the member. This is achieved using an `#if` statement:

```handlebars  theme={"dark"}
{{#if @member}}
  <p>Thanks for becoming a member 🎉</p>
{{else}}
  <p>You should totally sign up... 🖋</p>
{{/if}}
```

Using `@member.paid` allows you to expose different content to members who have an active paid subscription.

```handlebars  theme={"dark"}
{{#if @member.paid}}
  <p>Thanks for becoming a paying member 🎉</p>
{{/if}}
```

`@member.paid` returns `true` for members with active subscriptions in states “active”, “trialing”, “unpaid” and “past\_due”. To revoke access for members with failing payments, update your [Stripe settings](https://dashboard.stripe.com/settings/billing/automatic) to automatically cancel subscriptions after all payment attempts have failed.

These two boolean values can be used together to customise UI and messages within a theme to a particular segment of your audience:

```handlebars  theme={"dark"}
{{#if @member.paid}}
  <p>Thanks for becoming a paying member 🎉</p>
{{else if @member}}
  <p>Thanks for being a member 🙌</p>
{{else}}
  <p>You should totally sign up... 🖋</p>
{{/if}}
```

### Visibility

The `visibility` attribute is relative to the post or page, and is useful for providing templates with extra attribute information depending on the viewer status. `visibility` has 3 possible values: `public`, `members` or `paid` .

```handlebars  theme={"dark"}
<article class="post post-access-{{visibility}}">
  <h1>{{title}}</h1>
  {{content}}
</article>
```

An example use case could be to show a particular icon next to the title of a post:

```handlebars  theme={"dark"}
<h1>
  {{title}}
  <svg>
    <use xlink:href="#icon-{{visibility}}"></use>
  </svg>
</h1>
```

### `visibility` in posts

By default, all posts (including those that are set to `members-only` or `paid-members only`) will appear in post archives unless the `visibility` parameter is included with the `#foreach` helper:

```handlebars  theme={"dark"}
{{#foreach visibility="paid"}}
  <article>
    <h2><a href="{{url}}">{{title}}</a></h2>
  </article>
{{/foreach}}
```

The content of the posts is still restricted based on the access level of the logged in member.

### `visibility` with `#has`

Using the visibility flag with the `#has` helper allows for more unique styling between `public`, `members` and `paid` posts. For example:

```handlebars  theme={"dark"}
{{#foreach posts}}
  <article>
    {{#has visibility="paid"}}
      <span class="premium-label">Premium</span>
    {{/has}}
    <h2><a href="{{url}}">{{title}}</a></h2>
  </article>
{{/foreach}}
```

***

## Checkout buttons

Turn your membership site into a business with paid subscriptions via Stripe, to offer paid content on a monthly or yearly basis.

### Subscription plans

There are currently two types of plans for each tier in Members: monthly and yearly. [Find out how to connect a Stripe account.](https://ghost.org/help/setup-members/#connect-a-stripe-account/).

Once Stripe is properly configured, it’s possible to direct visitors to a Stripe payment form pre-filled with the selected plan, by adding buttons with the `data-portal` attribute pointing to monthly or yearly price of a tier. The data attribute for monthly/yearly plan of a tier can be fetched from Portal settings in your Admin URL - `/ghost/#/settings/members?showPortalSettings=true`.

```html  theme={"dark"}
<a href="javascript:" data-portal="signup/TIER_ID/monthly">Monthly plan</a>

<a href="javascript:" data-portal="signup/TIER_ID/yearly">Yearly plan</a>
```

***

## Member profile pages

It’s possible to expose information about a member in a Ghost theme to allow members to manage their own subscriptions, or update their details when logged in.

<Frame>
    <img src="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4f101771-theme-account-example_hua1cc91f659d30ed537e78ceeee649a6e_60374_800x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=6db050bf041330df6ed7ce1a4950556d" alt="" data-og-width="800" width="800" data-og-height="472" height="472" data-path="images/4f101771-theme-account-example_hua1cc91f659d30ed537e78ceeee649a6e_60374_800x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4f101771-theme-account-example_hua1cc91f659d30ed537e78ceeee649a6e_60374_800x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=279d412ad9c48b9412f30e0b74227978 280w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4f101771-theme-account-example_hua1cc91f659d30ed537e78ceeee649a6e_60374_800x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=8a81580e7c444a30a0f58e267c9a5d3c 560w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4f101771-theme-account-example_hua1cc91f659d30ed537e78ceeee649a6e_60374_800x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=3475a61f06a6e0319f3ce614772d7399 840w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4f101771-theme-account-example_hua1cc91f659d30ed537e78ceeee649a6e_60374_800x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=3a14fbea259cf6db0da4d316700d0d87 1100w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4f101771-theme-account-example_hua1cc91f659d30ed537e78ceeee649a6e_60374_800x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=cde0927683e01c5343333a5b6b0e2e7c 1650w, https://mintcdn.com/ghost/ZMdvGdmwew7ypzvu/images/4f101771-theme-account-example_hua1cc91f659d30ed537e78ceeee649a6e_60374_800x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=ZMdvGdmwew7ypzvu&q=85&s=66b47e2bbb636eef9505e48be5973910 2500w" />
</Frame>

### Member attributes

The `@member` object has a series of attributes that expose the information required to create a member profile page:

* `@member` – The member object, evaluates to `true` or `false` if the viewer is a member or not
* `@member.paid` –The member’s payment status, returns `true` or `false` if the member has an active paid subscription
* `@member.email` –The member’s email address
* `@member.name` – The member’s full name
* `@member.firstname` – The member’s first name (everything before the first whitespace character in the member’s full name)
* `@member.uuid` – A unique identifier for a member for use with analytics tracking such as Google Tag Manager

### Member subscriptions

It’s also possible to retrieve and expose information about a member’s subscription using data that comes from Stripe using `@member.subscriptions`.

Members may have multiple subscriptions, provided as an array. Subscription data can be exposed using a `#foreach`:

```handlebars  theme={"dark"}
{{#foreach @member.subscriptions}}

  <p>Name: <strong>{{customer.name}}</strong></p>

  <p>Plan type: <strong>{{plan.nickname}}</strong></p>

  <p>Status: <strong>{{status}}</strong></p>

{{/foreach}}
```

### Subscription attributes

Subscription data comes from Stripe meaning a valid Stripe account connected to Ghost is required. Using subscription data in a local environment requires the [Stripe CLI tool](https://stripe.com/docs/stripe-cli).

* `id` –The Stripe ID of the subscription
* `avatar_image` — The customers avatar image, pulled in from [Gravatar](https://en.gravatar.com/). If there is not one set for their email a transparent `png` will be returned as a default
* `customer.id` – The Stripe ID of the customer
* `customer.name` – The name of the customer in Stripe
* `customer.email` – The email of the customer in Stripe
* `plan.id` – The Stripe ID of the plan
* `plan.nickname` – The Stripe nickname of the plan (currently only “Monthly” or “Yearly”)
* `plan.interval` – The Stripe plan payment interval (currently only “month” or “year”)
* `plan.currency` –The currency code of the plan as an ISO currency code
* `plan.amount` – The amount of the Stripe plan in the smallest currency denomination (e.g. USD \$5 would be “500” cents)
* `status` – The status of the subscription (can be one of: “active”, “trialing”, “unpaid”, “past\_due”, “canceled”)
* `start_date` –The date which the subscription was first started, can be used with the `{{date}}` helper
* `default_payment_card_last4` – The last 4 digits of the card that paid the subscription
* `current_period_end` – The date which the subscription has been paid up until, can be used with the `{{date}}` helper

### Member account editing

Members may want to update their billing information. Rather than contacting the site owner the member can be linked to a page to update their details with a single button:

```html  theme={"dark"}
<a href="javascript:" data-members-edit-billing>Edit billing info</a>
```

Additional attributes can be used to direct the member to different URLs if they update their billing information or cancel their subscription:

```html  theme={"dark"}
<a href="javascript:"
  data-members-edit-billing
  data-members-success="/billing-update-success/"
  data-members-cancel="/billing-update-cancel/"
>Edit billing info</a>
```

### The `price` helper

The `{{price}}` helper formats monetary values from their smallest denomination to a human readable denomination with currency formatting. This is best used in the context of a subscription plan to format Stripe plan amounts (see `plan.amount` above) or outputting prices for tiers. Example:

```handlebars  theme={"dark"}
{{price plan}}
```

This will output `$5`.

The `{{price}}` helper has many options with detailed documentation [here](/themes/helpers/data/price/).

### Cancel links

The `{{cancel_link}}` helper is designed to output links to cancel or continue a subscription, so that your members can manage their own subscriptions.

This helper wraps all of the internals needed to cancel an active subscription or to continue the subscription if it was previously canceled.

The helper must be used in the `@member.subscriptions` context, for example:

```handlebars  theme={"dark"}
<!-- Usage Context -->

{{#foreach @member.subscriptions}} {{cancel_link}} {{/foreach}}
```

The HTML markup generated by this code looks like this:

```html  theme={"dark"}
<!-- Generated HTML -->

<a class="gh-subscription-cancel" data-members-cancel-subscription="sub_*****" href="javascript:">
    Cancel subscription
</a>
<span class="gh-error gh-error-subscription-cancel" data-members-error><!-- error message will appear here --></span>
```

The `{{cancel_link}}` helper accepts a number of optional attributes:

* `class` - defaults to `gh-subscription-cancel`
* `errorClass` - defaults to `gh-error gh-error-subscription-cancel`
* `cancelLabel` - defaults to `Cancel subscription`
* `continueLabel` - defaults to `Continue subscription`

Here’s an example of how you can use the helper with all of the attributes:

```handlebars  theme={"dark"}
<!-- Usage -->

{{cancel_link
  class="cancel-link"
  errorClass="cancel-error"
  cancelLabel="Cancel!"
  continueLabel="Continue!"
}}
```

This would produce the following HTML for previously canceled subscription:

```html  theme={"dark"}
<!-- Generated HTML -->

<a class="cancel-link" data-members-continue-subscription="sub_*****" href="javascript:">
    Continue!
</a>
<span class="cancel-error" data-members-error><!-- error message will appear here --></span>
```

Here’s an example of the `{{cancel_link}}` helper in use in the members-enabled theme [Lyra](https://github.com/TryGhost/Lyra/) within the [account.hbs](https://github.com/TryGhost/Lyra/blob/4ca9576/members/account.hbs/#L15-L65) file.

It’s used inside a `{{#foreach @member.subscriptions}}` loop which provides the helper the context needed to generate an appropriate link, and is surrounded by other useful information displayed to the member.

```html  theme={"dark"}
<!-- account.hbs -->

{{#foreach @member.subscriptions}}
  <div class="subscription">
    {{#if cancel_at_period_end}}
      <p>
        <strong class="subscription-expiration-warning">Your subscription will expire on {{date current_period_end format="DD MMM YYYY"}}.</strong> If you change your mind in the mean time you can turn auto-renew back on to continue your subscription.
      </p>
    {{else}}
      <p>
        Hey! You have an active {{@site.title}} account with access to all areas. Get in touch if have any problems or need some help getting things updated, and thanks for subscribing.
      </p>
    {{/if}}
    <div class="subscriber-details">
      <div class="subscriber-detail">
        <label class="subscriber-detail-label">Email address</label>
        <span class="subscriber-detail-content">{{@member.email}}</span>
      </div>
      <div class="subscriber-detail">
        <label class="subscriber-detail-label">Your plan</label>
        <span class="subscriber-detail-content">{{price plan}}/{{plan.interval}}</span>
      </div>
      <div class="subscriber-detail">
        <label class="subscriber-detail-label">Card</label>
        <span class="subscriber-detail-content">**** **** **** {{default_payment_card_last4}}</span>
      </div>
      <div class="subscriber-detail">
        <label class="subscriber-detail-label">
          {{#if cancel_at_period_end}}
            Expires
          {{else}}
            Next bill date
          {{/if}}
        </label>
        <span class="subscriber-detail-content">{{date current_period_end format="DD MMM YYYY"}}</span>
      </div>
    </div>
    {{cancel_link}}
  </div>
{{/foreach}}
```


# URLs & Dynamic Routing
Source: https://docs.ghost.org/themes/routing

Routing is the system that maps URL patterns to data and templates within Ghost. It comes pre-configured by default, but it can also be customized extensively to build powerful custom site structures.

***

All of Ghost’s routing configuration is defined in `content/settings/routes.yaml` - which you can edit directly, but you can also upload/download this file from within your Ghost admin panel under `Settings » Labs`.

If you edit the file manually, you’ll need to restart Ghost to see the changes, but if you upload the file in admin then your routes will automatically be updated right away.

### Base configuration

The default `routes.yaml` which comes with all new installs of Ghost sets things up with a traditional publication structure. The homepage of the site is a reverse-chronological list of the site’s posts, with each post living on its own URL defined by a `{slug}` parameter, such as `my-great-post`. There are also additional archives of posts sorted by tag and author.

```yaml  theme={"dark"}
## routes.yaml

routes:

collections:
  /:
    permalink: /{slug}/
    template: index

taxonomies:
  tag: /tag/{slug}/
  author: /author/{slug}/
```

For most publications and use cases, this structure is exactly what’s needed and it’s not necessary to make any edits in order to use Ghost or develop a theme for it.

### What’s YAML?

YAML stands for **Y**et **A**nother **M**arkup **L**anguage - because there aren’t enough unfunny acronyms in computer science. You can think of it loosely like JSON without all the brackets and commas. In short, it’s a document format used to store nested `key:value` pairs, commonly used for simple/readable configuration.

The most important thing to know when working with YAML is that it uses indentation to denote structure. That means the **only** type of nesting which works is **2 spaces**.

The most common reason for YAML files not working is when you accidentally use the wrong type or quantity of spacing for indentation. So keep a close eye on that!

### When to use dynamic routing

Maybe you want your homepage to be a simple landing page, while all of your posts appear on `site.com/writing/`. Maybe you actually want to split your site into two main collections of content, like `/blog/` and `/podcast/`. Maybe you just want to change the URL of your archives from `/tag/news/` to `/archive/news/`.

If you’re looking to create an alternative site structure to the one described above, then dynamic routing is what you need in order to achieve all your hopes and dreams.

Okay, maybe not all your hopes and dreams but at least your URLs. We’ll start there.

Hopes and dreams come later.

## Custom Routes

Template routes allow you to map individual URLs to specific template files within a Ghost theme. For example: make `/custom/` load `custom.hbs`

Using template routes is very minimal. There’s no default data associated with them, so there isn’t any content automatically loaded in from Ghost like there is with posts and pages. Instead, you can write all the custom code you like into a specific file, and then have that file load on the route of your choice.

Custom routes are handy for creating static pages outside of Ghost Admin, when you don’t want them to be editable, they use lots of custom code, or you need to create a specific custom URL with more than a basic slug.

Don’t worry, we’ll go through some examples of all of the above!

***

### Basic routing

The [default routes.yaml file](/themes/routing/) which comes with Ghost contains an empty section under `routes`, and this is where custom routes can be defined.

Let’s say you’ve got a big **Features** landing page with all sorts of animations and custom HTML. Rather than trying to cram all the code into the Ghost editor and hope for the best, you can instead store the code in a custom template called `features.hbs` - and then point a custom route at it:

```yaml  theme={"dark"}
routes:
  /features/: features
```

The first half is the URL: `site.com/features/` - the second is the template which will be used: `features.hbs` - you leave off the `.hbs` because Ghost takes care of that part. Now you’ve created a new static page in Ghost, without using the admin!

You can also use custom routes to simulate subdirectories. For example, if you want a “Team” page to appear, for navigational purposes, as if it’s a subpage of your “About” page.

```yaml  theme={"dark"}
routes:
  /features/: features
  /about/team/: team
```

Now `site.com/about/team/` is a dedicated URL for a static `team.hbs` template within your theme. Routes can be just about anything you like using letters, numbers, slashes, hyphens, and underscores.

***

### Loading data

The downside of using an `/about/team` route to point at a static `team.hbs` template is that it’s… well: static.

Unlike the **Features** the team page needs to be updated fairly regularly with a list of team members; so it would be inconvenient to have to do that in code each time. What we really want is to keep the custom route, but have the page still use data stored in Ghost. This is where the `data` property comes in.

```yaml  theme={"dark"}
routes:
  /features/: features
  /about/team/:
    template: team
    data: page.team
```

This will assign all of the data from a Ghost **page** with a slug of `team` to the new route, and it will also automatically redirect the original URL of the content to the new one.

Now, the data from `site.com/team/` will be available inside the `{{#page}}` block helper in a custom `team.hbs` template on `site.com/about/team/` and the old URL will redirect to the new one, to prevent the content being duplicated in two places.

***

### Building feeds & APIs

In the examples used so far, routes have been configured to generate a single page, some data and a template, but that’s not all routes can do. You can make a route output just about anything, for instance a custom RSS feed or JSON endpoint.

If you create a custom template file with a [\{\{#get}}](/themes/helpers/functional/get/) helper API query loading a list of filtered posts, you can return those posts on a custom route with custom formatting.

```yaml  theme={"dark"}
routes:
  /podcast/rss/:
    template: podcast-feed
    content_type: text/xml
```

Generally, routes render HTML, but you can override that by specifying a `content_type` property with a custom mime-type.

For example, you might want to build a custom RSS feed to get all posts tagged with `podcast` and deliver them to iTunes. In fact, [here’s a full tutorial](https://ghost.org/tutorials/custom-rss-feed/) for how to do that.

Or perhaps you’d like to build your own little public JSON API of breaking news, and provide it to other people to be able to consume your most important updates inside their websites and applications? That’s fine too, you’d just pass `json` as the `content_type`.

## Collections

Collections are the backbone of how posts on a Ghost site are organized, as well as what URLs they live on.

You can think of collections as major sections of a site that represent distinct and separate types of content, for example: `blog` and `podcast`.

**Collections serve two main purposes:**

1. To display all posts contained within them on a paginated index route
2. To determine the URL structure of their posts and where they ’live’ on the site. For this reason, posts can only ever be in **one** collection.

A post must either be a blog or a podcast, it can’t be both.

***

### The default collection

The [default routes.yaml file](/themes/routing/) which comes with Ghost contains just a single collection on the root `/` URL which defines the entire structure of the site.

```yaml  theme={"dark"}
collections:
  /:
    permalink: /{slug}/
    template: index
```

Here, the home route of `site.com` will display all posts, using the `index.hbs` template file, and render each post on a URL determined by the `{slug}` created in the Ghost editor.

In short: This is exactly how and why Ghost works by default!

***

### Using a custom homepage

One of the most minimal examples of editing the default collection is to move it to a new location and make room for a custom home page.

```yaml  theme={"dark"}
routes:
  /: home

collections:
  /blog/:
    permalink: /blog/{slug}/
    template: index
```

Using an example from the previous section on [custom routes](/themes/routing/#routes), the home `/` route is now pointing at a static template called `home.hbs` — and the main collection has now been moved to load on `site.com/blog/`. Each post URL is also prefixed with `/blog/`.

***

### Filtering collections

Much like the [\{\{#get}}](/themes/helpers/functional/get/) helper, collections can be filtered to contain only a subset of content on your site, rather than all of it.

```yaml  theme={"dark"}
collections:
  /blog/:
    permalink: /blog/{slug}/
    template: blog
    filter: primary_tag:blog
  /podcast/:
    permalink: /podcast/{slug}/
    template: podcast
    filter: primary_tag:podcast
```

Returning to the earlier example, all of the posts within Ghost here are divided into two collections of `blog` and `podcast`.

#### Blog collection

* **Appears on:** `site.com/blog/`
* **Post URLs:** `site.com/blog/my-story/`
* **Contains posts with:** a `primary_tag` of `blog`

#### Podcast collection

* **Appears on:** `site.com/podcast/`
* **Post URLs:** `site.com/podcast/my-episode/`
* **Contains posts with:** a `primary_tag` of `podcast`

The `primary_tag` property is simply the *first* tag that is entered in the tag list inside Ghost’s editor. It’s useful to filter against the **primary** tag because it will always be unique.

If posts match the filter property for *multiple* collections this can lead to problems with post rendering and collection pagination, so it’s important to try and always keep collection filters unique from one another.

***

### Doing more with collections

Collections are an incredibly powerful way to organize your content and your site structure, so its only limits are your imagination — and our clichés.

#### Loading data into the index

Much like [custom routes](/themes/routing/#routes), collections can also accept a data property in order to pass in the data to the collection’s index. For example, you might have a collection called `portfolio` which lists all of your most recent work. But how do you set the title, description, and metadata for *that* collection index?

```yaml  theme={"dark"}
collections:
  /portfolio/:
    permalink: /work/{slug}/
    template: work
    filter: primary_tag:work
    data: tag.work
```

Now, your `work.hbs` template will have access to all of the data (and metadata) from your `work` tag. And don’t forget: `site.com/tag/work/` will now also be redirected to `site.com/portfolio/` — so no duplicate content!

#### Creating multi-lang sites

Another really popular use for collections is for sites that publish content in multiple languages and want to create distinct areas and URL patterns for each locale.

```yaml  theme={"dark"}
collections:
  /:
    permalink: /{slug}/
    template: index
    filter: 'tag:-hash-de'
  /de/:
    permalink: /de/{slug}/
    template: index-de
    filter: 'tag:hash-de'
```

This would set the base URL to be in the site’s default language, and add an additional `site.com/de/` section for all posts in German, tagged with a private tag of `#de`. Using [Private tags](https://ghost.org/help/organizing-content/#internal-tags) means these tags wouldn’t be shown on the front end but can still be treated differently with Handlebars templating. The main collection excludes these same posts to avoid any overlap.

## Taxonomies

Taxonomies are groupings of posts based on a common relation. In Ghost, this is always defined by the post’s author or tag

Using taxonomies, Ghost will automatically generate post archives for tags and authors like `/tag/getting-started/` which will render a list of associated content.

Unlike [collections](/themes/routing/#collections), posts can appear in multiple taxonomies, and the post’s URL is not affected by which taxonomies are applied.

Taxonomies are structured like this:

```yaml  theme={"dark"}
taxonomies:
  tag: /tag/{slug}/
  author: /author/{slug}/
```

If a post by `Cameron` is tagged with `News` then it will be included in archives appearing on:

* `site.com` – (The collection index)
* `site.com/author/cameron`
* `site.com/tag/news/`

Each of these comes with its own automatically generated RSS feeds that are accessed by adding /rss/ to the end of the URL.

***

### Customising taxonomies

The configuration options for taxonomies are a lot more basic than [routes](/themes/routing/#routes) and [collections](/themes/routing/#collections). You can’t define new or custom taxonomies, you can only modify those which are already there and adapt their syntax a small amount.

```yaml  theme={"dark"}
taxonomies:
  tag: /topic/{slug}/
  author: /host/{slug}/
```

If you don’t like the prefixes for taxonomies, you can customize them to something else that suits your site and your content better. If you’re running a publication that is primarily a podcast, for example, you might prefer `host` and `topic`.

***

### Removing taxonomies

One small extra trick is that you can actually remove taxonomies entirely and not generate those pages for your site. If you prefer to keep things minimal, just leave the taxonomies field empty.

```yaml  theme={"dark"}
taxonomies:
  ## Nothing but silence
```

Just make sure you also update your template files to not link to any tag or author archives, which will now 404!

## Channels

If you want something more flexible than taxonomies, but less rigid than collections, then channels might be for you.

A channel is a custom stream of paginated content matching a specific filter. This allows you to create subsets and supersets of content by combining or dividing existing posts into content hubs.

Unlike [collections](/themes/routing/#collections), channels have no influence over a post’s URL or location within the site, so posts can belong to any number of channels.

**The best way to think of channels is as a set of permanent search results.** It’s a filtered slice of content from across your site, without modifying the content itself.

***

### Creating a channel

Channels are defined as a [custom route](/themes/routing/#routes), with a custom `controller` property called `channel`, and a filter to determine which posts to return.

```yaml  theme={"dark"}
routes:
  /apple-news/:
    controller: channel
    filter: tag:[iphone,ipad,mac]
  /editors-column/:
    controller: channel
    filter: tag:column+primary_author:cameron
```

In this example, there are two channels. The first is a channel that will return any posts tagged `iPhone`, `iPad` or `Mac` on a custom route of `site.com/apple-news/`.

The second is a special Editor’s Column area, which will return any posts tagged with `Column`, but only if they’re explicitly authored by `Cameron`.

These are two small examples of how you can use channels to include and exclude groups of posts from appearing together on a custom paginated route, with full automatic RSS feeds included as standard. Just add `/rss/` to any channel URL to get the feed.

***

### When to use channels vs collections

Collections and channels share a lot of similarities because they’re both methods of filtering a set of posts and returning them on a custom URL.

So how do you know when to use which?

#### You should generally use a collection when…

There’s a need to define permanent site structure and information architecture

* **You’re sorting different types/formats of content**\
  *eg. posts are blog posts OR podcasts*
* **You’re filtering incompatible content**\
  *eg. posts are either in English OR German*
* **You want the parent filter to influence the post’s URL**\
  *eg. an index page called `/news/` and posts like `/news/my-story/`*

#### You might be better off with a channel if…

All you need is a computed view of a subsection of existing content

* **You’re combining/grouping different pieces of content**\
  *eg. posts tagged with `news` AND `featured`*
* **You’re dividing existing streams of content with multiple properties**\
  *eg. posts tagged with `news` but NOT authored by `steve`*
* **You want to be able to update/change properties without affecting post URLs**\
  *eg. quickly creating/destroying new sections of a site without any risk*

If you’re still not sure which is the best fit for you, drop by the [Ghost Forums](https://forum.ghost.org) and share what structure you’re hoping to accomplish. There’s a large community of Ghost developers around to help.

## Index of all available properties

| Property       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `template`     | Determines which Handlebars template file will be used for this route. Defaults to `index.hbs` if not specified.                                                                                                                                                                                                                                                                                                                                                                                                 |
| `permalink`    | The generated URL for any post within a collection. Can contain dynamic variables based on post data:<br />• `{id}` - unique set of characters, eg. `5982d807bcf38100194efd67`<br />• `{slug}` - the post slug, eg. `my-post`<br />• `{year}` - publication year, eg. `2019`<br />• `{month}` - publication month, eg. `04`<br />• `{day}` - publication day, eg. `29`<br />• `{primary_tag}` - slug of first tag listed in the post, eg. `news`<br />• `{primary_author}` - slug of first author, eg. `cameron` |
| `filter`       | Extensively filter posts returned in collections and channels using the full power and syntax of the [Ghost Content API](/content-api/#filtering) For example `author:cameron+tag:news` will return all posts published by Cameron, tagged with ‘News’. Mix and match to suit.                                                                                                                                                                                                                                   |
| `order`        | Choose any number of fields and sort orders for your content:<br />• `published_at desc` - *default*, newest post first<br />• `published_at asc` - chronological, oldest first<br />• `featured desc, published_at desc` - featured posts, then normal posts, newest first                                                                                                                                                                                                                                      |
| `data`         | Fetch & associate data from the Ghost API with a specified route. The source route of the data will be redirected to the new custom route.<br />• `post.slug` - get data with => `{{#post}}`<br />• `page.slug` - get data with => `{{#page}}`<br />• `tag.slug` - get data with => `{{#tag}}`<br />• `author.slug` - get data with => `{{#author}}`                                                                                                                                                             |
| `rss`          | Collections and channels come with automatically generated RSS feeds which can be disabled by setting the `rss` property to `false`                                                                                                                                                                                                                                                                                                                                                                              |
| `content_type` | Specify the mime-type for the current route, default: `HTML`                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `controller`   | Add a custom controller to a route to perform additional functions. Currently the only supported value is `channel`                                                                                                                                                                                                                                                                                                                                                                                              |

## Redirects

In addition to creating routes, you can also create redirects for any time there are any changes in your URLs and you need to forward visitors

### Accessing the redirects file

<Note>
  If you’ve updated your site from an earlier version (prior to 4.0), your redirects may be in JSON format. Both formats are still supported, but JSON support will be removed in a later version.
</Note>

The `redirects.yaml` file is located in `content/data/redirects.yaml` and - like `routes.yaml` - can also be downloaded/uploaded in the settings in Ghost Admin.

### File structure

Refer to [Implementing redirects in Ghost](https://ghost.org/tutorials/implementing-redirects/) for more details about the file structure.

### Implementation

Upload your new `redirects.yaml` file in Ghost admin in the settings. This is the recommended method.

To replace the YAML file on the server, ensure it exists in `content/data/redirects.yaml` and restart Ghost for your changes to take effect.

### When not to use `redirects.yaml`

There are some instances where it is not recommended to use the `redirects.yaml` file:

* Page rules for www or HTTP/HTTPS redirection should always be implemented with your DNS provider.
* Ghost automatically forces trailing slashes, so you do not need to write any page rules to accommodate for duplicate content caused by this.
* If you’re trying to change the URL structure of your publication, the recommended way to do this is with dynamic routing and the `routes.yaml` file. (However, you may still need to redirect existing content using `redirects.yaml`).

## Final Tips

Ghost’s dynamic routing system is an extremely powerful way to build advanced structures for your site, and it’s hard to document every possible example of what can be done with it in comprehensive detail.

### Detailed tutorials

While these docs cover simple examples and broad use cases, you’ll find more detailed and specific use cases of how to build different types of publications in these tutorials:

* [Make an iTunes Podcast RSS feed](https://ghost.org/tutorials/custom-rss-feed/)
* [Use a custom homepage](https://ghost.org/tutorials/custom-homepage/)
* [How to build specialized content hubs](https://ghost.org/tutorials/content-collections/)
* [Define a custom order for posts](https://ghost.org/tutorials/change-post-order/)

Head over to the [Ghost tutorials](https://ghost.org/tutorials/) section to find even more tutorials about how to build different types of themes and websites with Ghost.

***

### Limitations & troubleshooting

As you work further with dynamic routing it’s worth keeping in mind that there are some limitations to what you’re able to do with it. Here are a few of the most common areas where you’ll find the edges of what’s possible:

**Slugs can conflict**

Dynamic routing has no concept of what slugs are used in Ghost, and vice-versa. So if you create a route called `/about/` and a page in Ghost called `about` then one of them is going to work, but not both. You’ll need to manage this manually.

**Collections must be unique**

If you have a collection filtering for posts tagged with `camera` and another filtering for posts tagged with `news` - then you will run into problems if a post is tagged with both `camera` and `news`. You should either trust your authors to use the correct tags, or base collections on properties that are always unique, like `primary_tag`.

**Trailing slashes are required**

You probably noticed that all the examples here use trailing slashes on routes, which is because these are required for dynamic routing to function correctly.


# Search
Source: https://docs.ghost.org/themes/search

Ghost has a native search feature that can be accessed via URL or implemented directly into themes using a single data attribute.

***

<Frame>
  <img src="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fe3de440-search-in-ghost_huac1f49fc436e5098ff1c22395a576ebf_186857_1074x0_resize_q100_h2_box_3.webp?fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=a7a8653ab5b60066c159ffb84c4e9455" data-og-width="1074" width="1074" data-og-height="555" height="555" data-path="images/fe3de440-search-in-ghost_huac1f49fc436e5098ff1c22395a576ebf_186857_1074x0_resize_q100_h2_box_3.webp" data-optimize="true" data-opv="3" srcset="https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fe3de440-search-in-ghost_huac1f49fc436e5098ff1c22395a576ebf_186857_1074x0_resize_q100_h2_box_3.webp?w=280&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=fc1b66ae05513493efb5be67766b50d2 280w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fe3de440-search-in-ghost_huac1f49fc436e5098ff1c22395a576ebf_186857_1074x0_resize_q100_h2_box_3.webp?w=560&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=d5641d3bd5dbd4af0eba41eedd7ed75d 560w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fe3de440-search-in-ghost_huac1f49fc436e5098ff1c22395a576ebf_186857_1074x0_resize_q100_h2_box_3.webp?w=840&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=97d0c55af3c914e9890bcfbf671f6f89 840w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fe3de440-search-in-ghost_huac1f49fc436e5098ff1c22395a576ebf_186857_1074x0_resize_q100_h2_box_3.webp?w=1100&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=ebdcf962d1b7b4e4e8a54dfdbba482d3 1100w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fe3de440-search-in-ghost_huac1f49fc436e5098ff1c22395a576ebf_186857_1074x0_resize_q100_h2_box_3.webp?w=1650&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=f83d7e731b3b6ff970aa8780f02d9162 1650w, https://mintcdn.com/ghost/aGR3I5_lq1oxakuc/images/fe3de440-search-in-ghost_huac1f49fc436e5098ff1c22395a576ebf_186857_1074x0_resize_q100_h2_box_3.webp?w=2500&fit=max&auto=format&n=aGR3I5_lq1oxakuc&q=85&s=8d3a13ce442ba4aa1da3fe300597d2d3 2500w" />
</Frame>

The easiest way to get started with search is by adding a `#/search` URL to the navigation or anywhere on the site. Beyond that, it’s also possible to implement search directly into a theme using a data attribute.

## Implementing Search in themes

The quickest way is to use the `{{search}}` helper to output a button with a search icon. See [the helper docs](/themes/helpers/utility/search) for more details.

Alternatively, add the `data-ghost-search` data attribute to any element in the theme. Here’s an example from the default theme [Casper](https://github.com/TryGhost/Casper/blob/81d036d4ca036f454f96173a650dd4acc6bb3ca0/default.hbs#L45):

```handlebars  theme={"dark"}
<button class="gh-search" data-ghost-search>{{> "icons/search"}}</button>
```

Both methods allow visitors to search content by clicking on the element to open the search modal or by using the shortcut `Cmd/Ctrl + K`.

### Technical details

* [Taxonomies](/themes/routing/#taxonomies) for tags and authors must be present for search results to include tags and authors
* The post title and excerpt are used to search post content from the most recent 10,000 posts. (Excerpts are excluded for member-only posts)

## Create an advanced search index using Algolia

If you have a large site with more than 10,000 posts, a complex data structure, or require advanced search functionality, we recommend using Algolia.

Ghost has open-source tools to pre-populate the Algolia search index and keep the index updated using webhooks and Netlify Functions.

### Populating the index

To make full use of Algolia from the start, you can pre-populate the search index. [Algolia Ghost CLI](https://github.com/TryGhost/algolia/tree/main/packages/algolia) is a tool that creates fragments of content from your Ghost site and adds them to your Algolia search index.

Follow the documentation for [Algolia Ghost CLI](https://github.com/TryGhost/algolia/tree/main/packages/algolia) to pre-populate your Algolia search index.

### Setting up Algolia Netlify

The best way to keep your Algolia search index updated with new and edited content is to use Netlify Functions, which listen to and processes webhook events and instruct Algolia to index, reindex, or unindex a URL. Once set up, it will automatically keep the search index up to date.

You can deploy and configure the [Algolia Netlify](https://github.com/TryGhost/algolia/tree/main/packages/algolia-netlify) package to Netlify in the browser.


# Structure
Source: https://docs.ghost.org/themes/structure

A Ghost theme contains static HTML templates that make use of helpers to output data from your site, and custom CSS for styling.

***

The recommended file structure for a Ghost theme is:

```bash  theme={"dark"}
# Structure

.
├── /assets
|   └── /css
|       ├── screen.css
|   ├── /fonts
|   ├── /images
|   ├── /js
├── default.hbs
├── index.hbs [required]
└── post.hbs [required]
└── package.json [required]
```

An optional `/partials` directory allows you to use partial templates across your site to share blocks of HTML between multiple templates and reduce code duplication.

```bash  theme={"dark"}
# Structure

.
├── /assets
    ├── /css
        ├── screen.css
    ├── /fonts
    ├── /images
    ├── /js
├── /partials
    ├── list-post.hbs
├── default.hbs
├── index.hbs [required]
└── post.hbs [required]
└── package.json [required]
```

### Templates

Two template files are required: `index.hbs` and `post.hbs`. All other templates are optional.

It’s recommended using a `default.hbs` file as a base layout for your theme. If you have significantly different layouts for different pages or content types, use the [dynamic routing](/themes/routing) configuration layer, or use partials to encapsulate common parts of your theme.

Theme templates are hierarchical, so one template can extend another template. This prevents base HTML from being repeated. Here are some commonly used templates and their uses:

#### default.hbs

`default.hbs` is a base template that contains the boring bits of HTML that exist on every page such as `<html>`, `<head>` or `<body>` as well as the required `{{ghost_head}}` and `{{ghost_foot}}` and any HTML for the header and footer.

#### index.hbs

This is the standard required template for a list of posts. It is also used if your theme does not have a `tag.hbs`, `author.hbs` or `index.hbs` template. The `index.hbs` template usually extends `default.hbs` and is passed a list of posts using the `{{#foreach}}` helper.

#### home.hbs

An optional template to provide special content for the home page. This template is only used to render `/`.

#### post.hbs

The required template for a single post which extends `default.hbs` and uses the `{{#post}}` helper to output the post details. Custom templates for individual posts can be created using `post-:slug.hbs`.

#### page.hbs

An optional template for static pages. If this is not specified then `post.hbs` will be used. Custom templates for individual pages can be mapped to the page using `page-:slug.hbs`.

#### custom-\{\{template-name}}.hbs

Optional custom templates that can be selected in the admin interface on a per-post basis. They can be used for both posts and pages.

#### tag.hbs

An optional template for tag archive pages. If not specifed the `index.hbs` template is used. Custom templates for individual tags can be created using `tag-:slug`.

#### author.hbs

An optional template for author archive pages. If not specified the `index.hbs` template is used. Custom templates for individual authors can be created using `author{{slug}}`.

#### private.hbs

An optional template for the password form page on password protected publications.

#### error.hbs

An optional theme template for any `404` or `500` errors that are not otherwise handled by error- or class-specific templates. If one is not specified Ghost will use the default.

#### error-\{\{error-class}}xx.hbs

An optional theme template for errors belonging to a specific class (e.g. `error-4xx.hbs` for `400`-level errors). A matching error class template is prioritized over both `error.hbs` and the Ghost default template for rendering the error.

#### error-\{\{error-code}}.hbs

An optional theme template for status code-specific errors (e.g. `error-404.hbs`). A matching error code template is prioritized over all other error templates for rendering the error.

#### robots.txt

Themes can include a robots.txt which overrides the default robots.txt provided by Ghost.

The development version of the default theme [Casper](https://github.com/TryGhost/Casper) can be used to explore how Ghost themes work, or you can customise Casper and make it your own!

***

## Helpers

Ghost templates are constructed from HTML and handlebars helpers. There are a few requirements:

In order for a Ghost theme to work, you must make use of the required helpers: `{{asset}}`, `{{body_class}}`, `{{post_class}}`, `{{ghost_head}}`, `{{ghost_foot}}`.

## Contexts

Each page in a Ghost theme belongs to a [context](/themes/contexts/) which is determined by the URL. The context will decide what template will be used, what data is available and what is output by the `{{body_class}}` helper.

## Styling

When building themes it is important to consider the scope of classes and IDs to avoid clashes between your main styling and your post styling. IDs are automatically generated for headings and used inside a post, so it’s best practice to scope things to a particular part of the page. For example: `#themename-my-id` is preferrable to `#my-id`.

## Development mode

It is recommended to use a local install to build a custom theme using development mode – review the [local install guide](/install/local/) to get started with your own local install for development.

In production mode, template files are loaded and cached by the server. For any changes in a `hbs` file to be reflected, use the `ghost restart` command.

Ghost will automatically check for fatal errors when you upload your theme into Ghost admin. For a full validation report during development, use the [GScan tool](https://gscan.ghost.org/).

## Package.json

The `package.json` file is required, and sets some information about your theme, so it’s important to keep it up to date with relevant information.

To reference a working example of a `package.json` file, review the [Casper file](https://github.com/TryGhost/Casper/blob/main/package.json/), and for further information about specific details of `package.json` handling, read the [npm docs](https://docs.npmjs.com/files/package.json).

```json  theme={"dark"}
// package.json

{
    "name": "your-theme-name",
    "description": "A brief explanation of your theme",
    "version": "0.5.0",
    "license": "MIT",
    "author": {
        "email": "your@email.here"
    },
    "screenshots": {
        "desktop": "assets/screenshot-desktop.jpg",
        "mobile": "assets/screenshot-mobile.jpg"
    },
    "config": {
        "posts_per_page": 10,
        "image_sizes": {},
        "card_assets": true
    }
}
```

The data in the file must be valid JSON, including double quotes around all property names. Every property except the last one should be separated by a comma.

## Additional properties

Here are some of the most common optional properties that can be used in the `package.json` file:

* `config.posts_per_page` — the default number of posts per page is 5
* `config.image_sizes` — read more about using [image sizes](/themes/assets/) guide for more details
* `config.card_assets` — configure the [card CSS and JS](/themes/content/#editor-cards) that Ghost automatically includes
* `config.custom` - add [custom settings](/themes/custom-settings/) to your theme
* `description` — provides a short description about your theme and what makes it unique
* `docs` - include a URL to docs about how to use the theme. The link to the docs will be available in Ghost Admin on the **Design** page
* `license` — use a valid licence string, we recommend `MIT` 😉

Changes to the `package.json` require a restart using the `ghost restart` command.

## Next steps

The rest of the theme documentation explores how [contexts](/themes/contexts/) and [helpers](/themes/helpers/) work, and serves as a useful reference list for your theme development.

For community led support about theme development, visit [the forum](https://forum.ghost.org/c/themes/).


# Trademark
Source: https://docs.ghost.org/trademark





# How To Update Ghost
Source: https://docs.ghost.org/update

Learn how to update your self-hosted Ghost install to the latest version

***

Our team [release](https://github.com/TryGhost/Ghost/releases) updates to the open source software every week, and you can find out whether new updates are available any time by running `ghost check-update`.

If you’re already running the latest major version (`6.x`) - update using Ghost CLI by running

```bash  theme={"dark"}
ghost update
```

That's it! If you want to be super safe, run `ghost backup` first.

## Updating to the latest major version (6.x)

If you're running Ghost 5.x with MySQL 8, updating your Ghost-CLI site is still just as easy as usual, but there are [breaking changes](/changes) you should check out first.

<Note>
  The web analytics feature is not compatible with Ghost-CLI. There is a docker-based hosting method currently in preview, which includes a migration tool for Ghost CLI sites: [check it out](/install/docker).
</Note>

If you're on an older version, or not using MySQL 8, getting up-to-date is slightly more involved. Below is a full breakdown of the the recommended update paths for older Ghost versions.

[**Updates are recommended for sites that are:**](/update-major-version/)

* Running Ghost version `3.0.0` or higher and are using MySQL in production
* Development sites using any database

[**A full reinstall of Ghost is recommended for sites that are:**](/reinstall/)

* Running on a Ghost version less than `3.0.0`
* Using SQLite3 in production on any Ghost version

| Ghost Version | Database | Update method                    |
| ------------- | -------- | -------------------------------- |
| \< 2.x        | Any      | [Reinstall](/reinstall/)         |
| 3.x, 4.x      | SQLite   | [Reinstall](/reinstall/)         |
| 3.x, 4.x      | MySQL    | [Update](/update-major-version/) |
| 5.x           | MySQL    | [Update](/update-major-version/) |

[*If you’re using MariaDB it is recommended to migrate to MySQL 8 - read more about supported databases.*](/faq/supported-databases/)


# Webhooks
Source: https://docs.ghost.org/webhooks

Webhooks are specific events triggered when something happens in Ghost, like publishing a new post or receiving a new member

***

## Overview

Webhooks allows Ghost to send POST requests to user-configured URLs in order to send them a notification about it. The request body is a JSON object containing data about the triggered event, and the end result could be something as simple as a Slack notification or as complex as a total redeployment of a site.

## Setting up a webhook

Configuring webhooks can be done through the Ghost Admin user interface under `Settings > Advanced > Integrations > Add custom integration`. The only required fields to setup a new webhook are a trigger event and target URL to notify. This target URL is your application URL, the endpoint where the POST request will be sent. Of course, this URL must be reachable from the Internet.

If the server responds with 2xx HTTP response, the delivery is considered successful. Anything else is considered a failure of some kind, and anything returned in the body of the response will be discarded.

## Available events

Currently Ghost has support for below events on which webhook can be setup:

| Event                   | Description                                                          |
| ----------------------- | -------------------------------------------------------------------- |
| `site.changed`          | Triggered whenever any content changes in your site data or settings |
| `post.added`            | Triggered whenever a post is added to Ghost                          |
| `post.deleted`          | Triggered whenever a post is deleted from Ghost                      |
| `post.edited`           | Triggered whenever a post is edited in Ghost                         |
| `post.published`        | Triggered whenever a post is published to Ghost                      |
| `post.published.edited` | Triggered whenever a published post is edited in Ghost               |
| `post.unpublished`      | Triggered whenever a post is unpublished from Ghost                  |
| `post.scheduled`        | Triggered whenever a post is scheduled to be published in Ghost      |
| `post.unscheduled`      | Triggered whenever a post is unscheduled from publishing in Ghost    |
| `post.rescheduled`      | Triggered whenever a post is rescheduled to publish in Ghost         |
| `page.added`            | Triggered whenever a page is added to Ghost                          |
| `page.deleted`          | Triggered whenever a page is deleted from Ghost                      |
| `page.edited`           | Triggered whenever a page is edited in Ghost                         |
| `page.published`        | Triggered whenever a page is published to Ghost                      |
| `page.published.edited` | Triggered whenever a published page is edited in Ghost               |
| `page.unpublished`      | Triggered whenever a page is unpublished from Ghost                  |
| `page.scheduled`        | Triggered whenever a page is scheduled to be published in Ghost      |
| `page.unscheduled`      | Triggered whenever a page is unscheduled from publishing in Ghost    |
| `page.rescheduled`      | Triggered whenever a page is rescheduled to publish in Ghost         |
| `tag.added`             | Triggered whenever a tag is added to Ghost                           |
| `tag.edited`            | Triggered whenever a tag is edited in Ghost                          |
| `tag.deleted`           | Triggered whenever a tag is deleted from Ghost                       |
| `post.tag.attached`     | Triggered whenever a tag is attached to a post in Ghost              |
| `post.tag.detached`     | Triggered whenever a tag is detached from a post in Ghost            |
| `page.tag.attached`     | Triggered whenever a tag is attached to a page in Ghost              |
| `page.tag.detached`     | Triggered whenever a tag is detached from a page in Ghost            |
| `member.added`          | Triggered whenever a member is added to Ghost                        |
| `member.edited`         | Triggered whenever a member is edited in Ghost                       |
| `member.deleted`        | Triggered whenever a member is deleted from Ghost                    |

## Stripe webhooks

Webhooks allow Ghost to communicate with Stripe. In order to use Stripe with a local version of Ghost you’ll need to do some additional setup to allow webhook events happen between Stripe and Ghost.

First, follow the instructions on [how to install and log into the Stripe CLI tool](https://stripe.com/docs/stripe-cli) in the Stripe documentation.

Then, before starting a local instance of Ghost, run the following command in your CLI. Note that the localhost port number should match the one used in your local Ghost install:

```bash  theme={"dark"}
stripe listen --forward-to http://localhost:2368/members/webhooks/stripe/
```

After running this the CLI will return a secret prefixed with `whsec_`. This secret needs to be given to Ghost on start up. In a new CLI window run the following:

```bash  theme={"dark"}
WEBHOOK_SECRET=whsec_1234567890abcdefg ghost start
```

After following these steps, Ghost will run locally with a webhook connection to your Stripe account. To test that it’s working, sign up for a paid membership on the local site.

Now that the local install of Ghost is running and communicating with Stripe, you can develop and test themes for a custom membership experience, build signup and signin forms, or expose member data.

