<a href="https://swiftblue.com/">
    <img src="http://static.swiftblue.net/brand/logo.png" alt="SwiftBlue logo" title="SwiftBlue" align="right" height="40" />
</a>

## Simple Express ACL Middleware

Simple ACL middleware that works well with JWT and Passport's JWT strategy

## Install

`$ npm install --save simple-express-acl`

## Usage

**Looks for an array of user role's in `req.user.roles`**

If `admin` is found in `req.user.roles`, that is considered a __Super Role__ that has access to all resources, regardless of rule definitions.

If middleware `acl.check` is defined on an Express route, and the user role is not defined in the role definitions, access will be **denied** by default.

#### Sample Express `router.js` file

```
import acl from 'simple-express-acl'

// Set custom YML file with rules
acl.setRules( __dirname + '/config/acl.yml' )

// Set rules from an object
acl.setRules( rulesObject )

// Set super role (default: admin)
acl.superRole = 'root'

// Set unauthorized response status (default: 401)
acl.responseStatus = 404

// Set unauthorized response
acl.response = {
    status:  'error',
    message: 'You do not have access mister...'
}

/**
 *    Express Routes
 */

import { Router } from 'express'
const router = new Router()

router.use( '/user', acl.check, require('./controllers/user.js') )
```

#### Sample `acl.yml`:
> Place in the `root` directory of your project by default

```
-   role: user
    permissions:
        -
            resource: user
            action: allow
            methods: '*'
        -
            resource: comment
            action: allow
            methods:
                - GET
                - POST
        -
            resource: profile
            action: allow
            methods:
                - GET
                - POST
                - PUT

-   role: friend
    permissions:
        -
            resource: user
            action: allow
            methods:
                - GET
        -
            resource: comment
            action: allow
            methods:
                - GET

        -
            resource: profile
            action: deny
            methods: '*'

-   role: guest
    includeRoles: friend

-   role: owner
    includeRoles:
        - user
        - friend
```

### License

> MIT License

> **Copyright © 2017 SwiftBlue, LLC, David Berube**

> Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

> The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
