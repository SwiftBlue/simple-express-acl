import yaml from 'js-yaml'
import _ from 'lodash'
import path from 'path'
import fs from 'fs'

let acl = null

class ACL {
    constructor(opts={}) {
        if(!acl) { acl = this }

        this.opts           = opts
        this.cwd            = process.cwd()
        this.rules          = {}
        this.prefix         = false
        this.superRole      = opts.superRole || 'admin'
        this.rulesFile      = opts.rulesFile || path.join( this.cwd, 'acl.yml' )
        this.responseStatus = opts.responseStatus || 401
        this.response       = opts.response || {status: 'error', message: `Unauthorized access or insufficient permissions`}

        return acl
    }

    setPrefix(prefix) {
        acl.prefix = prefix
    }

    check(req, res, next) {
        if (Object.keys(acl.rules).length == 0) {
            acl.setRules(acl.rulesFile)
        }

        const rules = acl.rules

        if (req && ((req.user && req.user.roles) || (req.session && req.session.roles))) {
            let userRequest = acl.makeUserRequest(req)
            let roleAccess  = acl.roleAccess(userRequest.resource, userRequest.method)
            let roles       = acl.makeRoles(userRequest.roles)
            let access      = false

            _.each(roles, (role) => {
                if (roleAccess[ role ] === true) { access = true }
                else { if (access !== true) { access = false } }
            })

            //  Super Roler Always Has Access
            if (_.includes(roles, acl.superRole)) { access = true }

            if (access === true) { next() }
            else { return acl.deny(res) }

        } else {
            return res.status(401).send({
                status: 'error',
                type: `development`,
                message: `No user roles found on req.user.roles or req.session.roles`
            })
        }
    }

    makeUserRequest(req) {

        if (acl.prefix) {

        }
        return {
            roles:    req.user ? req.user.roles: req.session.roles,
            method:   _.toLower(req.method) || 'get',
            resource: acl.makeResource(req)
        }
    }

    makeResource(req) {
        if (!acl.prefix) {
            return (_.toLower( _.trim(req.baseUrl, '/') )) || '/'
        } else {
            let _baseUrl = (_.toLower( _.trim(req.baseUrl, '/') )) || '/'
            return _.trimStart(_baseUrl, acl.prefix)
        }
    }

    roleAccess(resource, method) {
        let access = {}

        _.each(acl.rules, (rule) => {
            let roleName       = rule.role
            access[ roleName ] = false

            let route = _.find(rule.permissions, function (perm) {
                return resource.match(new RegExp(perm.resource !== '*'? perm.resource : '/*' , 'y'));
            });

            if (!route) {
                // Resource route not found in ACL configuration
                access[ roleName ] = false
            } else {
                // Resource route found in ACL configuration
                if (_.isString(route.methods)) { route.methods = _.toLower(route.methods) }
                else { route.methods = _.map(route.methods, _.toLower) }

                if (route.action !== 'allow') {
                    access[ roleName ] = false
                } else {
                    if ( _.includes(route.methods, method) || route.methods === '*' ) {
                        access[ roleName ] = true
                    } else {
                        access[ roleName ] = false
                    }
                }
            }
        })

        return access
    }

    makeRoles(userRoles) {
        let roles = []

        _.each(userRoles, (role) => {
            roles.push(role)

            let roleRules    = _.find(acl.rules, { role })
            let includeRoles = []

            if (!roleRules || !roleRules.includeRoles) return

            if (_.isString(roleRules.includeRoles)) { includeRoles.push(roleRules.includeRoles) }
            else { includeRoles = _.map(roleRules.includeRoles) }

            _.each(includeRoles, (role) => { roles.push(role) })
        })

        return roles
    }

    deny(res) {
        return res.status(acl.responseStatus).send(acl.response)
    }

    setRules(rules={}) {
        if(_.isString(rules)) {
            this.rulesFile = rules
            rules = this.loadRulesFile(rules)
        }
        this.rules = rules
    }

    loadRulesFile(file=false, encoding='utf8') {
        if (!file) throw new Error(`Not a valid file path`)
        this.rules = yaml.safeLoad(fs.readFileSync( file, encoding ))
        return this.rules
    }
}

const aclInstance = new ACL()
export default aclInstance
