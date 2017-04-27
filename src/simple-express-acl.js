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
        this.superRole      = opts.superRole || 'admin'
        this.rulesFile      = opts.rulesFile || path.join( this.cwd, 'acl.yml' )
        this.responseStatus = opts.responseStatus || 401
        this.response       = opts.response || {status: 'error', message: `Unauthorized access or insufficient permissions`}

        return acl
    }

    check(req, res, next) {
        if (Object.keys(acl.rules).length == 0) {
            acl.setRules(acl.rulesFile)
        }

        const rules = acl.rules

        if (req && req.user && req.user.roles) {
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
                message: `No user roles found on req.user.roles`
            })
        }
    }

    makeUserRequest(req) {
        return {
            roles:    req.user.roles,
            method:   _.toLower(req.method) || 'get',
            resource: (_.toLower( _.trim(req.baseUrl, '/') )) || '/'
        }
    }

    roleAccess(resource, method) {
        let access = {}

        _.each(acl.rules, (rule) => {
            let roleName       = rule.role
            access[ roleName ] = false

            let route = _.find(rule.permissions, { resource })

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

            if (_.isString(roleRules.includeRoles)) { includeRoles.push(_.toLower(roleRules.includeRoles)) }
            else { includeRoles = _.map(roleRules.includeRoles, _.toLower) }

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
