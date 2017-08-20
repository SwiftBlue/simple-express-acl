'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _jsYaml = require('js-yaml');

var _jsYaml2 = _interopRequireDefault(_jsYaml);

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

var _path = require('path');

var _path2 = _interopRequireDefault(_path);

var _fs = require('fs');

var _fs2 = _interopRequireDefault(_fs);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var acl = null;

var ACL = function () {
    function ACL() {
        var opts = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

        _classCallCheck(this, ACL);

        if (!acl) {
            acl = this;
        }

        this.opts = opts;
        this.cwd = process.cwd();
        this.rules = {};
        this.prefix = false;
        this.superRole = opts.superRole || 'admin';
        this.rulesFile = opts.rulesFile || _path2.default.join(this.cwd, 'acl.yml');
        this.responseStatus = opts.responseStatus || 401;
        this.response = opts.response || { status: 'error', message: 'Unauthorized access or insufficient permissions' };

        return acl;
    }

    _createClass(ACL, [{
        key: 'setPrefix',
        value: function setPrefix(prefix) {
            acl.prefix = prefix;
        }
    }, {
        key: 'check',
        value: function check(req, res, next) {
            if (Object.keys(acl.rules).length == 0) {
                acl.setRules(acl.rulesFile);
            }

            var rules = acl.rules;

            if (req && (req.user && req.user.roles || req.session && req.session.roles)) {
                var userRequest = acl.makeUserRequest(req);
                var roleAccess = acl.roleAccess(userRequest.resource, userRequest.method);
                var roles = acl.makeRoles(userRequest.roles);
                var access = false;

                _lodash2.default.each(roles, function (role) {
                    if (roleAccess[role] === true) {
                        access = true;
                    } else {
                        if (access !== true) {
                            access = false;
                        }
                    }
                });

                //  Super Roler Always Has Access
                if (_lodash2.default.includes(roles, acl.superRole)) {
                    access = true;
                }

                if (access === true) {
                    next();
                } else {
                    return acl.deny(res);
                }
            } else {
                return res.status(401).send({
                    status: 'error',
                    type: 'development',
                    message: 'No user roles found on req.user.roles or req.session.roles'
                });
            }
        }
    }, {
        key: 'makeUserRequest',
        value: function makeUserRequest(req) {

            if (acl.prefix) {}
            return {
                roles: req.user ? req.user.roles : req.session.roles,
                method: _lodash2.default.toLower(req.method) || 'get',
                resource: acl.makeResource(req)
            };
        }
    }, {
        key: 'makeResource',
        value: function makeResource(req) {
            if (!acl.prefix) {
                return _lodash2.default.toLower(_lodash2.default.trim(req.baseUrl, '/')) || '/';
            } else {
                var _baseUrl = _lodash2.default.toLower(_lodash2.default.trim(req.baseUrl, '/')) || '/';
                return _lodash2.default.trimStart(_baseUrl, acl.prefix);
            }
        }
    }, {
        key: 'roleAccess',
        value: function roleAccess(resource, method) {
            var access = {};

            _lodash2.default.each(acl.rules, function (rule) {
                var roleName = rule.role;
                access[roleName] = false;

                var route = _lodash2.default.find(rule.permissions, function (perm) {
                    return resource.match(new RegExp(perm.resource !== '*' ? perm.resource : '/*', 'y'));
                });

                if (!route) {
                    // Resource route not found in ACL configuration
                    access[roleName] = false;
                } else {
                    // Resource route found in ACL configuration
                    if (_lodash2.default.isString(route.methods)) {
                        route.methods = _lodash2.default.toLower(route.methods);
                    } else {
                        route.methods = _lodash2.default.map(route.methods, _lodash2.default.toLower);
                    }

                    if (route.action !== 'allow') {
                        access[roleName] = false;
                    } else {
                        if (_lodash2.default.includes(route.methods, method) || route.methods === '*') {
                            access[roleName] = true;
                        } else {
                            access[roleName] = false;
                        }
                    }
                }
            });

            return access;
        }
    }, {
        key: 'makeRoles',
        value: function makeRoles(userRoles) {
            var roles = [];

            _lodash2.default.each(userRoles, function (role) {
                roles.push(role);

                var roleRules = _lodash2.default.find(acl.rules, { role: role });
                var includeRoles = [];

                if (!roleRules || !roleRules.includeRoles) return;

                if (_lodash2.default.isString(roleRules.includeRoles)) {
                    includeRoles.push(roleRules.includeRoles);
                } else {
                    includeRoles = _lodash2.default.map(roleRules.includeRoles);
                }

                _lodash2.default.each(includeRoles, function (role) {
                    roles.push(role);
                });
            });

            return roles;
        }
    }, {
        key: 'deny',
        value: function deny(res) {
            return res.status(acl.responseStatus).send(acl.response);
        }
    }, {
        key: 'setRules',
        value: function setRules() {
            var rules = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

            if (_lodash2.default.isString(rules)) {
                this.rulesFile = rules;
                rules = this.loadRulesFile(rules);
            }
            this.rules = rules;
        }
    }, {
        key: 'loadRulesFile',
        value: function loadRulesFile() {
            var file = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : false;
            var encoding = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'utf8';

            if (!file) throw new Error('Not a valid file path');
            this.rules = _jsYaml2.default.safeLoad(_fs2.default.readFileSync(file, encoding));
            return this.rules;
        }
    }]);

    return ACL;
}();

var aclInstance = new ACL();
exports.default = aclInstance;