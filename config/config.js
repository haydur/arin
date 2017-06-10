module.exports = {
    "name": "American Registry for Internet Numbers",
    "acronym":"ARIN",
    "logging": { level: 'debug'},
    "entityTypes": ['IPv4', 'IPv6'],
    "customTypes":[
        {
            key: 'IPv4CIDR',
            regex: /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$/
        }
    ],
    "description": "ARIN Integration",
    "styles":[
        "./styles/arin.less"
    ],
    "block": {
        "component": {
            "file": "./component/arin.js"
        },
        "template": {
            "file": "./template/arin.hbs"
        }
    },
    "options":[
        {
            "key": "lookupIPv6",
            "name": "Lookup IPv6 Addresses",
            "description": "If checked, the integration will IPv6 addresses in addition to IPv4.",
            "default": true,
            "type": "boolean",
            "userCanEdit": true,
            "adminOnly": false
        },
        {
            "key"         : "blacklist",
            "name"        : "Blacklist IPs",
            "description" : "List of IPs that you never want sent to ARIN.",
            "default"     : "",
            "type"        : "text",
            "userCanEdit" : false,
            "adminOnly"    : false
        }

    ]
};