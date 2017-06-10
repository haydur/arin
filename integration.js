'use strict';

let request = require('request');
let _ = require('lodash');
let util = require('util');
let async = require('async');
let log = null;
var arinuri = '';

function startup(logger) {
    log = logger;
}

function doLookup(entities, options, cb) {

    let blacklist = options.blacklist;
	
	let checkv6 = options.lookupIPv6;

    let lookupResults = [];

    async.each(entities, function (entityObj, next) {
        if (_.includes(blacklist, entityObj.value)) {
            next(null);
        }
        else if (entityObj.isIPv4 || (entityObj.isIPv6 && checkv6 == true) || entityObj.types.indexOf('custom.IPv4CIDR') > 0) {
            _lookupEntity(entityObj, options, function (err, result) {
                if (err) {
                    next(err);
                } else {
                    lookupResults.push(result);
                    log.trace({result: result}, "Result Values:");
                    next(null);
                }
            });
        } else {
            lookupResults.push({entity: entityObj, data: null}); //Cache the missed results
            next(null);
        }
    }, function (err) {
        cb(err, lookupResults);
    });
}


function _lookupEntity(entityObj, options, cb) {
    log.debug({entity: entityObj.value}, "What is the entity");
	
    if (entityObj.value) {
		
		if (entityObj.types.indexOf('custom.IPv4CIDR') > 0) {
			let arinuri = 'cidr';
		} else {
			let arinuri = 'ip';
		}
		
		log.debug({arinuri: arinuri}, "What is the ARIN API endpoint");
	
        request({
            uri: 'http://whois.arin.net/rest/' + arinuri + '/' + entityObj.value,
            method: 'GET',
            json: true,
			headers: {
				'Accept': 'application/json'
			}
        }, function (err, response, body) {
            if (err) {
                cb(null, {
                    entity: entityObj,
                    data: null
                });
                log.error({err:err}, "Logging error");
                return;
            }

            if (response.statusCode === 500) {
                cb(_createJsonErrorPayload("ARIN server was unable to process your request", null, '500', '2A', 'Unable to Process Request', {
                    err: err
                }));
                return;
            }

            if (response.statusCode === 404) {
                cb(_createJsonErrorPayload("No information available for request", null, '404', '2A', 'No Information', {
                    err: err
                }));
                return;
            }

            if (response.statusCode === 206) {
                cb(_createJsonErrorPayload("Unable to parse request", null, '206', '2A', 'Parse Error', {
                    err: err
                }));
                return;
            }

            if (response.statusCode !== 200) {
                cb(body);
                return;
            }


            log.trace({body: body}, "Printing out the results of Body ");

            // The lookup results returned is an array of lookup objects with the following format
            cb(null, {
                // Required: This is the entity object passed into the integration doLookup method
                entity: entityObj,
                // Required: An object containing everything you want passed to the template
                data: {
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj.value,
                    // Required: These are the tags that are displayed in your template
                    summary: [body.net.orgRef.handle],
                    // Data that you want to pass back to the notification window details block
                    details: {
                        created: body.net.orgRef.name,
                        updated: body.net.parentNetRef.handle,
                        registrar: body.net.startAddress,
                        registrant: body.net.updateDate,
                        ip: body.net.netBlocks.netBlock.cidrLength,
                        domains: body.response.server.other_domains,
                        expires: body.response.registration.expires,
                        nameservers: nameservers.server,
                        earliest: body.response.history.registrar.earliest_event,
                        historicalEvents: body.response.history.registrar.events,
                        nameEvents: body.response.history.name_server.events,
                        nameSpan: body.response.history.name_server.timespan_in_years,
                        ipEvents: body.response.history.ip_address.events,
                        ipSpan: body.response.history.ip_address.timespan_in_years,
                        records: body.response.history.whois.records,
                        whoearliest: body.response.history.whois.earliest_event,
                        seoScore: body.response.seo.score,
                        response: body.response.website_data.response_code,
                        title: body.response.website_data.title,
                        server: body.response.website_data.server,
                        meta: body.response.website_data.meta.description,
                        history_url: body.response.history.registrar.product_url,
                        reverse_whois_url: body.response.registrant.product_url,
                        reverse_ip_url: body.response.server.product_url,
                        website_whois: body.response.website_data.product_url
                    }
                }
            });
        });
		
	}
}

function validateOptions(userOptions, cb) {
    let errors = [];
	//nothig to validate; leaving function for future expantion of integration.
    cb(null, errors);
}

// function that takes the ErrorObject and passes the error message to the notification window
var _createJsonErrorPayload = function (msg, pointer, httpCode, code, title, meta) {
    return {
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
};

// function that creates the Json object to be passed to the payload
var _createJsonErrorObject = function (msg, pointer, httpCode, code, title, meta) {
    let error = {
        detail: msg,
        status: httpCode.toString(),
        title: title,
        code: 'DT_' + code.toString()
    };

    if (pointer) {
        error.source = {
            pointer: pointer
        };
    }

    if (meta) {
        error.meta = meta;
    }

    return error;
};

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};