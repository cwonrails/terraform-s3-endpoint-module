'use strict';

const headers = {
    "all": {
        "Server":"",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000; includeSubdomains; preload"
    },
    "html": {
        // Content-Security-Policy-Report-Only: https://tesera.report-uri.com/r/d/csp/reportOnly
        // Content-Security-Policy:             https://tesera.report-uri.com/r/d/csp/enforce
        "Content-Security-Policy": "default-src 'none';" +
            " img-src 'self';" +
            " script-src 'self';" +
            " style-src 'self';" +
            " connect-src 'self';" +
            " base-uri 'none';" +
            " frame-ancestors 'none';" +
            " block-all-mixed-content;" +
            " upgrade-insecure-requests;" +
            " report-uri https://tesera.report-uri.com/r/d/csp/reportOnly",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "X-UA-Compatible":"ie=edge"
    }
};

// Reformat headers object for CF
function makeHeaders (headers) {
    const formattedHeaders = {};
    Object.keys(headers).forEach((key) => {
        formattedHeaders[key.toLowerCase()] = [{
            key: key,
            value: headers[key]
        }]
    });
    return formattedHeaders;
}

function getHeaders(mime) {
    return makeHeaders(headers[mime])
}

function handler (event, context, callback) {
    const response = event.Records[0].cf.response;
    const contentType = response.headers['content-type'][0].value;

    let responseHeaders = getHeaders('all');

    if (contentType.indexOf('text/html') !== -1) {
        responseHeaders = Object.assign({}, responseHeaders, getHeaders('html'));
    }

    response.headers = Object.assign({}, response.headers, responseHeaders);

    callback(null, response);
}

module.exports = {
    makeHeaders,
    headers,
    handler
};
