'use strict';

// Reformat headers object for CF
const makeHeaders = (headers) => {
    const formattedHeaders = {};
    Object.keys(headers).forEach((key) => {
        formattedHeaders[key.toLowerCase()] = [{
            key: key,
            value: headers[key]
        }]
    });
    return formattedHeaders;
};

exports.handler = (event, context, callback) => {
    const response = event.Records[0].cf.response;
    const securityHeaders = {
        "Strict-Transport-Security": "max-age=31536000; includeSubdomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
        // Content-Security-Policy-Report-Only: https://tesera.report-uri.com/r/d/csp/reportOnly
        // Content-Security-Policy:             https://tesera.report-uri.com/r/d/csp/enforce
        "Content-Security-Policy-Report-Only":
            "default-src 'none';" +
            " img-src 'self';" +
            " script-src 'self';" +
            " style-src 'self';" +
            " connect-src 'self';" +
            " base-uri 'none';" +
            " frame-ancestors 'none';" +
            " block-all-mixed-content;" +
            " upgrade-insecure-requests;" +
            " report-uri https://tesera.report-uri.com/r/d/csp/reportOnly",
        // Public-Key-Pins-Report-Only: https://tesera.report-uri.com/r/d/hpkp/reportOnly
        // Public-Key-Pins:             https://tesera.report-uri.com/r/d/hpkp/enforce
        //"Public-Key-Pins-Report-Only":
        //     "pin-sha256=\"{pkphash}\";" +    // domain name
        //     " pin-sha256=\"JSMzqOOrtyOT1kmau6zKhgT676hGgczD5VMdRMyJZFA=\";" +   // Amazon
        //     " pin-sha256=\"++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=\";" +   // Amazon Root CA 1
        //     " pin-sha256=\"KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=\";" +   // Starfield Services Root Certificate Authority - G2
        //     " pin-sha256=\"FfFKxFycfaIz00eRZOgTf+Ne4POK6FgYPwhBDqgqxLQ=\";" +   // Starfield Class 2 Certification Authority
        //     " max-age=5184000; includeSubDomains;" +
        //     " report-uri=\"https://tesera.report-uri.com/r/d/hpkp/reportOnly\""
    };

    response.headers = Object.assign({}, response.headers, makeHeaders(securityHeaders));

    callback(null, response);
};
