var util = require("util");
var Strategy = require("passport-strategy");

/*
 * passport.js TLS client certificate strategy
 */
function ClientCertStrategy(options, verify) {
	if (typeof options == "function") {
		verify = options;
		options = {};
	}
	if (!verify) throw new Error("Client cert authentication strategy requires a verify function");

	Strategy.call(this);
	this.name = "client-certificate";
	this._verify = verify;
}

util.inherits(ClientCertStrategy, Strategy);

ClientCertStrategy.prototype.authenticate = function (req, options) {
	var that = this;

	// Requests must be authorized
	// (i.e. the certificate must be signed by at least one trusted CA)
	var clientAuth = (req.get("x-ssl-client-verify") == "SUCCESS");
	if (!clientAuth) {
		that.fail();
	} else {
		var clientCert = req.get("x-ssl-client-cert").toLowerCase();
		var clientFingerprint = req.get("x-ssl-client-fingerprint").toLowerCase();
		var clientSerial = req.get("x-ssl-client-serial").toLowerCase();

		// The cert must exist and be non-empty
		if (!clientCert || Object.getOwnPropertyNames(clientCert).length === 0) {
			that.fail();
		} else {

			this._verify(clientCert, clientFingerprint, clientSerial,
				function (err, user) {
					if (err) {
						return that.error(err);
					}
					if (!user) {
						return that.fail();
					}
					that.success(user);
				});
		}
	}
};

exports.Strategy = ClientCertStrategy;
