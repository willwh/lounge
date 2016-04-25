var _ = require("lodash");
var pkg = require("../package.json");
var bcrypt = require("bcrypt-nodejs");
var Client = require("./client");
var ClientManager = require("./clientManager");
var express = require("express");
var fs = require("fs");
var io = require("socket.io");
var dns = require("dns");
var Helper = require("./helper");
var ServeStatic = require("serve-static");
var config = {};

var manager = null;
var packages = null;
var stylesheets = [];
var scripts = [];

module.exports = function(options) {
	manager = new ClientManager();
	config = Helper.getConfig();
	config = _.extend(config, options);
	packages = require("./packages");

	var app = express()
		.use(allRequests)
		.use(index)
		.use(clientPackages)
		.use(express.static("client"));

	packages.forEachProp("client", function(client, package) {
		if ("stylesheets" in client && client.stylesheets instanceof Array) {
			client.stylesheets.forEach(function(css) {
				stylesheets.push(package.webroot + css);
			});
		}

		if ("scripts" in client && client.scripts instanceof Array) {
			client.scripts.forEach(function(script) {
				scripts.push(package.webroot + script);
			});
		}
	});

	packages.emit("httpServer", app);

	app.enable("trust proxy");

	var server = null;
	var https = config.https || {};
	var protocol = https.enable ? "https" : "http";
	var port = config.port;
	var host = config.host;
	var transports = config.transports || ["polling", "websocket"];

	if (!https.enable) {
		server = require("http");
		server = server.createServer(app).listen(port, host);
	} else {
		server = require("spdy");
		server = server.createServer({
			key: fs.readFileSync(Helper.expandHome(https.key)),
			cert: fs.readFileSync(Helper.expandHome(https.certificate))
		}, app).listen(port, host);
	}

	if ((config.identd || {}).enable) {
		if (manager.identHandler) {
			log.warn("Using both identd and oidentd at the same time!");
		}

		require("./identd").start(config.identd.port);
	}

	var sockets = io(server, {
		transports: transports
	});

	sockets.on("connect", function(socket) {
		if (config.public) {
			auth.call(socket);
		} else {
			init(socket);
		}
	});

	manager.sockets = sockets;

	log.info("The Lounge v" + pkg.version + " is now running on", protocol + "://" + (config.host || "*") + ":" + config.port + "/");
	log.info("Press ctrl-c to stop\n");

	if (!config.public) {
		manager.loadUsers();
		if (config.autoload) {
			manager.autoload();
		}
	}
};

function getClientIp(req) {
	if (!config.reverseProxy) {
		return req.connection.remoteAddress;
	} else {
		return req.headers["x-forwarded-for"] || req.connection.remoteAddress;
	}
}

function allRequests(req, res, next) {
	res.setHeader("X-Content-Type-Options", "nosniff");
	return next();
}

function index(req, res, next) {
	if (req.url.split("?")[0] !== "/") {
		return next();
	}

	return fs.readFile("client/index.html", "utf-8", function(err, file) {
		var data = _.merge(
			pkg,
			config,
			{
				stylesheets: stylesheets,
				scripts: scripts
			}
		);
		var template = _.template(file);
		res.setHeader("Content-Security-Policy", "default-src *; style-src * 'unsafe-inline'; script-src 'self'; child-src 'none'; object-src 'none'; form-action 'none'; referrer no-referrer;");
		res.setHeader("Content-Type", "text/html");
		res.writeHead(200);
		res.end(template(data));
	});
}

function init(socket, client) {
	if (!client) {
		socket.emit("auth", {success: true});
		socket.on("auth", auth);
	} else {
		socket.on(
			"input",
			function(data) {
				client.input(data);
			}
		);
		socket.on(
			"more",
			function(data) {
				client.more(data);
			}
		);
		socket.on(
			"conn",
			function(data) {
				// prevent people from overriding webirc settings
				data.ip = null;
				data.hostname = null;
				client.connect(data);
			}
		);
		if (!config.public) {
			socket.on(
				"change-password",
				function(data) {
					var old = data.old_password;
					var p1 = data.new_password;
					var p2 = data.verify_password;
					if (typeof p1 === "undefined" || p1 === "") {
						socket.emit("change-password", {
							error: "Please enter a new password"
						});
						return;
					}
					if (p1 !== p2) {
						socket.emit("change-password", {
							error: "Both new password fields must match"
						});
						return;
					}
					if (!bcrypt.compareSync(old || "", client.config.password)) {
						socket.emit("change-password", {
							error: "The current password field does not match your account password"
						});
						return;
					}

					var salt = bcrypt.genSaltSync(8);
					var hash = bcrypt.hashSync(p1, salt);

					client.setPassword(hash, function(success) {
						var obj = {};

						if (success) {
							obj.success = "Successfully updated your password, all your other sessions were logged out";
							obj.token = client.config.token;
						} else {
							obj.error = "Failed to update your password";
						}

						socket.emit("change-password", obj);
					});
				}
			);
		}
		socket.on(
			"open",
			function(data) {
				client.open(data);
			}
		);
		socket.on(
			"sort",
			function(data) {
				client.sort(data);
			}
		);
		socket.on(
			"names",
			function(data) {
				client.names(data);
			}
		);
		socket.join(client.id);
		socket.emit("init", {
			active: client.activeChannel,
			networks: client.networks,
			token: client.config.token || null
		});
	}
}

function reverseDnsLookup(socket, client) {
	client.ip = getClientIp(socket.request);

	dns.reverse(client.ip, function(err, host) {
		if (!err && host.length) {
			client.hostname = host[0];
		} else {
			client.hostname = client.ip;
		}

		init(socket, client);
	});
}

function auth(data) {
	var socket = this;
	if (config.public) {
		var client = new Client(manager);
		manager.clients.push(client);
		socket.on("disconnect", function() {
			manager.clients = _.without(manager.clients, client);
			client.quit();
		});
		if (config.webirc) {
			reverseDnsLookup(socket, client);
		} else {
			init(socket, client);
		}
	} else {
		var success = false;
		_.each(manager.clients, function(client) {
			if (data.token) {
				if (data.token === client.config.token) {
					success = true;
				}
			} else if (client.config.user === data.user) {
				if (bcrypt.compareSync(data.password || "", client.config.password)) {
					success = true;
				}
			}
			if (success) {
				if (config.webirc !== null && !client.config["ip"]) {
					reverseDnsLookup(socket, client);
				} else {
					init(socket, client);
				}
				return false;
			}
		});
		if (!success) {
			socket.emit("auth", {success: success});
		}
	}
}

function clientPackages(req, res, next) {
	if (!req.url.startsWith("/packages/")) {
		return next();
	}

	req.url = req.url.replace(/^\/packages\/([^?&#]*?)\/(.*)$/, "/$1/client/$2");
	ServeStatic("packages/")(req, res, next);
}
