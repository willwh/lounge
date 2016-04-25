var EventEmitter = require("events").EventEmitter;
var Helper = require("./helper");

function Packages() {
	EventEmitter.call(this);
	this.packages = [];
}

Packages.prototype = new EventEmitter();

Packages.prototype.forEachProp = function(prop, callback) {
	this.packages.forEach(function(package) {
		if (prop in package.exports) {
			callback(package.exports[prop], package);
		}
	});
};

var packages = module.exports = new Packages();

(function(config) {
	if ("packages" in config && config.packages instanceof Array) {
		config.packages.forEach(function(package) {
			packages.packages.push({
				exports: require("../packages/" + package),
				path: package,
				webroot: "packages/" + package + "/",
			});
		});
	}
})(Helper.getConfig());

packages.emit("packagesLoaded");
