'use strict';

//const domain = "www.google.com";
//const domain = "www.north-winds.org";
const domain = "north-winds.org";
const dnsServer = "8.8.8.8";


var lib = require('./lib.js');

var socketId;

var onReceive = function(info) {
    if(info.socketId !== socketId)
        return;
    lib.decodePacket(info.data);
}

console.log(lib.DNSRequest(domain));

function chrome() {
    // Create the Socket
    chrome.sockets.udp.create({}, function(socketInfo) {
        var arrayBuffer = lib.DNSRequest(domain);
        socketId = socketInfo.socketId;
        chrome.sockets.udp.onReceive.addListener(onReceive);
        chrome.sockets.udp.bind(socketId, "0.0.0.0", 0, function(result) {
            if(result < 0) {
                console.log("Error binding DNS socket.");
                return;
            }
            chrome.sockets.udp.send(socketId, arrayBuffer,
              '8.8.8.8', 53, function(sendInfo) {
                console.log("sent " + sendInfo.bytesSent);
            });
        });
    });

    chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {
        var socketId;
        console.log("2Got message: " + request.domain);
        var domain = request.domain;
        var onReceive = function(info) {
            if(info.socketId !== socketId)
                return;
            console.log(info.data);
            var adFlag = 1 << 5;
            var view = new DataView(info.data);
            var flags = view.getUint16(2);
            var secure = false;
            if((flags & adFlag) == adFlag) {
                console.log("2Authenticated data for '" + domain + "': 0x" + flags.toString(16) + "!");
                secure = true;
            } else {
                console.log("2Not authentic for '" + domain + "': 0x" + flags.toString(16) + "!");
            }
            sendResponse({secure: secure});
        }

        chrome.sockets.udp.create({}, function(socketInfo) {
            var arrayBuffer = lib.DNSRequest(domain);
            socketId = socketInfo.socketId;
            chrome.sockets.udp.onReceive.addListener(onReceive);
            chrome.sockets.udp.bind(socketId, "0.0.0.0", 0, function(result) {
                if(result < 0) {
                    console.log("2Error binding DNS socket.");
                    return;
                }
                chrome.sockets.udp.send(socketId, arrayBuffer,
                  '8.8.8.8', 53, function(sendInfo) {
                    console.log("2sent " + sendInfo.bytesSent);
                });
            });
        });
        return true;
    });
}

const dgram = require('dgram');
const server = dgram.createSocket('udp4');

server.on('error', (err) => {
    console.log(`server error:\n${err.stack}`);
    server.close();
});

server.on('message', (msg, rinfo) => {
    console.log(`Message: ${typeof msg}`);
    //console.log(`server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
    console.log("decoding...");
    function toArrayBuffer(buf) {
        var ab = new ArrayBuffer(buf.length);
        var view = new Uint8Array(ab);
        for (var i = 0; i < buf.length; ++i) {
            view[i] = buf[i];
        }
        return ab;
    }
    lib.decodePacket(toArrayBuffer(msg))
    process.exit(0);
});

setTimeout(function() {
    console.log("timeout");
    return process.exit(0);
}, 10000);

server.on('listening', () => {
    const address = server.address();
    console.log(`server listening ${address.address}:${address.port}`);
});
//require('fs').open('dns-raw', 'w', (err, f) -> {
require('fs').writeFile('dns-raw', Buffer.from(lib.DNSRequest(domain)), err => {
    if(err) {
	console.log(err);
    }
});
server.send(Buffer.from(lib.DNSRequest(domain)), 53, dnsServer);

//server.bind(41234);
// Prints: server listening 0.0.0.0:41234

