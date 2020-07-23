'use strict';

//const domain = "www.google.com";
const domain = "www.north-winds.org";
//const domain = "www.alzatex.com";
const dns_server = "8.8.8.8";
//const dns_server = "10.248.2.1";
//const dns_server = "ns.tallye.com";


var lib = require('./lib.js');

var socketId;

var onReceive = function(info) {
    if(info.socketId !== socketId)
        return;
    decode(info.data);
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
            var ad_flag = 1 << 5;
            var view = new DataView(info.data);
            var flags = view.getUint16(2);
            var secure = false;
            if((flags & ad_flag) == ad_flag) {
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
    decode(toArrayBuffer(msg))
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
server.send(Buffer.from(lib.DNSRequest(domain)), 53, dns_server);

//server.bind(41234);
// Prints: server listening 0.0.0.0:41234

