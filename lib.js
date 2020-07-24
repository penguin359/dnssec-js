'use strict';

// DNS Header values

// DNS message is a Query Response
const qrBit = 1 << 15;

// DNS operation
const opcodes = {
    query:  0 * (1 << 11),
    iquery: 1 * (1 << 11),
    status: 2 * (1 << 11),
    notify: 4 * (1 << 11),
    update: 5 * (1 << 11),
    dso:    6 * (1 << 11),
};
const opcodeMask = 0xf << 11;

function findOpcode(value) {
    for(var name in opcodes) {
        if(opcodes[name] === value) {
            return name;
        }
    }
}

// DNS response code
const rcodes = [
    {
        code: 0,
        name: "NoError",
        descr: "No Error",
        standard: "[RFC1035]",
    },
    {
        code: 1,
        name: "FormErr",
        descr: "Format Error",
        standard: "[RFC1035]",
    },
    {
        code: 2,
        name: "ServFail",
        descr: "Server Failure",
        standard: "[RFC1035]",
    },
    {
        code: 3,
        name: "NXDomain",
        descr: "Non-Existent Domain",
        standard: "[RFC1035]",
    },
    {
        code: 4,
        name: "NotImp",
        descr: "Not Implemented",
        standard: "[RFC1035]",
    },
    {
        code: 5,
        name: "Refused",
        descr: "Query Refused",
        standard: "[RFC1035]",
    },
    {
        code: 6,
        name: "YXDomain",
        descr: "Name Exists when it should not",
        standard: "[RFC2136][RFC6672]",
    },
    {
        code: 7,
        name: "YXRRSet",
        descr: "RR Set Exists when it should not",
        standard: "[RFC2136]",
    },
    {
        code: 8,
        name: "NXRRSet",
        descr: "RR Set that should exist does not",
        standard: "[RFC2136]",
    },
    {
        code: 9,
        name: "NotAuth",
        descr: "Server Not Authoritative for zone",
        standard: "[RFC2136]",
    },
    {
        code: 10,
        name: "NotZone",
        descr: "Name not contained in zone",
        standard: "[RFC2136]",
    },
    {
        code: 11,
        name: "DSOTYPENI",
        descr: "DSO-TYPE Not Implemented",
        standard: "[RFC8490]",
    },
    {
        code: 16,
            name: "BADVERS",
            descr: "Bad OPT Version",
            standard: "[RFC6891]",
    },
    {
        code: 17,
        name: "BADKEY",
        descr: "Key not recognized",
        standard: "[RFC-ietf-dnsop-rfc2845bis-09]",
    },
    {
        code: 18,
        name: "BADTIME",
        descr: "Signature out of time window",
        standard: "[RFC-ietf-dnsop-rfc2845bis-09]",
    },
    {
        code: 19,
        name: "BADMODE",
        descr: "Bad TKEY Mode",
        standard: "[RFC2930]",
    },
    {
        code: 20,
        name: "BADNAME",
        descr: "Duplicate key name",
        standard: "[RFC2930]",
    },
    {
        code: 21,
        name: "BADALG",
        descr: "Algorithm not supported",
        standard: "[RFC2930]",
    },
    {
        code: 22,
        name: "BADTRUNC",
        descr: "Bad Truncation",
        standard: "[RFC-ietf-dnsop-rfc2845bis-09]",
    },
    {
        code: 23,
        name: "BADCOOKIE",
        descr: "Bad/missing Server Cookie",
        standard: "[RFC7873]",
    },
];
const rcodeMask = 0xf;

// DNS header flags
const flags = {
    AA: 1 << 10,
    TC: 1 << 9,
    RD: 1 << 8,
    RA: 1 << 7,
    AD: 1 << 5,
    CD: 1 << 4,
};

function findFlags(value) {
    var list = [];
    for(var name in flags) {
        if((flags[name] & value) === flags[name]) {
            list.push(name);
        }
    }
    return list;
}

function decodeA(value) {
    return `${value.getUint8(0)}.${value.getUint8(1)}.${value.getUint8(2)}.${value.getUint8(3)}`;
}

// Resource Record types
const rrtype = [
    {
        code: 1,
        name: "A",
        descr: "a host address",
        standard: "[RFC1035]",
        decode: decodeA,
    },
    {
        code: 2,
        name: "NS",
        descr: "an authoritative name server",
        standard: "[RFC1035]",
    },
    {
        code: 3,
        name: "MD",
        descr: "a mail destination (OBSOLETE - use MX)",
        standard: "[RFC1035]",
    },
    {
        code: 4,
        name: "MF",
        descr: "a mail forwarder (OBSOLETE - use MX)",
        standard: "[RFC1035]",
    },
    {
        code: 5,
        name: "CNAME",
        descr: "the canonical name for an alias",
        standard: "[RFC1035]",
    },
    {
        code: 6,
        name: "SOA",
        descr: "marks the start of a zone of authority",
        standard: "[RFC1035]",
    },
    {
        code: 7,
        name: "MB",
        descr: "a mailbox domain name (EXPERIMENTAL)",
        standard: "[RFC1035]",
    },
    {
        code: 8,
        name: "MG",
        descr: "a mail group member (EXPERIMENTAL)",
        standard: "[RFC1035]",
    },
    {
        code: 9,
        name: "MR",
        descr: "a mail rename domain name (EXPERIMENTAL)",
        standard: "[RFC1035]",
    },
    {
        code: 10,
        name: "NULL",
        descr: "a null RR (EXPERIMENTAL)",
        standard: "[RFC1035]",
    },
    {
        code: 11,
        name: "WKS",
        descr: "a well known service description",
        standard: "[RFC1035]",
    },
    {
        code: 12,
        name: "PTR",
        descr: "a domain name pointer",
        standard: "[RFC1035]",
    },
    {
        code: 13,
        name: "HINFO",
        descr: "host information",
        standard: "[RFC1035]",
    },
    {
        code: 14,
        name: "MINFO",
        descr: "mailbox or mail list information",
        standard: "[RFC1035]",
    },
    {
        code: 15,
        name: "MX",
        descr: "mail exchange",
        standard: "[RFC1035]",
    },
    {
        code: 16,
        name: "TXT",
        descr: "text strings",
        standard: "[RFC1035]",
    },
    {
        code: 17,
        name: "RP",
        descr: "for Responsible Person",
        standard: "[RFC1183]",
    },
    {
        code: 18,
        name: "AFSDB",
        descr: "for AFS Data Base location",
        standard: "[RFC1183][RFC5864]",
    },
    {
        code: 19,
        name: "X25",
        descr: "for X.25 PSDN address",
        standard: "[RFC1183]",
    },
    {
        code: 20,
        name: "ISDN",
        descr: "for ISDN address",
        standard: "[RFC1183]",
    },
    {
        code: 21,
        name: "RT",
        descr: "for Route Through",
        standard: "[RFC1183]",
    },
    {
        code: 22,
        name: "NSAP",
        descr: "for NSAP address, NSAP style A record",
        standard: "[RFC1706]",
    },
    {
        code: 23,
        name: "NSAP-PTR",
        descr: "for domain name pointer, NSAP style",
        standard: "[RFC1348][RFC1637][RFC1706]",
    },
    {
        code: 24,
        name: "SIG",
        descr: "for security signature",
        standard: "[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008]",
    },
    {
        code: 25,
        name: "KEY",
        descr: "for security key",
        standard: "[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110]",
    },
    {
        code: 26,
        name: "PX",
        descr: "X.400 mail mapping information",
        standard: "[RFC2163]",
    },
    {
        code: 27,
        name: "GPOS",
        descr: "Geographical Position",
        standard: "[RFC1712]",
    },
    {
        code: 28,
        name: "AAAA",
        descr: "IP6 Address",
        standard: "[RFC3596]",
    },
    {
        code: 29,
        name: "LOC",
        descr: "Location Information",
        standard: "[RFC1876]",
    },
    {
        code: 30,
        name: "NXT",
        descr: "Next Domain (OBSOLETE)",
        standard: "[RFC3755][RFC2535]",
    },
    {
        code: 31,
        name: "EID",
        descr: "Endpoint Identifier",
        standard: "[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]",
    },
    {
        code: 32,
        name: "NIMLOC",
        descr: "Nimrod Locator",
        standard: "[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]",
    },
    {
        code: 33,
        name: "SRV",
        descr: "Server Selection",
        standard: "[1][RFC2782]",
    },
    {
        code: 34,
        name: "ATMA",
        descr: "ATM Address",
        standard: "[ ATM Forum Technical Committee, \"ATM Name System, V2.0\", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]",
    },
    {
        code: 35,
        name: "NAPTR",
        descr: "Naming Authority Pointer",
        standard: "[RFC2915][RFC2168][RFC3403]",
    },
    {
        code: 36,
        name: "KX",
        descr: "Key Exchanger",
        standard: "[RFC2230]",
    },
    {
        code: 37,
        name: "CERT",
        descr: "CERT",
        standard: "[RFC4398]",
    },
    {
        code: 38,
        name: "A6",
        descr: "A6 (OBSOLETE - use AAAA)",
        standard: "[RFC3226][RFC2874][RFC6563]",
    },
    {
        code: 39,
        name: "DNAME",
        descr: "DNAME",
        standard: "[RFC6672]",
    },
    {
        code: 40,
        name: "SINK",
        descr: "SINK",
        standard: "[Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink]",
    },
    {
        code: 41,
        name: "OPT",
        descr: "OPT",
        standard: "[RFC6891][RFC3225]",
    },
    {
        code: 42,
        name: "APL",
        descr: "APL",
        standard: "[RFC3123]",
    },
    {
        code: 43,
        name: "DS",
        descr: "Delegation Signer",
        standard: "[RFC4034][RFC3658]",
    },
    {
        code: 44,
        name: "SSHFP",
        descr: "SSH Key Fingerprint",
        standard: "[RFC4255]",
    },
    {
        code: 45,
        name: "IPSECKEY",
        descr: "IPSECKEY",
        standard: "[RFC4025]",
    },
    {
        code: 46,
        name: "RRSIG",
        descr: "RRSIG",
        standard: "[RFC4034][RFC3755]",
        decode: function() { return "RR"; },
    },
    {
        code: 47,
        name: "NSEC",
        descr: "NSEC",
        standard: "[RFC4034][RFC3755]",
    },
    {
        code: 48,
        name: "DNSKEY",
        descr: "DNSKEY",
        standard: "[RFC4034][RFC3755]",
    },
    {
        code: 49,
        name: "DHCID",
        descr: "DHCID",
        standard: "[RFC4701]",
    },
    {
        code: 50,
        name: "NSEC3",
        descr: "NSEC3",
        standard: "[RFC5155]",
    },
    {
        code: 51,
        name: "NSEC3PARAM",
        descr: "NSEC3PARAM",
        standard: "[RFC5155]",
    },
    {
        code: 52,
        name: "TLSA",
        descr: "TLSA",
        standard: "[RFC6698]",
    },
    {
        code: 53,
        name: "SMIMEA",
        descr: "S/MIME cert association",
        standard: "[RFC8162]",
    },
    {
        code: 55,
        name: "HIP",
        descr: "Host Identity Protocol",
        standard: "[RFC8005]",
    },
    {
        code: 56,
        name: "NINFO",
        descr: "NINFO",
        standard: "[Jim_Reid]",
    },
    {
        code: 57,
        name: "RKEY",
        descr: "RKEY",
        standard: "[Jim_Reid]",
    },
    {
        code: 58,
        name: "TALINK",
        descr: "Trust Anchor LINK",
        standard: "[Wouter_Wijngaards]",
    },
    {
        code: 59,
        name: "CDS",
        descr: "Child DS",
        standard: "[RFC7344]",
    },
    {
        code: 60,
        name: "CDNSKEY",
        descr: "DNSKEY(s) the Child wants reflected in DS",
        standard: "[RFC7344]",
    },
    {
        code: 61,
        name: "OPENPGPKEY",
        descr: "OpenPGP Key",
        standard: "[RFC7929]",
    },
    {
        code: 62,
        name: "CSYNC",
        descr: "Child-To-Parent Synchronization",
        standard: "[RFC7477]",
    },
    {
        code: 63,
        name: "ZONEMD",
        descr: "message digest for DNS zone",
        standard: "[draft-wessels-dns-zone-digest]",
    },
    {
        code: 64,
        name: "SVCB",
        descr: "Service Binding",
        standard: "[draft-ietf-dnsop-svcb-https-00]",
    },
    {
        code: 65,
        name: "HTTPS",
        descr: "HTTPS Binding",
        standard: "[draft-ietf-dnsop-svcb-https-00]",
    },
    {
        code: 99,
        name: "SPF",
        descr: "",
        standard: "[RFC7208]",
    },
    {
        code: 100,
        name: "UINFO",
        descr: "",
        standard: "[IANA-Reserved]",
    },
    {
        code: 101,
        name: "UID",
        descr: "",
        standard: "[IANA-Reserved]",
    },
    {
        code: 102,
        name: "GID",
        descr: "",
        standard: "[IANA-Reserved]",
    },
    {
        code: 103,
        name: "UNSPEC",
        descr: "",
        standard: "[IANA-Reserved]",
    },
    {
        code: 104,
        name: "NID",
        descr: "",
        standard: "[RFC6742]",
    },
    {
        code: 105,
        name: "L32",
        descr: "",
        standard: "[RFC6742]",
    },
    {
        code: 106,
        name: "L64",
        descr: "",
        standard: "[RFC6742]",
    },
    {
        code: 107,
        name: "LP",
        descr: "",
        standard: "[RFC6742]",
    },
    {
        code: 108,
        name: "EUI48",
        descr: "an EUI-48 address",
        standard: "[RFC7043]",
    },
    {
        code: 109,
        name: "EUI64",
        descr: "an EUI-64 address",
        standard: "[RFC7043]",
    },
    {
        code: 249,
        name: "TKEY",
        descr: "Transaction Key",
        standard: "[RFC2930]",
    },
    {
        code: 250,
        name: "TSIG",
        descr: "Transaction Signature",
        standard: "[RFC-ietf-dnsop-rfc2845bis-09]",
    },
    {
        code: 251,
        name: "IXFR",
        descr: "incremental transfer",
        standard: "[RFC1995]",
    },
    {
        code: 252,
        name: "AXFR",
        descr: "transfer of an entire zone",
        standard: "[RFC1035][RFC5936]",
    },
    {
        code: 253,
        name: "MAILB",
        descr: "mailbox-related RRs (MB, MG or MR)",
        standard: "[RFC1035]",
    },
    {
        code: 254,
        name: "MAILA",
        descr: "mail agent RRs (OBSOLETE - see MX)",
        standard: "[RFC1035]",
    },
    {
        code: 255,
        name: "*",
        descr: "A request for some or all records the server has available",
        standard: "[RFC1035][RFC6895][RFC8482]",
    },
    {
        code: 256,
        name: "URI",
        descr: "URI",
        standard: "[RFC7553]",
    },
    {
        code: 257,
        name: "CAA",
        descr: "Certification Authority Restriction",
        standard: "[RFC8659]",
    },
    {
        code: 258,
        name: "AVC",
        descr: "Application Visibility and Control",
        standard: "[Wolfgang_Riedel]",
    },
    {
        code: 259,
        name: "DOA",
        descr: "Digital Object Architecture",
        standard: "[draft-durand-doa-over-dns]",
    },
    {
        code: 260,
        name: "AMTRELAY",
        descr: "Automatic Multicast Tunneling Relay",
        standard: "[RFC8777]",
    },
    {
        code: 32768,
        name: "TA",
        descr: "DNSSEC Trust Authorities",
        standard: "[Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]",
    },
    {
        code: 32769,
        name: "DLV",
        descr: "DNSSEC Lookaside Validation (OBSOLETE)",
        standard: "[RFC8749][RFC4431]",
    },
];

// Resource Record classes
const rrclass = [
    {
        code: 1,
        name: "IN",
        descr: "Internet",
    },
    {
        code: 3,
        name: "CH",
        descr: "Chaos",
    },
    {
        code: 4,
        name: "HS",
        descr: "Hesiod",
    },
    {
        code: 254,
        name: "NONE",
        descr: "QCLASS NONE",
    },
    {
        code: 255,
        name: "ANY",
        descr: "QCLASS *",
    },
];

function decodeName(view, offset, packetView) {
    // TODO Check for compressed pointer to compress.
    // TODO Check for long DNS name
    // TODO Check for multiple compression layers
    // TODO Check for uncompressed DNS name support
    // TODO Check for broken DNS names
    // TODO Check duplicate DNS names
    // TODO Check for exact DNS limits
    // TODO Check for label truncated
    // TODO Check for pointer outside range
    var nextPtr = 0;
    var name = ''
    var follow = false;
    while(true) {
        var len = view.getUint8(offset); offset += 1;
        if((len & 0xc0) == 0xc0) {
            if(follow) {
                throw Error("Domain pointer is broken");
            }
            var offset2 = ((len & ~0xc0) << 8) | view.getUint8(offset);
            offset += 1;
            if(nextPtr == 0) {
                nextPtr = offset;
            }
            offset = offset2;
            view = packetView;
            if(!view) {
                throw Error("Found compressed domain name when not expected");
            }
            follow = true;
            continue;
            //break;  // Compressed DNS name
        } else
        if(len > 63) {
            throw Error('DNS label too long');  // Broken DNS packet
        } else
        if(len == 0) {
            break;  // End of DNS name
        } else {
            for(var j = 0; j < len; j++) {
                name += String.fromCharCode(view.getUint8(offset++))
            }
            name += '.'
            if(name.length > 256) {
                throw Error('DNS name too long');
            }
        }
        follow = false;
    }
    if(nextPtr > 0) {
        offset = nextPtr;
    }

    return [offset, name];
}

function decodeRecordHeader(view, offset) {
    var [ptr, name] = decodeName(view, offset, view);
    var type = view.getUint16(ptr); ptr += 2;
    var class_ = view.getUint16(ptr); ptr += 2;
    type = rrtype.find(item => item.code === type).name;
    console.log(class_);
    class_ = (rrclass.find(item => item.code === class_) || {name: `C${class_}`}).name;
    return [ptr, name, type, class_];
}

function decodeRecord(view, offset) {
    var name, type, class_;
    [offset, name, type, class_] = decodeRecordHeader(view, offset);
    var ttl = view.getInt32(offset); offset += 4;
    var rdlength = view.getUint16(offset); offset += 2;
    console.log(`Record name: ${name}, type: ${type}, len: ${rdlength}`);
    var rdata = view.buffer.slice(offset, offset+rdlength);
    var rview = new DataView(rdata);
    offset += rdlength;
    var a = rrtype.find(item => item.name == type);
    if(a.decode) {
        var value = a.decode(rview);
        console.log(`RValue: ${value}`);
        rdata = value;
    }
    return [offset, name, type, class_, ttl, rdata];
}

function decode(data) {
    console.log(data);
    var msg = {};
    var adFlag = 1 << 5;
    var view = new DataView(data);
    var ptr = 0;
    msg.id = view.getUint16(ptr);      ptr += 2;
    var header = view.getUint16(ptr);   ptr += 2;
    msg.opcode = findOpcode(header & opcodeMask);
    msg.isResponse = (header & qrBit) === qrBit;
    msg.rcode = rcodes.find(item => item.code === (header & rcodeMask)).name;
    msg.flags = findFlags(header);
    msg.question = [];
    msg.answer = [];
    msg.authority = [];
    msg.additional = [];
    var qdcount = view.getUint16(ptr); ptr += 2;
    var ancount = view.getUint16(ptr); ptr += 2;
    var nscount = view.getUint16(ptr); ptr += 2;
    var arcount = view.getUint16(ptr); ptr += 2;
    for(var i = 0; i < qdcount; i++) {
        var name, type, class_;
        [ptr, name, type, class_] = decodeRecordHeader(view, ptr);
        msg.question.push({name: name, type: type, class: class_});
        console.log(`Q was ${name}, type: ${type}, class: ${class_}`);
    }
    for(var i = 0; i < ancount; i++) {
        var name, type, class_, ttl, rdata;
        [ptr, name, type, class_, ttl, rdata] = decodeRecord(view, ptr);
        console.log(`A was ${name}`);
        msg.answer.push({name: name, type: type, class: class_, ttl: ttl, rdata: rdata});
    }
    for(var i = 0; i < nscount; i++) {
        var name, type, class_, ttl, rdata;
        [ptr, name, type, class_, ttl, rdata] = decodeRecord(view, ptr);
        console.log(`N was ${name}`);
        msg.authority.push({name: name, type: type, class: class_, ttl: ttl, rdata: rdata});
    }
    for(var i = 0; i < arcount; i++) {
        var name, type, class_, ttl, rdata;
        [ptr, name, type, class_, ttl, rdata] = decodeRecord(view, ptr);
        console.log(`R was ${name}`);
        msg.additional.push({name: name, type: type, class: class_, ttl: ttl, rdata: rdata});
    }
    console.log(msg);
    if((header & adFlag) == adFlag) {
        console.log("Authenticated data for '" + domain + "': 0x" + header.toString(16) + "!");
    } else {
        console.log("Not authentic for '" + domain + "': 0x" + header.toString(16) + "!");
    }
}
exports.decode = decode;
var domain = '';

exports.DNSRequest = function DNSRequest(domain_) {
    domain = domain_;
    var arrayBuffer = new ArrayBuffer(4096);
    var view = new DataView(arrayBuffer);
    var fields = {
        id: Math.floor(Math.random()*65536),
        opcode: "QUERY",
        isResponse: false,
        rcode: "nOeRror",
        flags: [ "RD", "AD" ],
        question: [ { name: domain, type: "A", class: "IN" } ],
        answer: [],
        authority: [],
        additional: [ { name: "", type: "OPT" } ],
    };
    var header = opcodes[fields.opcode.toLowerCase()];
    if(fields.isResponse) {
        header |= qrBit;
    }
    header |= fields.flags.map(item => flags[item]).reduce((item, value) => item | value);
    header |= rcodes.find(item => item.name.toLowerCase() == fields.rcode.toLowerCase()).code;
    var ptr = 0;
    view.setUint16(ptr, fields.id);                ptr += 2;
    view.setUint16(ptr, header);                   ptr += 2;
    view.setUint16(ptr, fields.question.length);   ptr += 2;
    view.setUint16(ptr, fields.answer.length);     ptr += 2;
    view.setUint16(ptr, fields.authority.length);  ptr += 2;
    view.setUint16(ptr, fields.additional.length); ptr += 2;
    for(var i = 0; i < fields.question.length; i++) {
        var labels = fields.question[i].name.split('.');
        for(var j = 0; j < labels.length; j++) {
            var label = labels[j];
            view.setUint8(ptr++, label.length);
            for(var k = 0; k < label.length; k++)
                view.setUint8(ptr++, label.charCodeAt(k));
        }
        view.setUint8(ptr++, 0); /* zero-length root label */
        view.setUint16(ptr, rrtype.find(item => item.name == fields.question[i].type).code);   ptr += 2;
        //console.log(rrclass[0].descr);
        view.setUint16(ptr, rrclass.find(item => item.name == fields.question[i].class).code); ptr += 2;
    }
    for(var i = 0; i < fields.additional.length; i++) {
        if(fields.additional[i].name != "") {
            var labels = fields.additional[i].split('.');
            for(var j = 0; j < labels.length; j++) {
                var label = labels[j];
                view.setUint8(ptr++, label.length);
                for(var k = 0; k < label.length; k++)
                    view.setUint8(ptr++, label.charCodeAt(k));
            }
        }
        view.setUint8(ptr++, 0); /* zero-length root label */
        view.setUint16(ptr, rrtype.find(item => item.name == fields.additional[i].type).code);   ptr += 2;
        view.setUint16(ptr, 4096); ptr += 2;
        view.setUint8(ptr,  0); ptr += 1;
        view.setUint8(ptr,  0); ptr += 1;
        view.setUint16(ptr,  1 << 15); ptr += 2;
        view.setUint16(ptr,  0); ptr += 2;
    }
    var buf2 = new ArrayBuffer(ptr);
    var view2 = new DataView(buf2);
    for(var i = 0; i < ptr; i++)
        view2.setUint8(i, view.getUint8(i));
    arrayBuffer = buf2;
    return arrayBuffer;
}
