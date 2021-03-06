'use strict';

var rewire = require('rewire');
var base64 = require('base64-arraybuffer');

class Packer {
    constructor(view) {
        this.view = view;
        this.offset = 0;
    }

    packUint8(value) {
        this.view.setUint8(this.offset, value);
        this.offset += 1;
    }

    packUint16(value) {
        this.view.setUint16(this.offset, value);
        this.offset += 2;
    }

    packUint32(value) {
        this.view.setUint32(this.offset, value);
        this.offset += 4;
    }

    packLabel(label) {
        if(label == '.') {
            label = '';
        }
        this.packUint8(label.length);
        for(var c in label) {
            this.packUint8(label.charCodeAt(c));
        }
    }

    packLabels(labels) {
        for(var idx in labels) {
            this.packLabel(labels[idx]);
        }
    }

    packString(label) {
        this.packUint8(label.length);
        for(var c in label) {
            this.packUint8(label.charCodeAt(c));
        }
    }

    packPointer(pointer) {
        this.packUint16(0xc000 | pointer);
    }

    getOffset() {
        return this.offset;
    }
}



describe("lib", function() {
  var lib = rewire('../../lib');
  var decodeName = lib.__get__('decodeName');
  var decodeRecordHeader = lib.__get__('decodeRecordHeader');
  var decodeRecord = lib.__get__('decodeRecord');
  var encodePacket = lib.__get__('encodePacket');

  xit("should encode a DNS message", function() {
    lib.DNSRequest({});
    //player.play(song);
    //expect(player.currentlyPlayingSong).toEqual(song);

    //demonstrates use of custom matcher
    //expect(player).toBePlaying(song);
  });

  it("should decode a DNS label", function() {
      var buf = new ArrayBuffer(16);
      var view = new DataView(buf);
      view.setUint8(0, 3);
      view.setUint8(1, 'c'.charCodeAt(0));
      view.setUint8(2, 'o'.charCodeAt(0));
      view.setUint8(3, 'm'.charCodeAt(0));
      view.setUint8(4, 0);
      var [offset, name] = decodeName(view, 0, null);
      expect(name).toBe('com.');
      expect(offset).toBe(5);
  });

  it("should decode a multi-label DNS name", function() {
      var buf = new ArrayBuffer(16);
      var view = new DataView(buf);
      var i = 0;
      view.setUint8(i++, 3);
      view.setUint8(i++, 'w'.charCodeAt(0));
      view.setUint8(i++, 'w'.charCodeAt(0));
      view.setUint8(i++, 'w'.charCodeAt(0));
      view.setUint8(i++, 4);
      view.setUint8(i++, 't'.charCodeAt(0));
      view.setUint8(i++, 'e'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint8(i++, 't'.charCodeAt(0));
      view.setUint8(i++, 3);
      view.setUint8(i++, 'c'.charCodeAt(0));
      view.setUint8(i++, 'o'.charCodeAt(0));
      view.setUint8(i++, 'm'.charCodeAt(0));
      view.setUint8(i++, 0);
      var [offset, name] = decodeName(view, 0, null);
      expect(name).toBe('www.test.com.');
      expect(offset).toBe(i);
  });

  it("should decode a DNS name with compression", function() {
      var buf = new ArrayBuffer(32);
      var view = new DataView(buf);
      var i = 0;
      view.setUint8(i++, 3);
      view.setUint8(i++, 'w'.charCodeAt(0));
      view.setUint8(i++, 'w'.charCodeAt(0));
      view.setUint8(i++, 'w'.charCodeAt(0));
      var compressionOffset = i;
      view.setUint8(i++, 4);
      view.setUint8(i++, 't'.charCodeAt(0));
      view.setUint8(i++, 'e'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint8(i++, 't'.charCodeAt(0));
      view.setUint8(i++, 3);
      view.setUint8(i++, 'c'.charCodeAt(0));
      view.setUint8(i++, 'o'.charCodeAt(0));
      view.setUint8(i++, 'm'.charCodeAt(0));
      view.setUint8(i++, 0);
      var startOffset = i;
      view.setUint8(i++, 2);
      view.setUint8(i++, 'n'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compressionOffset); i++;
      var [offset, name] = decodeName(view, startOffset, view);
      expect(name).toBe('ns.test.com.');
      expect(offset).toBe(i);
  });

  it("should decode a DNS name with multi-level compression", function() {
      var buf = new ArrayBuffer(32);
      var view = new DataView(buf);
      var i = 0;
      view.setUint8(i++, 3);
      view.setUint8(i++, 'w'.charCodeAt(0));
      view.setUint8(i++, 'w'.charCodeAt(0));
      view.setUint8(i++, 'w'.charCodeAt(0));
      var compressionOffset = i;
      view.setUint8(i++, 4);
      view.setUint8(i++, 't'.charCodeAt(0));
      view.setUint8(i++, 'e'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint8(i++, 't'.charCodeAt(0));
      view.setUint8(i++, 3);
      view.setUint8(i++, 'c'.charCodeAt(0));
      view.setUint8(i++, 'o'.charCodeAt(0));
      view.setUint8(i++, 'm'.charCodeAt(0));
      view.setUint8(i++, 0);
      var compressionOffset2 = i;
      view.setUint8(i++, 2);
      view.setUint8(i++, 'n'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compressionOffset); i++;
      var startOffset = i;
      view.setUint8(i++, 5);
      view.setUint8(i++, 'c'.charCodeAt(0));
      view.setUint8(i++, 'h'.charCodeAt(0));
      view.setUint8(i++, 'i'.charCodeAt(0));
      view.setUint8(i++, 'l'.charCodeAt(0));
      view.setUint8(i++, 'd'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compressionOffset2); i++;
      var [offset, name] = decodeName(view, startOffset, view);
      expect(name).toBe('child.ns.test.com.');
      expect(offset).toBe(i);
  });

  it("should decode a repeated DNS name with multi-level compression", function() {
      var buf = new ArrayBuffer(32);
      var view = new DataView(buf);
      var i = 0;
      view.setUint8(i++, 3);
      view.setUint8(i++, 'w'.charCodeAt(0));
      view.setUint8(i++, 'w'.charCodeAt(0));
      view.setUint8(i++, 'w'.charCodeAt(0));
      var compressionOffset = i;
      view.setUint8(i++, 4);
      view.setUint8(i++, 't'.charCodeAt(0));
      view.setUint8(i++, 'e'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint8(i++, 't'.charCodeAt(0));
      view.setUint8(i++, 3);
      view.setUint8(i++, 'c'.charCodeAt(0));
      view.setUint8(i++, 'o'.charCodeAt(0));
      view.setUint8(i++, 'm'.charCodeAt(0));
      view.setUint8(i++, 0);
      var compressionOffset2 = i;
      view.setUint8(i++, 2);
      view.setUint8(i++, 'n'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compressionOffset); i++;
      var startOffset = i;
      view.setUint8(i++, 5);
      view.setUint8(i++, 'c'.charCodeAt(0));
      view.setUint8(i++, 'h'.charCodeAt(0));
      view.setUint8(i++, 'i'.charCodeAt(0));
      view.setUint8(i++, 'l'.charCodeAt(0));
      view.setUint8(i++, 'd'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compressionOffset2); i++;
      var [offset, name] = decodeName(view, startOffset, view);
      expect(name).toBe('child.ns.test.com.');
      expect(offset).toBe(i);
  });

  it("should decode a DNS domain with multi-level compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels(['delete']);
      var wwwOffset = packer.getOffset();
      packer.packLabels(['www']);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var nsOffset = packer.getOffset();
      packer.packLabels(['ns']);
      packer.packPointer(testOffset);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(nsOffset);

      /*
      var raw = [];
      for(var i = 0; i < 64; i++) {
          raw.push(view.getUint8(i));
      }
      console.log(raw);
      */

      var [offset, name] = decodeName(view, startOffset, view);
      expect(name).toBe('child.ns.test.com.');
      expect(offset).toBe(packer.getOffset());

      var [offset, name] = decodeName(view, wwwOffset, view);
      expect(name).toBe('www.test.com.');
  });

  it("should decode raise an error on long domain name", function() {
      var buf = new ArrayBuffer(512);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels([
          'long', 'long', 'long', 'long', 'long', 'long', 'long', 'long',
          'long', 'long', 'long', 'long', 'long', 'long', 'long', 'long',
          'long', 'long', 'long', 'long', 'long', 'long', 'long', 'long',
          'long', 'long', 'long', 'long', 'long', 'long', 'long', 'long',
          'long', 'long', 'long', 'long', 'long', 'long', 'long', 'long',
          'long', 'long', 'long', 'long', 'long', 'long', 'long', 'long',
          'long', 'long', 'long', 'long', '.',
      ]);

      expect(function() { decodeName(view, 0, view); }).toThrowError(/long/);
  });

  it("should decode raise an error on pointer loop", function() {
      var buf = new ArrayBuffer(16);
      var view = new DataView(buf);
      var packer = new Packer(view);

      packer.packLabels(['long', 'long']);
      packer.packPointer(0);  /* Point back to start */
      packer.packLabel('.');

      expect(function() { decodeName(view, 0, view); }).toThrowError(/long/);
  });

  it("should decode raise an error on broken pointer", function() {
      var buf = new ArrayBuffer(16);
      var view = new DataView(buf);
      var packer = new Packer(view);

      packer.packLabels(['long', 'long', '.']);
      var loopOffset = packer.getOffset();
      packer.packPointer(loopOffset);
      packer.packLabel('.');

      expect(function() {
          decodeName(view, loopOffset, view);
      }).toThrowError(/broken/);
  });

  it("should decode raise an error on label too long", function() {
      var buf = new ArrayBuffer(256);
      var view = new DataView(buf);
      var packer = new Packer(view);

      var goodLabelOffset = packer.getOffset();
      packer.packLabels(
          ['123456789012345678901234567890123456789012345678901234567890123',
           '.']);
      var badLabelOffset = packer.getOffset();
      packer.packLabels(
          ['1234567890123456789012345678901234567890123456789012345678901234',
           '.']);

      expect(decodeName(view, goodLabelOffset, view)).toBeTruthy();
      expect(function() { decodeName(view, badLabelOffset, view); }).toThrowError(/label too/);
  });

  it("should decode raise an error on compressed domain missing context", function() {
      var buf = new ArrayBuffer(256);
      var view = new DataView(buf);
      var packer = new Packer(view);

      packer.packLabels(['one', '.']);
      var domainOffset = packer.getOffset();
      packer.packLabels(['two']);
      packer.packPointer(0);

      expect(decodeName(view, domainOffset, view)).toBeTruthy();
      expect(function() { decodeName(view, domainOffset, null); }).toThrowError(/compressed domain/);
  });

  it("should decode raise an error on compressed domain missing context", function() {
      var buf = new ArrayBuffer(256);
      var view = new DataView(buf);
      var packer = new Packer(view);

      packer.packLabels(['one', '.']);
      var domainOffset = packer.getOffset();
      packer.packLabels(['two']);
      packer.packPointer(0);

      expect(decodeName(view, domainOffset, view)).toBeTruthy();
      expect(function() { decodeName(view, domainOffset, null); }).toThrowError(/compressed domain/);
  });

  it("should decode a DNS record header with multi-level compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels(['delete']);
      var wwwOffset = packer.getOffset();
      packer.packLabels(['www']);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var nsOffset = packer.getOffset();
      packer.packLabels(['ns']);
      packer.packPointer(testOffset);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(nsOffset);
      packer.packUint16(5);  /* RR Type CNAME */
      packer.packUint16(4);  /* RR Class HS */

      var [offset, name, type, class_] = decodeRecordHeader(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.ns.test.com.');
      expect(type).toBe('CNAME');
      expect(class_).toBe('HS');
  });

    /* TODO Test unrecognized type and class */

  it("should decode a DNS record with multi-level compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels(['delete']);
      var wwwOffset = packer.getOffset();
      packer.packLabels(['www']);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var nsOffset = packer.getOffset();
      packer.packLabels(['ns']);
      packer.packPointer(testOffset);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(nsOffset);
      packer.packUint16(1);    /* RR Type A */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(480);  /* RR TTL */
      packer.packUint16(4);    /* RR Data length */
      packer.packUint8(1);     /* RR Data */
      packer.packUint8(2);     /* RR Data */
      packer.packUint8(3);     /* RR Data */
      packer.packUint8(4);     /* RR Data */

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.ns.test.com.');
      expect(type).toBe('A');
      expect(class_).toBe('IN');
      expect(ttl).toBe(480);
      expect(rdata).toBe('1.2.3.4');
  });

  it("should decode a CNAME record", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels(['delete']);
      var wwwOffset = packer.getOffset();
      packer.packLabels(['www']);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var nsOffset = packer.getOffset();
      var startOffset = packer.getOffset();
      packer.packLabels(['ns']);
      packer.packPointer(testOffset);
      //packer.packLabels(['child']);
      //packer.packPointer(nsOffset);
      packer.packUint16(5);    /* RR Type CNAME */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(3600); /* RR TTL */
      packer.packUint16(17);   /* RR Data length */
      packer.packLabels(['www', 'example', 'org', '.']);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('ns.test.com.');
      expect(type).toBe('CNAME');
      expect(class_).toBe('IN');
      expect(ttl).toBe(3600);
      expect(rdata).toBe('www.example.org.');
  });

  it("should decode a CNAME record with partial compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels(['delete']);
      var wwwOffset = packer.getOffset();
      packer.packLabels(['www']);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var nsOffset = packer.getOffset();
      packer.packLabels(['ns']);
      packer.packPointer(testOffset);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(nsOffset);
      packer.packUint16(5);    /* RR Type CNAME */
      packer.packUint16(3);    /* RR Class CH */
      packer.packUint32(12345678); /* RR TTL */
      packer.packUint16(6);   /* RR Data length */
      packer.packLabels(['www']);
      packer.packPointer(testOffset);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.ns.test.com.');
      expect(type).toBe('CNAME');
      expect(class_).toBe('CH');
      expect(ttl).toBe(12345678);
      expect(rdata).toBe('www.test.com.');
  });

  it("should decode a CNAME record with full compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels(['delete']);
      var wwwOffset = packer.getOffset();
      packer.packLabels(['www']);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var nsOffset = packer.getOffset();
      packer.packLabels(['ns']);
      packer.packPointer(testOffset);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(nsOffset);
      packer.packUint16(5);    /* RR Type CNAME */
      packer.packUint16(3);    /* RR Class CH */
      packer.packUint32(12); /* RR TTL */
      packer.packUint16(2);   /* RR Data length */
      packer.packPointer(wwwOffset);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.ns.test.com.');
      expect(type).toBe('CNAME');
      expect(class_).toBe('CH');
      expect(ttl).toBe(12);
      expect(rdata).toBe('www.test.com.');
  });

  it("should decode an MB record with full compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels(['delete']);
      var wwwOffset = packer.getOffset();
      packer.packLabels(['www']);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var nsOffset = packer.getOffset();
      packer.packLabels(['ns']);
      packer.packPointer(testOffset);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(nsOffset);
      packer.packUint16(7);    /* RR Type MB */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(0); /* RR TTL */
      packer.packUint16(2);   /* RR Data length */
      packer.packPointer(wwwOffset);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.ns.test.com.');
      expect(type).toBe('MB');
      expect(class_).toBe('IN');
      expect(ttl).toBe(0);
      expect(rdata).toBe('www.test.com.');
  });

  it("should decode an HINFO record", function() {
      var buf = new ArrayBuffer(512);
      var view = new DataView(buf);

      var cpu = "This is quick the CPU name, but not too long";
      var os = 
          "This is an extremely long and very boring name for "
          "an operating system that you will never likely run.";

      var packer = new Packer(view);
      var wwwOffset = packer.getOffset();
      packer.packLabels(['www', 'test', 'com', '.']);
      packer.packUint16(13);    /* RR Type HINFO */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(64); /* RR TTL */
      packer.packUint16(cpu.length + os.length + 2);   /* RR Data length */
      packer.packString(cpu);
      packer.packString(os);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, 0);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('www.test.com.');
      expect(type).toBe('HINFO');
      expect(class_).toBe('IN');
      expect(ttl).toBe(64);
      expect(rdata).toBeDefined();
      expect(rdata.cpu).toBeDefined();
      expect(rdata.cpu).toBe(cpu);
      expect(rdata.os).toBeDefined();
      expect(rdata.os).toBe(os);
  });

  it("should decode an MD record with partial compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(testOffset);
      packer.packUint16(3);    /* RR Type MD */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(6);   /* RR Data length */
      packer.packLabels(['www']);
      packer.packPointer(testOffset);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.test.com.');
      expect(type).toBe('MD');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBe('www.test.com.');
  });

  it("should decode an MF record with no compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(testOffset);
      packer.packUint16(4);    /* RR Type MF */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(17);   /* RR Data length */
      packer.packLabels(['www', 'example', 'org', '.']);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.test.com.');
      expect(type).toBe('MF');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBe('www.example.org.');
  });

  it("should decode an MINFO record with partial compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(testOffset);
      packer.packUint16(14);    /* RR Type MINFO */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(12);   /* RR Data length */
      packer.packLabels(['one']);
      packer.packPointer(testOffset);
      packer.packLabels(['two']);
      packer.packPointer(testOffset);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.test.com.');
      expect(type).toBe('MINFO');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBeDefined();
      expect(rdata.rmailbx).toBeDefined();
      expect(rdata.rmailbx).toBe('one.test.com.');
      expect(rdata.emailbx).toBeDefined();
      expect(rdata.emailbx).toBe('two.test.com.');
  });

  it("should decode an MR record with partial compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(testOffset);
      packer.packUint16(9);    /* RR Type MR */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(6);   /* RR Data length */
      packer.packLabels(['www']);
      packer.packPointer(testOffset);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.test.com.');
      expect(type).toBe('MR');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBe('www.test.com.');
  });

  it("should decode an MX record with partial compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(testOffset);
      packer.packUint16(15);    /* RR Type MX */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(8);   /* RR Data length */
      packer.packUint16(25);   /* MX Preference field */
      packer.packLabels(['www']);
      packer.packPointer(testOffset);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.test.com.');
      expect(type).toBe('MX');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBeDefined();
      expect(rdata.pref).toBeDefined();
      expect(rdata.pref).toBe(25);
      expect(rdata.exchange).toBeDefined();
      expect(rdata.exchange).toBe('www.test.com.');
  });

  it("should decode a NULL record", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var startOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      packer.packUint16(10);    /* RR Type MX */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(4);   /* RR Data length */
      packer.packUint8(5);
      packer.packUint8(6);
      packer.packUint8(7);
      packer.packUint8(8);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('test.com.');
      expect(type).toBe('NULL');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBeDefined();
      expect(rdata).toBeInstanceOf(ArrayBuffer);
      var view = new DataView(rdata);
      expect(view.getUint8(0)).toBe(5);
      expect(view.getUint8(1)).toBe(6);
      expect(view.getUint8(2)).toBe(7);
      expect(view.getUint8(3)).toBe(8);
  });

  it("should decode an NS record with partial compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(testOffset);
      packer.packUint16(2);    /* RR Type NS */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(6);   /* RR Data length */
      packer.packLabels(['www']);
      packer.packPointer(testOffset);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.test.com.');
      expect(type).toBe('NS');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBe('www.test.com.');
  });

  it("should decode an PTR record with partial compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      var startOffset = packer.getOffset();
      packer.packLabels(['child']);
      packer.packPointer(testOffset);
      packer.packUint16(12);   /* RR Type PTR */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(6);    /* RR Data length */
      packer.packLabels(['www']);
      packer.packPointer(testOffset);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.test.com.');
      expect(type).toBe('PTR');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBe('www.test.com.');
  });

  it("should decode a SOA record with partial compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      packer.packUint16(6);    /* RR Type SOA */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(38);   /* RR Data length */
      packer.packLabels(['primary']);
      packer.packPointer(testOffset);
      packer.packLabels(['owner']);
      packer.packPointer(testOffset);
      packer.packUint32(123);  /* Serial */
      packer.packUint32(1200); /* Refresh */
      packer.packUint32(300);  /* Retry */
      packer.packUint32(99999);/* Expire */
      packer.packUint32(480);  /* Minimum */

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, testOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('test.com.');
      expect(type).toBe('SOA');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBeDefined();
      expect(rdata.mname).toBeDefined();
      expect(rdata.mname).toBe('primary.test.com.');
      expect(rdata.rname).toBeDefined();
      expect(rdata.rname).toBe('owner.test.com.');
      expect(rdata.serial).toBeDefined();
      expect(rdata.serial).toBe(123);
      expect(rdata.refresh).toBeDefined();
      expect(rdata.refresh).toBe(1200);
      expect(rdata.retry).toBeDefined();
      expect(rdata.retry).toBe(300);
      expect(rdata.expire).toBeDefined();
      expect(rdata.expire).toBe(99999);
      expect(rdata.minimum).toBeDefined();
      expect(rdata.minimum).toBe(480);
  });

  it("should decode a TXT record", function() {
      var buf = new ArrayBuffer(128);
      var view = new DataView(buf);

      var txt = "Some intersting text to put into a TXT record."
      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      packer.packUint16(16);   /* RR Type TXT */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(txt.length + 1);   /* RR Data length */
      packer.packString(txt);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, testOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('test.com.');
      expect(type).toBe('TXT');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBe(txt);
  });

  it("should decode an AAAA record", function() {
      var buf = new ArrayBuffer(128);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      packer.packUint16(28);   /* RR Type AA */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(16);   /* RR Data length */
      packer.packUint16(10);
      packer.packUint16(256);
      packer.packUint16(4096);
      packer.packUint16(0);
      packer.packUint16(32);
      packer.packUint16(2560);
      packer.packUint16(0);
      packer.packUint16(1);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, testOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('test.com.');
      expect(type).toBe('AAAA');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBe("a:100:1000:0:20:a00:0:1");
  });

  it("should decode an AAAA record", function() {
      var buf = new ArrayBuffer(128);
      var view = new DataView(buf);

      var packer = new Packer(view);
      var testOffset = packer.getOffset();
      packer.packLabels(['test', 'com', '.']);
      packer.packUint16(28);   /* RR Type AA */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(16);   /* RR Data length */
      packer.packUint16(10);
      packer.packUint16(256);
      packer.packUint16(4096);
      packer.packUint16(0);
      packer.packUint16(32);
      packer.packUint16(2560);
      packer.packUint16(0);
      packer.packUint16(1);

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, testOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('test.com.');
      expect(type).toBe('AAAA');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBe("a:100:1000:0:20:a00:0:1");
  });

  it("should decode a DS record", function() {
      var buf = new ArrayBuffer(128);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels(['test', 'com', '.']);
      packer.packUint16(43);   /* RR Type DS */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      packer.packUint16(24);   /* RR Data length */
      packer.packUint16(12345);/* Key tag */
      packer.packUint8(5);     /* Algorithm RSA/SHA-1 */
      packer.packUint8(1);     /* Digest SHA-1 */
      for(var i = 0; i < 20; i++)
          packer.packUint8(0); /* Digest Data */

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, 0);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('test.com.');
      expect(type).toBe('DS');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBeDefined();
      expect(rdata.tag).toBeDefined();
      expect(rdata.tag).toBe(12345);
      expect(rdata.algorithm).toBeDefined();
      expect(rdata.algorithm).toBe("RSASHA1");
      expect(rdata.digest).toBeDefined();
      expect(rdata.digest).toBe("SHA1");
      expect(rdata.digest_hash).toBeDefined();
      expect(rdata.digest_hash).toBeInstanceOf(ArrayBuffer);
  });

  it("should decode a DNSKEY record", function() {
      var buf = new ArrayBuffer(256);
      var view = new DataView(buf);

      var packer = new Packer(view);
      packer.packLabels(['test', 'com', '.']);
      packer.packUint16(48);   /* RR Type DNSKEY */
      packer.packUint16(1);    /* RR Class IN */
      packer.packUint32(512);  /* RR TTL */
      var key = base64.decode(
          "AQPPQ2tvH4YbcKOsaHDO12qf5XsKPQhauMUmvcO5SCgBKqCXA7MuEkrh" +
          "SjeRrDu/pcWF7NBuPdE3e7ETUcnqB0s7p9rTbIN15J+swZGRTsdK6lXw" +
          "hUmtl5OFnKx0eqgwpIdoqoG0hsrrtLGTzn48qHWfNXKDXmjfZPiT+UPf" +
          "J57+bw==");
      expect(key.byteLength).toBe(1024/8 + 1 + 1);
      var key_view = new DataView(key);
      packer.packUint16(key.byteLength+4);   /* RR Data length */
      packer.packUint16(256);  /* Key flags ZONE */
      packer.packUint8(3);     /* Protocol DNSSEC */
      packer.packUint8(5);     /* Algorithm RSA/SHA-1 */
      for(var i = 0; i < key.byteLength; i++)
          packer.packUint8(key_view.getUint8(i)); /* Key Data */

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, 0);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('test.com.');
      expect(type).toBe('DNSKEY');
      expect(class_).toBe('IN');
      expect(ttl).toBe(512);
      expect(rdata).toBeDefined();
      expect(rdata.tag).toBeDefined();
      expect(rdata.tag).toBe(52406);
      expect(rdata.flags).toBeDefined();
      expect(rdata.flags).toBe(256);
      expect(rdata.protocol).toBeDefined();
      expect(rdata.protocol).toBe("DNSSEC");
      expect(rdata.algorithm).toBeDefined();
      expect(rdata.algorithm).toBe("RSASHA1");
      expect(rdata.key).toBeDefined();
      expect(rdata.key.exponent).toBeDefined();
      expect(rdata.key.exponent).toBe(3);
      expect(rdata.key.modulus).toBeDefined();
      expect(rdata.key.modulus).toBeInstanceOf(ArrayBuffer);
      expect(rdata.key.modulus.byteLength).toBe(1024/8);
  });

  it("should encode an empty DNS request", function() {
      var fields = {
          id: Math.floor(Math.random()*65536),
          opcode: "Query",
          isResponse: false,
          rcode: "nOeRror",
          flags: [],
          question: [],
          answer: [],
          authority: [],
          additional: [],
      };
      var packet = encodePacket(fields);
      var view = new DataView(packet);
      expect(view.getUint16(0)).toBe(fields.id);
      expect(view.getUint16(2)).toBe(0);   /* header */
      expect(view.getUint16(4)).toBe(0);   /* question */
      expect(view.getUint16(6)).toBe(0);   /* answer */
      expect(view.getUint16(8)).toBe(0);   /* authority */
      expect(view.getUint16(10)).toBe(0);  /* additional */
      expect(view.getUint16(10)).toBe(0);  /* additional */
      expect(packet.byteLength).toBe(12);
  });

  it("should encode an empty DNS request with default values", function() {
      var fields = {
          id: Math.floor(Math.random()*65536),
      };
      var packet = encodePacket(fields);
      var view = new DataView(packet);
      expect(view.getUint16(0)).toBe(fields.id);
      expect(view.getUint16(2)).toBe(0);   /* header */
      expect(view.getUint16(4)).toBe(0);   /* question */
      expect(view.getUint16(6)).toBe(0);   /* answer */
      expect(view.getUint16(8)).toBe(0);   /* authority */
      expect(view.getUint16(10)).toBe(0);  /* additional */
      expect(view.getUint16(10)).toBe(0);  /* additional */
      expect(packet.byteLength).toBe(12);
  });

  it("should encode an basic IP address DNS request", function() {
      var fields = {
          id: Math.floor(Math.random()*65536),
          flags: [ "RD", "AD" ],
          question: [
              { name: "com", type: "A", class: "IN" },
          ],
      };
      var packet = encodePacket(fields);
      var view = new DataView(packet);
      expect(view.getUint16(0)).toBe(fields.id);
      expect(view.getUint16(2)).toBe((1<<8)|(1<<5));   /* RD AD */
      expect(view.getUint16(4)).toBe(1);   /* question */
      expect(view.getUint16(6)).toBe(0);   /* answer */
      expect(view.getUint16(8)).toBe(0);   /* authority */
      expect(view.getUint16(10)).toBe(0);  /* additional */
      expect(view.getUint8(12)).toBe(3);
      expect(view.getUint8(13)).toBe('c'.charCodeAt(0));
      expect(view.getUint8(14)).toBe('o'.charCodeAt(0));
      expect(view.getUint8(15)).toBe('m'.charCodeAt(0));
      expect(view.getUint8(16)).toBe(0);
      expect(view.getUint16(17)).toBe(1);
      expect(view.getUint16(19)).toBe(1);
      expect(packet.byteLength).toBe(21);
  });

  it("should encode an DNSSEC IP address DNS request", function() {
      var fields = {
          id: Math.floor(Math.random()*65536),
          flags: [ "RD", "AD", "DO" ],
          question: [
              { name: "com", type: "A", class: "IN" },
          ],
      };
      var packet = encodePacket(fields);
      var view = new DataView(packet);
      expect(view.getUint16(0)).toBe(fields.id);
      expect(view.getUint16(2)).toBe((1<<8)|(1<<5));   /* RD AD */
      expect(view.getUint16(4)).toBe(1);   /* question */
      expect(view.getUint16(6)).toBe(0);   /* answer */
      expect(view.getUint16(8)).toBe(0);   /* authority */
      expect(view.getUint16(10)).toBe(1);  /* additional */
      expect(view.getUint8(12)).toBe(3);   /* com. */
      expect(view.getUint8(13)).toBe('c'.charCodeAt(0));
      expect(view.getUint8(14)).toBe('o'.charCodeAt(0));
      expect(view.getUint8(15)).toBe('m'.charCodeAt(0));
      expect(view.getUint8(16)).toBe(0);
      expect(view.getUint16(17)).toBe(1);  /* Type A */
      expect(view.getUint16(19)).toBe(1);  /* Class IN */
      expect(view.getUint8(21)).toBe(0);   /* . */
      expect(view.getUint16(22)).toBe(41); /* Type OPT */
      expect(view.getUint16(24)).toBe(4096);  /* UDP Max Size */
      expect(view.getUint8(26)).toBe(0);  /* Ext. RCODE */
      expect(view.getUint8(27)).toBe(0);  /* EDNS Version */
      expect(view.getUint16(28)).toBe(1<<15);  /* DO Flag */
      expect(view.getUint16(30)).toBe(0);  /* RDATA Length */
      expect(packet.byteLength).toBe(32);
  });
});
