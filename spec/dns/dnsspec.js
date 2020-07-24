'use strict';

var rewire = require('rewire');

class Packer {
    constructor(view) {
        this.view = view;
        this.offset = 0;
    }

    packUint8(value) {
        this.view.setUint8(this.offset++, value);
    }

    packUint16(value) {
        this.view.setUint16(this.offset, value);
        this.offset += 2;
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

  xit("should decode a DNS record with multi-level compression", function() {
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
      packer.packUint16(1);  /* RR Type A */
      packer.packUint16(1);  /* RR Class IN */
      packer.packUint16(480);  /* RR TTL */
      packer.packUint8(4);  /* RR Data length */
      packer.packUint8(1);  /* RR Data */
      packer.packUint8(2);  /* RR Data */
      packer.packUint8(3);  /* RR Data */
      packer.packUint8(4);  /* RR Data */

      var [offset, name, type, class_, ttl, rdata] = decodeRecord(view, startOffset);
      expect(offset).toBe(packer.getOffset());
      expect(name).toBe('child.ns.test.com.');
      expect(type).toBe('A');
      expect(class_).toBe('IN');
      expect(ttl).toBe(480);
      expect(rdata).toBe('1.2.3.4');
  });
});
