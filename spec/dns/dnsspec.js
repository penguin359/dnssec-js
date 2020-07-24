'use strict';

var rewire = require('rewire');


describe("lib", function() {
  var lib = rewire('../../lib');
  var decodeName = lib.__get__('decodeName');

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
      var compression_offset = i;
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
      var start_offset = i;
      view.setUint8(i++, 2);
      view.setUint8(i++, 'n'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compression_offset); i++;
      var [offset, name] = decodeName(view, start_offset, view);
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
      var compression_offset = i;
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
      var compression_offset2 = i;
      view.setUint8(i++, 2);
      view.setUint8(i++, 'n'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compression_offset); i++;
      var start_offset = i;
      view.setUint8(i++, 5);
      view.setUint8(i++, 'c'.charCodeAt(0));
      view.setUint8(i++, 'h'.charCodeAt(0));
      view.setUint8(i++, 'i'.charCodeAt(0));
      view.setUint8(i++, 'l'.charCodeAt(0));
      view.setUint8(i++, 'd'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compression_offset2); i++;
      var [offset, name] = decodeName(view, start_offset, view);
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
      var compression_offset = i;
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
      var compression_offset2 = i;
      view.setUint8(i++, 2);
      view.setUint8(i++, 'n'.charCodeAt(0));
      view.setUint8(i++, 's'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compression_offset); i++;
      var start_offset = i;
      view.setUint8(i++, 5);
      view.setUint8(i++, 'c'.charCodeAt(0));
      view.setUint8(i++, 'h'.charCodeAt(0));
      view.setUint8(i++, 'i'.charCodeAt(0));
      view.setUint8(i++, 'l'.charCodeAt(0));
      view.setUint8(i++, 'd'.charCodeAt(0));
      view.setUint16(i++, 0xc000 | compression_offset2); i++;
      var [offset, name] = decodeName(view, start_offset, view);
      expect(name).toBe('child.ns.test.com.');
      expect(offset).toBe(i);
  });

  it("should decode a DNS record header with multi-level compression", function() {
      var buf = new ArrayBuffer(64);
      var view = new DataView(buf);

      class Packer {
          constructor(view) {
              this.view = view;
              this.offset = 0;
          }

          packLabel(label) {
              if(label == '.') {
                  label = '';
              }
              this.view.setUint8(this.offset++, label.length);
              for(var c in label) {
                  this.view.setUint8(this.offset++, label.charCodeAt(c));
              }
          }

          packLabels(labels) {
              for(label in labels) {
                  this.packLabel(label);
              }
          }

          packPointer(pointer) {
              this.view.setUint16(this.offset, 0xc000 | pointer);
              this.offset += 2;
          }

          getOffset() {
              return this.offset;
          }
      }

      var packer = new Packer(view);
      packer.packLabel('delete');
      var www_offset = packer.getOffset();
      packer.packLabel('www');
      var test_offset = packer.getOffset();
      packer.packLabel('test');
      packer.packLabel('com');
      packer.packLabel('');
      var ns_offset = packer.getOffset();
      packer.packLabel('ns');
      packer.packPointer(test_offset);
      var start_offset = packer.getOffset();
      packer.packLabel('child');
      packer.packPointer(ns_offset);

      var [offset, name] = decodeName(view, start_offset, view);
      expect(name).toBe('child.ns.test.com.');
      expect(offset).toBe(packer.getOffset());

      var [offset, name] = decodeName(view, www_offset, view);
      expect(name).toBe('www.test.com.');
  });
});
