var rewire = require('rewire');


describe("lib", function() {
  var lib = rewire('../../lib');

    /*
  beforeEach(function() {
    player = new Player();
    song = new Song();
  });

*/
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
      console.log(lib);
      var decode_name = lib.__get__('decode_name');
      var [offset, name] = decode_name(view, 0, null);
      expect(name).toBe('com.');
  });
    /*

  describe("when song has been paused", function() {
    beforeEach(function() {
      player.play(song);
      player.pause();
    });

    it("should indicate that the song is currently paused", function() {
      expect(player.isPlaying).toBeFalsy();

      // demonstrates use of 'not' with a custom matcher
      expect(player).not.toBePlaying(song);
    });

    it("should be possible to resume", function() {
      player.resume();
      expect(player.isPlaying).toBeTruthy();
      expect(player.currentlyPlayingSong).toEqual(song);
    });
  });

  // demonstrates use of spies to intercept and test method calls
  it("tells the current song if the user has made it a favorite", function() {
    spyOn(song, 'persistFavoriteStatus');

    player.play(song);
    player.makeFavorite();

    expect(song.persistFavoriteStatus).toHaveBeenCalledWith(true);
  });

  //demonstrates use of expected exceptions
  describe("#resume", function() {
    it("should throw an exception if song is already playing", function() {
      player.play(song);

      expect(function() {
        player.resume();
      }).toThrowError("song is already playing");
    });
  });
  */
});
