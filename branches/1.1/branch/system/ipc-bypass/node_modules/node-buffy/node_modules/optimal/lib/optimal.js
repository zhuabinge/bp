(function(module) {
  function parseString(s) {
    var ret = {},
        types = {'o': 'object', 'f': 'function', 'n': 'number', 's': 'string', 'b': 'boolean'};

    var args = s.split(",").map(function(x) {
      var current = x.split(':'),
          type = types[current[0].trim()],
          name = current[1],
          optional = false, defaultValue;

      if (current.length < 2)
        throw new Error("NOTYPEDECLARED");

      if (name[0] === '[' && name[name.length-1] === ']') { // optional parameter
        optional = true;
        name = name.substring(1, name.length-1);

        if (~name.indexOf('=')) {
          defaultValue = JSON.parse(name.substring(name.indexOf('=')+1, name.length));
          name = name.substring(0, name.indexOf('='));
        }
      }

      ret[name] = {
        optional: optional,
        type: type
      };

      if (defaultValue)
        ret[name].defaultValue = defaultValue;
    });

    return ret;
  }


  module.optimal = function(arguments, o) {
    var current, next,
        opts = (typeof o === 'string') ? parseString(o) : o,
        args = Array.prototype.slice.call(arguments),
        keys = Object.keys(opts), 
        ret = {};

    for (var i = 0; i < keys.length; i++) {
      current = keys[i];
      next = keys[i+1];

      if (!opts[current].optional) {
        ret[keys[i]] = args.shift();
      } else {
        if (opts[current].optional && opts[next] && opts[current].type === opts[next].type)
          throw new Error("CANNOT")

        if (typeof args[0] === opts[current].type)
          ret[current] = args.shift();
      }
    }

    keys.forEach(function(x) {
      if (typeof ret[x] === 'undefined' && opts[x].defaultValue)
        ret[x] = opts[x].defaultValue;
    });

    return ret;
  };
})((typeof exports === 'undefined' ? window : exports))