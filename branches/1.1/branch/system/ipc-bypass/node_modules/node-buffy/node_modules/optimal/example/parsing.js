var optimal = require('../');

var fn = function() {
  return optimal(arguments, 's:exist, n:[optional], f:fn, o:[may={}]');
}

console.log(
  fn('string', function(){})
);

// $ node parsing.js
// { exist: 'string', fn: [Function], may: {} }

console.log(
  fn('string', 1, function(){}, {lol: 1})
);

// $ node parsing.js
// { exist: 'string', optional: 1, fn: [Function], may: { lol: 1 } }