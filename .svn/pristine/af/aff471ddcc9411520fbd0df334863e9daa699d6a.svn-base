var assert = require('assert'),
    optimal = require('../');

describe('Optimal', function() {
  it('Should parse optional arguments correctly with object', function() {
    var args = optimal(['test', 1337, function() {}, {'test': 7887}, 90], {
      string: {
        type: 'string'
      },

      number: {
        type: 'number',
        optional: true
      },

      nonexistent: {
        type: 'object',
        optional: true
      },

      fn: {
        type: 'function'
      },

      existent: {
        type: 'object',
        optional: true
      },

      existentdefault: {
        type: 'number',
        optional: true,
        defaultValue: 1
      },

      nonexistentdefault: {
        type: 'string',
        optional: true,
        defaultValue: 'test'
      }
    });

    args.string.should.be.a('string');
    args.number.should.be.a('number');
    assert.strictEqual(args.nonexistent, undefined);
    args.fn.should.be.a('function');
    args.existent.should.be.a('object');
    args.existentdefault.should.be.equal(90);
    args.nonexistentdefault.should.be.equal('test');
  });

  it('Should parse optional arguments correctly with string', function() {
    var args = optimal(['test', 1337, function() {}, {'test': 7887}, 90], 's:string, n:[number], o:[nonexistent], f:fn, o:[existent], n:[existentdefault=90], s:[nonexistentdefault="test"]');

    args.string.should.be.a('string');
    args.number.should.be.a('number');
    assert.strictEqual(args.nonexistent, undefined);
    args.fn.should.be.a('function');
    args.existent.should.be.a('object');
    args.existentdefault.should.be.equal(90);
    args.nonexistentdefault.should.be.equal('test');
  });
});