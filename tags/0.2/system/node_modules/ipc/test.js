var bypass = require('./bypass')(123457);
bypass.listen('128','1');
bypass.on('data', function(data) {
  console.log(data);
});
