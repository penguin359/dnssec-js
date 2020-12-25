//const BigInt = require('BigInt');
const BigNumber = require('bignumber.js');

//console.log(BigInt.powMod(BigInt.str2bigInt('4', 10), BigInt.str2bigInt('3', 10), BigInt.str2bigInt('61', 10)).toString());
console.log(new BigNumber('4', 10).pow(new BigNumber('3', 10), new BigNumber('61', 10)).toString());

num = new BigNumber('2', 10);
Array(10).fill().map((_, i) => {
    console.log(num.toString());
    num = num.pow(2);
});
Array(12).fill().map((_, i) => {
    //console.log(num.toString());
    console.log(num);
    num = num.sqrt();
});

console.log(new BigNumber(2).pow(4096).toString())
console.log(new BigNumber(2.3).pow(4096).toString())
console.log(new BigNumber(2.3).pow(4096).toString())
console.log(new BigNumber(2.3).pow(4096).sqrt().toString())
console.log(new BigNumber(2.3).pow(4096).sqrt().sqrt().toString())
