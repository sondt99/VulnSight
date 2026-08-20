'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const appSource = fs.readFileSync(
  path.join(__dirname, '..', 'static', 'app.js'),
  'utf8',
);
const functionStart = appSource.indexOf('function csvCell');
const functionEnd = appSource.indexOf('\n    function doExport', functionStart);
assert.notEqual(functionStart, -1, 'csvCell must exist in app.js');
assert.notEqual(functionEnd, -1, 'csvCell must end before doExport');

const csvCell = Function(
  `'use strict'; ${appSource.slice(functionStart, functionEnd)}; return csvCell;`,
)();

for (const value of ['=2+2', '+CMD', '-1+2', '@SUM(A1:A2)', '  =HYPERLINK("x")']) {
  assert.match(csvCell(value), /'?'/, `dangerous CSV cell was not neutralized: ${value}`);
  const decoded = csvCell(value).replace(/^"|"$/g, '').replace(/""/g, '"');
  assert.equal(decoded[0], "'", `cell must begin with an apostrophe: ${value}`);
}

assert.equal(csvCell('\tformula-like'), "'\tformula-like");
assert.equal(csvCell('ordinary text'), 'ordinary text');
assert.match(appSource, /function apiPost/);
assert.match(appSource, /X-VulnSight-Token/);
assert.match(appSource, /AUTH_REQUIRED/);
assert.equal(csvCell('alpha,beta'), '"alpha,beta"');
assert.equal(csvCell('say "hello"'), '"say ""hello"""');

console.log('frontend CSV security checks passed');
