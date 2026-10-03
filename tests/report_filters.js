// Run the report's actual script against a small DOM stub, without a browser.
function verifyFilters(script) {
  function element(text, dataset) {
    return {value: '', textContent: text || '', dataset: dataset || {}, hidden: false,
      open: false, addEventListener: function() {}};
  }
  const controls = {};
  ['search', 'severity', 'status', 'visible', 'map-search', 'map-category', 'map-inputs'].forEach(function(id) {
    controls['#' + id] = element();
  });
  const findings = [element('a.py SQL', {severity:'high', status:'new'}),
    element('b.ts HTML', {severity:'medium', status:'existing'})];
  const rows = [element('a.py request', {category:'input'}), element('b.ts query', {category:'database query'})];
  const document = {querySelector: function(id) { return controls[id]; },
    querySelectorAll: function(selector) { return selector === '.finding' ? findings : rows; }};
  function assert(condition, message) { if (!condition) throw new Error(message); }
  const checks = `
    assert(controls['#visible'].textContent==='2 findings shown', 'initial count');
    controls['#severity'].value='high'; filter();
    assert(!findings[0].hidden && findings[1].hidden, 'severity filter');
    controls['#status'].value='existing'; filter();
    assert(findings.every(function(f){return f.hidden;}), 'combined filters');
    controls['#severity'].value=''; controls['#status'].value='';
    controls['#search'].value='B.TS'; filter();
    assert(findings[0].hidden && !findings[1].hidden, 'case-insensitive search');
    mapFilter(); assert(!controls['#map-inputs'].open, 'inputs collapsed initially');
    controls['#map-category'].value='input'; mapFilter();
    assert(controls['#map-inputs'].open && !rows[0].hidden && rows[1].hidden, 'input category');
    controls['#map-category'].value=''; controls['#map-search'].value='request'; mapFilter();
    assert(controls['#map-inputs'].open && !rows[0].hidden && rows[1].hidden, 'search opens inputs');
    controls['#map-search'].value=''; mapFilter();
    assert(!controls['#map-inputs'].open && !rows[1].hidden, 'reset');
  `;
  new Function('document', 'controls', 'findings', 'rows', 'assert', script + '\n' + checks)(document, controls, findings, rows, assert);
}
// Node is optional locally; CI runs this with the hosted runner's Node runtime.
if (typeof require !== 'undefined') {
  const childProcess = require('child_process');
  const script = childProcess.execFileSync('python3', ['-c', 'from appsec_assistant.reports import SCRIPT; print(SCRIPT)'], {encoding:'utf8'});
  verifyFilters(script);
  console.log('Report filter tests passed');
}
