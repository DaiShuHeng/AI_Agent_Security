"""Execute the polling implementation with a virtual clock and mocked HTTP."""
import shutil
import subprocess
import unittest
from pathlib import Path


class CollectionFrontendTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js unavailable')
    def test_polling_follows_own_run_and_has_a_deadline(self):
        script = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const fn = src.slice(src.indexOf('async function waitForCollection('), src.indexOf('async function collect('));
let now = 0, calls = 0, status = 'running', fail = false;
const api = async (path, options, timeout) => {
  assert.equal(path, '/api/runs/42');
  assert.ok(timeout > 0 && timeout <= 5000);
  calls++;
  if (fail) throw Error('offline');
  return {run:{id:42,status:now >= 42500 ? status : 'running'}};
};
const poll = new Function('api','window','Date', fn+'return waitForCollection;')(
 api, {setTimeout(fn,ms){now += ms; fn();}}, {now:()=>now});
(async()=>{
  status = 'success';
  assert.equal((await poll(42)).status, 'success');
  assert.equal(now, 42500); assert.ok(calls > 5);
  for (const terminal of ['partial','failed','interrupted']) {
    now = 42500; status = terminal;
    assert.equal((await poll(42)).status, terminal);
  }
  now = 0; calls = 0; status = 'running';
  assert.equal(await poll(42), null);
  assert.equal(now, 120000); assert.ok(calls < 50);
  now = 0; fail = true;
  await assert.rejects(poll(42), /后台采集可能仍在运行/);
})().catch(error=>{console.error(error);process.exitCode=1});
'''
        result = subprocess.run(['node', '-e', script, str(Path(__file__).resolve().parents[1] / 'web/app.js')],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
