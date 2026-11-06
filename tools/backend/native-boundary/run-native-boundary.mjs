// Explicit local experiment only. Never run by npm test or imported by runtime.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, copyFile, lstat, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateObservation, validateRecord } from './result-contract.mjs';
const root = path.dirname(fileURLToPath(import.meta.url));
const fail = code => { throw new Error(code); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function run(exe, args, cwd, env, timeout) {
  return new Promise((resolve, reject) => {
    const p = spawn(exe, args, { cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), error, ended = false, grace;
    const finish = code => {
      if (ended) return;
      ended = true; clearTimeout(timer); clearTimeout(grace);
      p.stdout.destroy(); p.stderr.destroy();
      if (error) reject(new Error(error));
      else resolve({ code, stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8') });
    };
    const stop = reason => {
      if (error || ended) return;
      error = reason; p.kill(); // Each owned child tree has a non-inherited kill-on-close Job.
      grace = setTimeout(() => finish(null), 3000);
    };
    const timer = setTimeout(() => stop('OUTER_TIMEOUT'), timeout);
    p.stdout.on('data', b => { if (stdout.length + b.length > 65536) stop('OUTER_OUTPUT_LIMIT'); else stdout = Buffer.concat([stdout, b]); });
    p.stderr.on('data', b => { if (stderr.length + b.length > 65536) stop('OUTER_ERROR_LIMIT'); else stderr = Buffer.concat([stderr, b]); });
    p.once('error', () => { error = 'PROCESS_START_FAILED'; finish(null); });
    p.once('close', finish);
  });
}
let build, result, failure, removed = false;
try {
  if (process.argv.length !== 3 || process.argv[2] !== '--run-synthetic-only') fail('EXPLICIT_FLAG_REQUIRED');
  if (process.platform !== 'win32' || process.arch !== 'x64') fail('WINDOWS_X64_REQUIRED');
  const sys = process.env.SystemRoot;
  if (!sys || !path.isAbsolute(sys)) fail('SYSTEM_ROOT_REQUIRED');
  const framework = path.join(sys, 'Microsoft.NET', 'Framework64', 'v4.0.30319');
  const compiler = path.join(framework, 'csc.exe');
  await access(compiler);
  const temp = await realpath(os.tmpdir());
  build = await mkdtemp(path.join(temp, 'secapp-boundary-'));
  if (path.dirname(build) !== temp || (await lstat(build)).isSymbolicLink()) fail('BUILD_ROOT_REJECTED');
  const sources = {
    harness: path.join(root, 'NativeBoundaryHarness.cs'), fixture: path.join(root, 'Fixture.cs'),
    support: path.join(root, '..', 'native-synthetic', 'SyntheticLaunchHarness.cs'),
    manifest: path.join(root, '..', 'native-synthetic', 'as-invoker.manifest'),
    runner: fileURLToPath(import.meta.url), validator: path.join(root, 'result-contract.mjs'),
  };
  const digests = {};
  for (const [key, source] of Object.entries(sources)) {
    digests[key] = hash(await readFile(source));
    if (key !== 'runner' && key !== 'validator') {
      const destination = path.join(build, path.basename(source));
      await copyFile(source, destination);
      if (hash(await readFile(destination)) !== digests[key]) fail('SOURCE_COPY_MISMATCH');
    }
  }
  const env = { SystemRoot: sys, WINDIR: sys, TEMP: build, TMP: build };
  const common = ['/nologo', '/noconfig', '/nostdlib+', '/platform:x64', '/checked+', '/optimize+', '/debug-', '/warn:4', '/warnaserror+',
    ...['mscorlib.dll', 'System.dll', 'System.Core.dll'].map(n => `/reference:${path.join(framework, n)}`)];
  for (const args of [
    ['/target:library', '/out:SyntheticFixture.dll', 'Fixture.cs'],
    ['/target:exe', '/main:SecApp.NativeBoundary.Entry', '/win32manifest:as-invoker.manifest', '/out:NativeBoundary.exe', 'NativeBoundaryHarness.cs', 'SyntheticLaunchHarness.cs'],
  ]) {
    const compiled = await run(compiler, [...common, ...args], build, env, 20000);
    if (compiled.code !== 0) {
      result = { compile: 'Failed', diagnostics: [...(compiled.stdout + compiled.stderr).matchAll(/\((\d+),(\d+)\): (?:error|warning) (CS\d+)/g)]
        .map(m => ({ line: Number(m[1]), column: Number(m[2]), code: m[3] })) };
      fail('COMPILE_FAILED');
    }
  }
  const executed = await run(path.join(build, 'NativeBoundary.exe'), ['--suite'], build, env, 55000);
  let observed;
  try { observed = JSON.parse(executed.stdout); } catch { fail('INVALID_NATIVE_RECORD'); }
  if (executed.code !== 0 || executed.stderr !== '') {
    result = { compile: 'Passed', native_exit: executed.code,
      completed_ids: Array.isArray(observed.cases) ? observed.cases.filter(r => r.status === 'Observed' && /^NB-00[1-7]$/.test(r.id)).map(r => r.id) : [],
      errors: (Array.isArray(observed.cases) ? observed.cases.filter(r => r.status !== 'Observed') : [observed]).map(r => ({
        code: /^[A-Z_]{1,64}$/.test(r.error) ? r.error : 'INVALID_ERROR',
        native_error: Number.isInteger(r.native_error) ? r.native_error : null,
      })) };
    fail('NATIVE_EXPERIMENT_FAILED');
  }
  result = { stage: 'NATIVE-BOUNDARY-EXPERIMENT1', compile: 'Passed', source_sha256: digests, observation: validateObservation(observed) };
} catch (e) { failure = /^[A-Z0-9_]{1,64}$/.test(e.message) ? e.message : 'CONTROLLED_RUNNER_FAILURE'; }
finally {
  if (build) {
    try {
      const parent = await realpath(os.tmpdir()), resolved = await realpath(build);
      if (path.dirname(resolved) !== parent || resolved !== build || !path.basename(build).startsWith('secapp-boundary-')
          || (await lstat(build)).isSymbolicLink()) fail('CLEANUP_PATH_REJECTED');
      // Exact unique build root only, on one filesystem API; no shell-built deletion.
      await rm(resolved, { recursive: true, force: false, maxRetries: 3, retryDelay: 200 });
      removed = true;
    } catch { failure = 'TEMP_CLEANUP_FAILED'; }
  }
}
const output = { ...(result ?? {}), temporary_files_removed: removed, ...(failure ? { failure } : {}) };
if (!failure) validateRecord(output);
console.log(JSON.stringify(output, null, 2));
process.exitCode = failure ? 1 : 0;
