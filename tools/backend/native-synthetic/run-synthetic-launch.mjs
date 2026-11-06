// Explicit lab entrypoint; never imported by the product or by npm test.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, copyFile, lstat, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateSuccessfulResult } from './result-contract.mjs';

const sourceRoot = path.dirname(fileURLToPath(import.meta.url));
const fail = code => { throw new Error(code); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function boundedProcess(executable, args, cwd, environment, milliseconds) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd, env: environment, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), stopped = false, finished = false;
    let failure = null, grace;
    const finish = (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer); clearTimeout(grace);
      child.stdout.destroy(); child.stderr.destroy();
      if (failure) reject(new Error(failure));
      else resolve({ code, stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8') });
    };
    const stop = code => {
      if (stopped) return;
      stopped = true; failure = code;
      // The harness owns kill-on-close Jobs; killing it closes non-inherited Job handles.
      child.kill();
      grace = setTimeout(() => finish(null), 3000);
    };
    const timer = setTimeout(() => stop('OUTER_DEADLINE'), milliseconds);
    child.stdout.on('data', chunk => {
      if (stdout.length + chunk.length > 65536) stop('OUTER_STDOUT_LIMIT');
      else stdout = Buffer.concat([stdout, chunk]);
    });
    child.stderr.on('data', chunk => {
      if (stderr.length + chunk.length > 65536) stop('OUTER_STDERR_LIMIT');
      else stderr = Buffer.concat([stderr, chunk]);
    });
    child.once('error', () => { failure = 'OUTER_PROCESS_ERROR'; finish(null); });
    child.once('close', finish);
  });
}

let build;
let result;
let failure;
try {
  if (process.argv.length !== 3 || process.argv[2] !== '--run-synthetic-only') fail('EXPLICIT_SYNTHETIC_FLAG_REQUIRED');
  if (process.platform !== 'win32' || process.arch !== 'x64') fail('WINDOWS_X64_REQUIRED');
  const systemRoot = process.env.SystemRoot;
  if (!systemRoot || !path.isAbsolute(systemRoot)) fail('SYSTEM_ROOT_REQUIRED');
  const framework = path.join(systemRoot, 'Microsoft.NET', 'Framework64', 'v4.0.30319');
  const compiler = path.join(framework, 'csc.exe');
  await access(compiler); // Existing local compiler only: no discovery downloads or installation.
  const tempRoot = await realpath(os.tmpdir());
  build = await mkdtemp(path.join(tempRoot, 'secapp-native-synthetic-'));
  if (path.dirname(build) !== tempRoot || (await lstat(build)).isSymbolicLink()) fail('TEMP_ROOT_INVALID');
  const source = path.join(build, 'SyntheticLaunchHarness.cs');
  const manifest = path.join(build, 'as-invoker.manifest');
  const image = path.join(build, 'SecAppSyntheticLaunch.exe');
  await copyFile(path.join(sourceRoot, 'SyntheticLaunchHarness.cs'), source);
  await copyFile(path.join(sourceRoot, 'as-invoker.manifest'), manifest);
  const environment = { SystemRoot: systemRoot, WINDIR: systemRoot, TEMP: build, TMP: build };
  const compiled = await boundedProcess(compiler, [
    '/nologo', '/noconfig', '/nostdlib+', '/target:exe', '/platform:x64', '/checked+',
    '/optimize+', '/debug-', '/warn:4', '/warnaserror+', `/out:${image}`, `/win32manifest:${manifest}`,
    ...['mscorlib.dll', 'System.dll', 'System.Core.dll'].map(name => `/reference:${path.join(framework, name)}`), source,
  ], build, environment, 20000);
  if (compiled.code !== 0) {
    // Only normalized compiler location/code, never raw compiler stdout/stderr or absolute paths.
    const diagnostics = [...(compiled.stdout + compiled.stderr).matchAll(/\((\d+),(\d+)\): (?:error|warning) (CS\d+)/g)]
      .map(match => ({ line: Number(match[1]), column: Number(match[2]), code: match[3] }));
    result = { stage: 'BACKEND-NATIVE-SYNTHETIC1', compile: 'Failed', diagnostics };
    fail('COMPILE_FAILED');
  }
  const sourceSha256 = hash(await readFile(source));
  const manifestSha256 = hash(await readFile(manifest));
  const executed = await boundedProcess(image, ['--suite'], build, environment, 45000);
  const parsed = JSON.parse(executed.stdout);
  if (executed.code !== 0 || executed.stderr !== '') {
    // Native output has only a closed vocabulary; do not echo arbitrary process data on failure.
    result = { stage: 'BACKEND-NATIVE-SYNTHETIC1', compile: 'Passed', source_sha256: sourceSha256,
      manifest_sha256: manifestSha256, native_exit: executed.code,
      failed_cases: Array.isArray(parsed.cases) ? parsed.cases.filter(row => row.passed === false)
        .map(row => ({ id: /^SN-\d{3}$/.test(row.id) ? row.id : 'Invalid',
          error: /^[A-Z_]{1,64}$/.test(row.error) ? row.error : 'Invalid',
          native_error: Number.isSafeInteger(row.native_error) ? row.native_error : null })) : [],
      error: /^[A-Z_]{1,64}$/.test(parsed.error) ? parsed.error : 'NATIVE_CASE_FAILURE' };
    fail('NATIVE_FAILED');
  }
  result = { compile: 'Passed', source_sha256: sourceSha256, manifest_sha256: manifestSha256,
    observation: validateSuccessfulResult(parsed) };
} catch (error) {
  failure = /^[A-Z0-9_]{1,64}$/.test(error.message) ? error.message : 'CONTROLLED_RUNNER_FAILURE';
} finally {
  if (build) {
    try {
      // Delete only the exact unique directory we created, never a caller-supplied path.
      const root = await realpath(os.tmpdir());
      const resolved = await realpath(build);
      if (path.dirname(resolved) !== root || resolved !== build
          || !path.basename(resolved).startsWith('secapp-native-synthetic-')
          || (await lstat(build)).isSymbolicLink()) fail('TEMP_CLEANUP_PATH_REJECTED');
      await rm(resolved, { recursive: true, force: false, maxRetries: 3, retryDelay: 200 });
    } catch { failure = 'TEMP_CLEANUP_FAILED'; }
  }
}
console.log(JSON.stringify({ ...(result ?? {}), temporary_files_removed: !!build && failure !== 'TEMP_CLEANUP_FAILED',
  ...(failure ? { failure } : {}) }, null, 2));
process.exitCode = failure ? 1 : 0;
