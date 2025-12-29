const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const pdfPath = path.join(__dirname, 'toxicframe.pdf');
const marpBin = path.join(__dirname, 'node_modules', '.bin', 'marp');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForStableFile(filePath, { timeoutMs = 120000, stableMs = 500 } = {}) {
  const start = Date.now();

  let lastSize = -1;
  let stableFor = 0;

  while (Date.now() - start < timeoutMs) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 0 && stat.size === lastSize) {
        stableFor += 100;
        if (stableFor >= stableMs) return;
      } else {
        stableFor = 0;
        lastSize = stat.size;
      }
    } catch {
      // File not there yet.
      stableFor = 0;
      lastSize = -1;
    }

    await sleep(100);
  }

  throw new Error(`export_pdf.js: Timed out waiting for ${filePath}`);
}

async function main() {
  // Remove old output to make detection reliable.
  try {
    fs.unlinkSync(pdfPath);
  } catch {
    // ignore
  }

  const args = [
    'toxicframe.md',
    '--pdf',
    '--html',
    '--theme-set',
    'theme.css',
    '--theme',
    'toxicframe',
    '--browser',
    'chrome',
    '--browser-timeout',
    '120',
    '--allow-local-files',
    '--output',
    'toxicframe.pdf'
  ];

  const child = spawn(marpBin, args, {
    cwd: __dirname,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: process.env
  });

  let sawSuccessLine = false;

  child.stdout.on('data', (buf) => {
    const s = buf.toString('utf8');
    process.stdout.write(s);
    if (s.includes('=> toxicframe.pdf')) sawSuccessLine = true;
  });

  child.stderr.on('data', (buf) => {
    const s = buf.toString('utf8');
    process.stderr.write(s);
    if (s.includes('=> toxicframe.pdf')) sawSuccessLine = true;
  });

  const exitPromise = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', (code, signal) => resolve({ code, signal }));
  });

  // Wait until Marp says it wrote the PDF, then ensure the file is stable.
  const start = Date.now();
  while (!sawSuccessLine) {
    if (Date.now() - start > 120000) {
      child.kill('SIGTERM');
      throw new Error('export_pdf.js: Timed out waiting for Marp output');
    }
    await sleep(50);
  }

  await waitForStableFile(pdfPath, { timeoutMs: 120000, stableMs: 800 });

  // Workaround: marp-cli (Node v25) sometimes never exits even after finishing.
  child.kill('SIGTERM');
  await Promise.race([exitPromise, sleep(1500)]);

  if (child.exitCode == null) {
    child.kill('SIGKILL');
    await Promise.race([exitPromise, sleep(1500)]);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
