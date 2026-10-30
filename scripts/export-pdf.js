const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const htmlFile = process.argv[2] || path.join(__dirname, '..', 'public', 'platform-audit-report.html');
const pdfFile = process.argv[3] || path.join(__dirname, '..', 'public', 'test.pdf');
const userDir = path.join(os.tmpdir(), 'chrome_pdf_' + Date.now());

const chromePaths = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
];

let browserPath = chromePaths.find(p => fs.existsSync(p));
if (!browserPath) {
  console.error('No suitable Chrome or Edge browser executable found.');
  process.exit(1);
}

const fileUrl = htmlFile.startsWith('http') ? htmlFile : `file://${path.resolve(htmlFile).replace(/\\/g, '/')}`;

console.log(`Rendering PDF from: ${fileUrl}`);
console.log(`Using Browser: ${browserPath}`);
console.log(`Output PDF: ${pdfFile}`);

try {
  const cmd = `"${browserPath}" --headless=new --user-data-dir="${userDir}" --disable-gpu --no-pdf-header-footer --print-to-pdf="${pdfFile}" "${fileUrl}"`;
  execSync(cmd, { stdio: 'inherit', timeout: 30000 });
  if (fs.existsSync(pdfFile)) {
    console.log(`[SUCCESS] PDF created successfully (${fs.statSync(pdfFile).size} bytes).`);
  } else {
    console.error('[FAILURE] PDF file was not created.');
  }
} catch (err) {
  console.error('[ERROR] Failed generating PDF:', err.message);
} finally {
  try {
    fs.rmSync(userDir, { recursive: true, force: true });
  } catch {}
}
