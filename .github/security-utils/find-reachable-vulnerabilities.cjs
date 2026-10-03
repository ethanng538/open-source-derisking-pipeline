const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (err) {
    console.error(`FINDER ERROR: Cannot read ${filePath}`);
    process.exit(1);
  }
}

// Helper to recursively find all files in a package directory
function getAllFiles(dirPath, arrayOfFiles = []) {
  if (!fs.existsSync(dirPath)) return arrayOfFiles;
  const files = fs.readdirSync(dirPath);

  files.forEach(file => {
    const filePath = path.join(dirPath, file);
    if (fs.statSync(filePath).isDirectory()) {
      arrayOfFiles = getAllFiles(filePath, arrayOfFiles);
    } else {
      const relativePath = path.normalize(path.relative(process.cwd(), filePath));
      arrayOfFiles.push(relativePath);
    }
  });
  return arrayOfFiles;
}

function runIndependentEngine() {
  console.log("Running vulnerable package finder...");

  if (!fs.existsSync('npm-audit.json')) {
    console.error("FINDER ERROR: Missing npm-audit.json");
    process.exit(1);
  }

  const auditData = safeReadJson('npm-audit.json');
  const vulnerablePackages = new Set();

  if (auditData.vulnerabilities) {
    for (const [pkgName, details] of Object.entries(auditData.vulnerabilities)) {
      vulnerablePackages.add(pkgName);
    }
  }

  const findings = [];

  // Scans node_modules directly for files belonging to vulnerable packages
  vulnerablePackages.forEach(pkgName => {
    // Handles both regular and scoped packages
    const pkgPath = path.join('node_modules', pkgName);
    if (fs.existsSync(pkgPath)) {
      const allPkgFiles = getAllFiles(pkgPath);

      allPkgFiles.forEach(filePath => {
        findings.push({
          filePath: filePath,
          status: "PENDING_EVALUATION",
          meta: { package: pkgName }
        });
      });
    }
  });

  const outputPayload = {
    generatedAt: new Date().toISOString(),
    findings: findings
  };

  fs.writeFileSync('reachability-results.json', JSON.stringify(outputPayload, null, 2), 'utf8');
  console.log(`✅ Results generated with ${findings.length} files with vulnerable dependencies.`);
}

runIndependentEngine();