const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (err) {
    console.error(`FINDER ERROR: Cannot read ${filePath}`);
    process.exit(1);
  }
}

function runIndependentEngine() {
  console.log("Running vulnerable dependency finder...");

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

  // Maps each vulnerable package to its exact module entry file
  vulnerablePackages.forEach(pkgName => {
    let resolvedPath = null;

    try {
      // Resolves the primary entry file used when importing the package
      const entryPoint = require.resolve(pkgName, { paths: [process.cwd()] });
      resolvedPath = path.normalize(path.relative(process.cwd(), entryPoint));
    } catch (e) {
      // Fall back to the package.json if it is a binary wrapper or unresolvable layout
      const packageJsonPath = path.join('node_modules', pkgName, 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        resolvedPath = path.normalize(packageJsonPath);
      }
    }

    if (resolvedPath) {
      findings.push({
        filePath: resolvedPath,
        status: "PENDING_EVALUATION",
        meta: { package: pkgName }
      });
    }
  });

  const outputPayload = {
    generatedAt: new Date().toISOString(),
    findings: findings
  };

  fs.writeFileSync('vulnerable-dependencies.json', JSON.stringify(outputPayload, null, 2), 'utf8');
  console.log(`✅ Results generated with ${findings.length} target modules to evaluate.`);
}

runIndependentEngine();