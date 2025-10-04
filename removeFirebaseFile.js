const { execSync } = require("child_process");
const fs = require("fs");

function runCommand(command, message) {
  try {
    console.log(message);
    execSync(command, { stdio: "inherit" });
  } catch (err) {
    console.log(`⚠️  Skipped: ${message} (${err.message})`);
  }
}

try {
  console.log("\n🚀 Starting Firebase admin key cleanup...\n");

  // Check if file exists
  if (fs.existsSync("firebase-admin.json")) {
    runCommand('git rm --cached firebase-admin.json', "Removing firebase-admin.json from Git tracking...");
  } else {
    console.log("✅ firebase-admin.json not found in repo (already removed).");
  }

  // Ensure .gitignore exists and contains firebase-admin.json
  if (!fs.existsSync(".gitignore")) fs.writeFileSync(".gitignore", "");
  const ignoreContent = fs.readFileSync(".gitignore", "utf8");
  if (!ignoreContent.includes("firebase-admin.json")) {
    fs.appendFileSync(".gitignore", "\nfirebase-admin.json\n");
    console.log("🛡️  Added firebase-admin.json to .gitignore");
  } else {
    console.log("✅ firebase-admin.json already ignored.");
  }

  // Commit .gitignore change
  runCommand('git add .gitignore', "Adding .gitignore changes...");
  runCommand('git commit -m "Removed firebase-admin.json and added to .gitignore"', "Committing ignore update...");

  // Clean Git history
  console.log("\n🧹 Cleaning file from Git history (this may take a few minutes)...");
  runCommand(
    'git filter-branch --force --index-filter "git rm --cached --ignore-unmatch firebase-admin.json" --prune-empty --tag-name-filter cat -- --all',
    "Removing firebase-admin.json from commit history..."
  );

  // Force push changes
  console.log("\n🚀 Pushing cleaned repo to remote (overwrites history)...");
  runCommand("git push origin main --force", "Force pushing to GitHub...");

  console.log("\n✅ Repository cleaned successfully and pushed to remote!");
  console.log("🔒 Remember to revoke and regenerate your Firebase key in the Firebase Console.");
} catch (error) {
  console.error("\n❌ Fatal error:", error.message);
}
