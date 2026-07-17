# Getting This Vault Onto GitHub

## 1. Install gitleaks (secret scanner) — do this first
```bash
# Linux
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
tar -xzf gitleaks_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

## 2. Init the repo locally
```bash
cd security-vault
git init
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

## 3. Do a manual pass before your first commit
Don't trust the hook alone for the first commit — eyeball it yourself:
```bash
gitleaks detect --source . --verbose
```
Fix anything it flags before proceeding.

## 4. First commit
```bash
git add .
git status   # double check nothing from .gitignore snuck in
git commit -m "Initial vault structure: CLAUDE.md, skills scaffold, gitignore"
```

## 5. Create the GitHub repo and push
Via GitHub CLI (if installed):
```bash
gh repo create security-research-vault --public --source=. --remote=origin --push
```
Or manually: create the repo on github.com first (no README/license — you
already have files), then:
```bash
git remote add origin https://github.com/<your-username>/security-research-vault.git
git branch -M main
git push -u origin main
```

## 6. Private repo for the sensitive folders
Repeat steps 2–5 in a separate local folder / repo for:
`Recon Output/`, `CVE Watch/`, `Lab Environment/` — set that repo's
visibility to **Private** in step 5, or don't push it to GitHub at all and
rely on Obsidian Sync instead.

## 7. Ongoing habit
Before every commit: `git status` first, glance at what's staged. The hook
is a safety net, not a replacement for looking at your own diff.
