#!/bin/bash

echo "=============================================="
echo "🚀 DEPLOYING SECURITY PORTFOLIO TO GITHUB"
echo "=============================================="

# Check if git is configured
if [ -z "$(git config user.name)" ]; then
    echo "⚠️ Git not configured. Setting up..."
    git config user.name "Sean Amon"
    git config user.email "seanamon56@gmail.com"
fi

# Add all files
echo "📁 Adding files to git..."
git add .

# Check status
echo "📊 Git status:"
git status

# Commit
echo "💾 Committing changes..."
git commit -m "Deploy complete security portfolio

Including:
- Advanced Web Security Scanner v2.0
- Automated Pentesting Framework
- CTF Challenge Solver toolkit
- Security Education Platform
- Professional portfolio website
- Complete documentation and setup files

Portfolio demonstrates OSCP preparation progress and
practical security skills for Junior Pentester roles."

echo ""
echo "✅ COMMIT COMPLETE!"
echo ""
echo "=============================================="
echo "NEXT STEPS TO PUBLISH:"
echo "=============================================="
echo ""
echo "1. Create GitHub repository at:"
echo "   https://github.com/new"
echo ""
echo "2. Repository name: 'seanamon' (or your username)"
echo "   Description: 'Security Portfolio | OSCP Candidate | Junior Pentester'"
echo "   Make it PUBLIC"
echo "   DO NOT initialize with README"
echo ""
echo "3. After creating, run these commands:"
echo "   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git"
echo "   git push -u origin main"
echo ""
echo "4. Enable GitHub Pages:"
echo "   Settings → Pages → Source: main → / (root) → Save"
echo ""
echo "5. Your portfolio will be live at:"
echo "   https://YOUR_USERNAME.github.io"
echo ""
echo "=============================================="
echo "Good luck with your job search! 🚀"
echo "=============================================="
