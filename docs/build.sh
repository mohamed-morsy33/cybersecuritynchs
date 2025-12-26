#!/bin/bash
source ~/Python_Envs/bin/activate # Note for contributors: change this to YOUR venv if you have one
python create_serach_md.py
mkdocs build
mkdocs gh-deploy
git add .
git commit -m "Deploy with build"
git push
