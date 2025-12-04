# How to Contribute:

- Go to `docs/docs/LECTURES`, and go into each unit folder. Each one will have a markdown file that can have lessons added to it
- It must be written in the format `lesson<unit>-<number>.md`
- Go to `docs/mkdocs.yml`, and update the file with your lesson based on the current file structure
- Example where I want to add `lesson4-1.md`:
  - Also note that adding new unit introduction files has to be put in the `docs/docs/` directory itself, but lessons go in the `LECTURES` subdirectory specifically under the related `unit` folder
```
nav:
  - Home: index.md
  - Unit 1:
    - Overview: unit1.md
    - Lesson 1.1: LECTURES/unit1/lesson1-1.md
    - Lesson 1.2: LECTURES/unit1/lesson1-2.md
    - Lesson 1.3: LECTURES/unit1/lesson1-3.md
    - Linux Installation Process: LECTURES/unit1/installation-process.md
  - Unit 2: unit2.md
  - Unit 3: unit3.md
  - Unit 4: unit4.md
    - Lesson 4.1: LECTURES/unit4/lesson1-4.md
  - Terminal: test.md
```

- Once you update, make a PR
- If you have any bugs, make a bug report
- After review, you'll be merged
