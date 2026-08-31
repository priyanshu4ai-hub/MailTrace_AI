# React + Tailwind CSS Skill

A skill for AI assistants (e.g. Claude) that helps **install and configure Tailwind CSS** in React projects and **revamp components** with utility-first styling, semantic design tokens, and common UI patterns.

---

## What’s in this skill

| Topic | What it covers |
|-------|----------------|
| **Setup** | Installing Tailwind, PostCSS, and Autoprefixer; wiring into CRA, Vite, Next.js, Remix, or plain React SPAs |
| **Installation order** | Correct sequence: React + bundler → Tailwind core → config → entry CSS → optional UI libraries |
| **Dependency management** | What to add as devDependencies, when to add Headless UI / Radix / Tailwind UI, and peer dependency notes |
| **Semantic tokens** | Designing `tailwind.config` with purpose-based colors (e.g. `bg.canvas`, `text.secondary`, `border.focus`), radii, shadows, and dark mode |
| **Component revamp** | Workflow to move from ad-hoc CSS to Tailwind: audit → design with utilities → refactor incrementally → extract shared components |
| **UI recipes** | Ready-to-adapt patterns for **forms**, **data tables**, **navigation** (top bar + sidebar), and **modals**, with accessibility guidance |
| **Troubleshooting** | Common issues (classes not applying, production purge, conflicts with Bootstrap) and how to fix them |

The skill is **framework-aware**: it infers CRA vs Vite vs Next.js from your project and tailors commands and config paths accordingly.

---

## How to use this skill

1. **Install or enable the skill** in your AI/agent environment (e.g. Cursor, Claude Code, or your skill runner) so the assistant can load it when relevant.
2. **Ask in natural language.** The skill is designed to trigger when you say things like:
   - “Set up Tailwind in this React project”
   - “Add Tailwind and configure it for Vite”
   - “Revamp this form/table/nav with Tailwind”
   - “Design semantic color tokens in tailwind.config”
   - “Help me with a modal / data table / navigation layout using Tailwind”
3. **Share context when helpful.** Point to specific files (e.g. `tailwind.config.js`, a component, or `package.json`) so the assistant can give exact edits and follow your stack.

---

## What you get when using it

- **Step-by-step setup** for your detected React + build tool (CRA, Vite, Next.js, etc.).
- **Copy-pastable config** for semantic theme tokens (colors, spacing, radii, shadows) and optional dark mode.
- **Component-level guidance** with before/after style examples and reusable patterns for forms, tables, nav, and modals.
- **Clear installation order** and dependency notes so you don’t break the build or mix incompatible versions.
- **Debugging tips** for “Tailwind classes not working,” production CSS missing, and conflicts with other CSS.

---

## Skill contents (file layout)

```
react-tailwind/
├── README.md   ← You are here (usage and overview)
└── SKILL.md    ← Full instructions for the AI (workflows, recipes, config examples)
```

`SKILL.md` is the file the AI loads when the skill is activated. This README is for humans: quick overview and how to use the skill in your workflow.

---

## Supported setups

- **Create React App** (react-scripts)
- **Vite** (React)
- **Next.js** (App Router and Pages Router)
- **Remix**
- **Generic React SPA** (webpack or similar)

If you use another React-based framework, the skill can still be used; the assistant may default to Vite-like instructions and explain how to adapt.

---

## Quick “when to use” checklist

Use this skill when you want to:

- Install and configure Tailwind in a React app.
- Choose and install Tailwind-related dependencies in the right order.
- Define or refactor a semantic design token system in `tailwind.config`.
- Migrate existing React components from plain CSS to Tailwind.
- Get concrete UI recipes for forms, data tables, navigation, or modals.
- Fix Tailwind not applying, production CSS issues, or conflicts with other CSS.

If you need Tailwind for non-React (e.g. Vue, Svelte, plain HTML), this skill is React-focused; you may still reuse the token and recipe ideas and adapt the setup steps for your stack.
