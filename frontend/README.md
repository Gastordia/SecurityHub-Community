## What is this?

The React frontend for SecurityHub — a TypeScript SPA built with Vite. It talks to the Django API and doesn't need any server-side rendering; in production it's served as static files by Nginx.

## Installation

```bash
npm install
```

Copy `env.example` to `.env` and set `VITE_APP_API_URL` to point at your backend.

## Available Scripts

`npm start` — runs the Vite dev server at [http://localhost:5173](http://localhost:5173) with hot module reload.

`npm test` — runs the test suite once with Vitest (`npm run test:watch` for watch mode, `npm run test:coverage` for a coverage report). Tests live under `tests/`; `tests/setup.ts` wires up `@testing-library/jest-dom` and a few DOM API mocks (`matchMedia`, `IntersectionObserver`, `ResizeObserver`) that components rely on but jsdom doesn't implement.

`npm run build` — type-checks with `tsc`, then builds the production bundle to `dist/` (not `build/` — that's a Create React App convention, this project uses Vite).
