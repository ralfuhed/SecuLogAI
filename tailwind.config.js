// Tailwind used to run in the browser from its CDN, which needed a third-party
// script and 'unsafe-inline' styles in the CSP. It is now built ahead of time
// into web/static/tailwind.css; run `npm run build:css` after changing classes
// in a template. CI fails if the committed file is out of date.
module.exports = {
  content: ['./web/templates/**/*.html', './web/**/*.py'],
  theme: {
    extend: {
      fontFamily: {
        display: ['Barlow Condensed', 'sans-serif'],
        mono:    ['JetBrains Mono', 'monospace'],
        sans:    ['Barlow', 'sans-serif'],
      },
      colors: {
        ops: {
          bg:     '#050b14',
          card:   '#0a1628',
          border: '#152238',
          cyan:   '#22d3ee',
          green:  '#4ade80',
          amber:  '#fbbf24',
          red:    '#f43f5e',
          purple: '#a78bfa',
          text:   '#e2e8f0',
          muted:  '#64748b',
          dim:    '#1e2d42',
        },
      },
    },
  },
};
