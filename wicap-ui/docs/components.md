# WICAP UI Component Library

> Glass Cockpit Design System v1.0

## Design Tokens

```css
/* Glass Effects */
--glass-bg: rgba(22, 27, 34, 0.75);
--glass-blur: blur(12px);
--glass-border: 1px solid rgba(255, 255, 255, 0.08);

/* Neon Glows */
--neon-blue: 0 0 20px rgba(88, 166, 255, 0.4);
--neon-green: 0 0 20px rgba(63, 185, 80, 0.4);
--neon-red: 0 0 20px rgba(248, 81, 73, 0.4);
```

---

## Components

### GlassCard

A premium container with blur and translucency effects.

```html
<div class="glass-card">
    <h2>Title</h2>
    <p>Content</p>
</div>

<!-- With glow variants -->
<div class="glass-card glow-blue">...</div>
<div class="glass-card glow-green">...</div>
<div class="glass-card glow-red">...</div>
```

---

### StatusBadge

Live status indicator with pulse animation.

```html
<span class="status-badge status-badge--live">
    <span class="pulse-dot"></span>
    Live
</span>

<span class="status-badge status-badge--dead">
    <span class="pulse-dot"></span>
    Offline
</span>

<span class="status-badge status-badge--cracking">
    <span class="pulse-dot"></span>
    Cracking
</span>

<span class="status-badge status-badge--cracked">
    <span class="pulse-dot"></span>
    Cracked
</span>
```

| Variant | Use Case |
|---------|----------|
| `--live` | Active/running systems |
| `--dead` | Offline/stopped |
| `--cracking` | In-progress operations |
| `--cracked` | Successfully completed |

---

### MetricSparkline

Mini-chart for showing metric trends inline.

```html
<div class="metric-sparkline">
    <div class="metric-sparkline__header">
        <span class="metric-sparkline__label">Events/min</span>
        <span class="metric-sparkline__trend metric-sparkline__trend--up">
            <i class="fas fa-arrow-up"></i> 12%
        </span>
    </div>
    <span class="metric-sparkline__value">1,234</span>
    <div class="metric-sparkline__chart">
        <div class="metric-sparkline__bar" style="height: 60%;"></div>
        <div class="metric-sparkline__bar" style="height: 80%;"></div>
        <div class="metric-sparkline__bar" style="height: 40%;"></div>
        <!-- ... more bars ... -->
    </div>
</div>
```

---

## Usage Guidelines

1. **Prefer `.glass-card`** over `.card` for premium sections
2. **Use glow variants** sparingly to highlight important states
3. **StatusBadge pulse** draws attention - don't overuse on one page
4. **Sparklines** work best at 8-12 bars width
