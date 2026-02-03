# @cyberstrike/spinner

A small & opinionated spinner library for terminal UIs built on [Cyberstrike TUI](https://github.com/CyberStrikeus/cyberstrike.io).

## Features

- **Built-in Spinners** - Powered by [cli-spinners](https://github.com/sindresorhus/cli-spinners)
- **Custom Spinners** - Create your own with custom frames and intervals
- **SolidJS Support** - First-class SolidJS integration via @cyberstrike/tui-solid
- **Type-Safe** - Full TypeScript support

## Installation

```bash
bun add @cyberstrike/spinner @cyberstrike/tui-core
```

For SolidJS support:

```bash
bun add @cyberstrike/spinner @cyberstrike/tui-core @cyberstrike/tui-solid solid-js
```

## Usage

### Basic Usage (Core)

```typescript
import { createCliRenderer } from "@cyberstrike/tui-core";
import { SpinnerRenderable } from "@cyberstrike/spinner";

const renderer = await createCliRenderer();

const spinner = new SpinnerRenderable(renderer, {
  name: "dots",
  color: "cyan",
});

renderer.root.add(spinner);
```

### With Text Label

```typescript
import {
  BoxRenderable,
  createCliRenderer,
  TextRenderable,
} from "@cyberstrike/tui-core";
import { SpinnerRenderable } from "@cyberstrike/spinner";

const renderer = await createCliRenderer();

const container = new BoxRenderable(renderer, {
  border: true,
  flexDirection: "row",
  alignItems: "center",
});

const spinner = new SpinnerRenderable(renderer, {
  name: "bouncingBall",
});

const label = new TextRenderable(renderer, {
  content: "Loading...",
  marginLeft: 1,
});

container.add(spinner);
container.add(label);
renderer.root.add(container);
```

### SolidJS Usage

First, import the SolidJS extension:

```tsx
import "@cyberstrike/spinner/solid";
```

Then use the `<spinner>` component in your Cyberstrike TUI SolidJS app:

```tsx
import { render } from "@cyberstrike/tui-solid";
import "@cyberstrike/spinner/solid";

function App() {
  return (
    <box alignItems="center" flexDirection="row">
      <spinner name="bouncingBall" color="cyan" />
      <text marginLeft={1}>Loading...</text>
    </box>
  );
}

render(() => <App />);
```

## API Reference

### SpinnerOptions

| Option            | Type                           | Default         | Description                                  |
| ----------------- | ------------------------------ | --------------- | -------------------------------------------- |
| `name`            | `SpinnerName`                  | `"dots"`        | Name of a built-in spinner from cli-spinners |
| `frames`          | `string[]`                     | -               | Custom animation frames (overrides `name`)   |
| `interval`        | `number`                       | -               | Time between frames in milliseconds          |
| `autoplay`        | `boolean`                      | `true`          | Whether to start playing automatically       |
| `color`           | `ColorInput \| ColorGenerator` | `"white"`       | Foreground color or color generator function |
| `backgroundColor` | `ColorInput`                   | `"transparent"` | Background color                             |

### SpinnerRenderable Methods

#### `start(): void`

Start or resume the spinner animation.

```typescript
spinner.start();
```

#### `stop(): void`

Pause the spinner animation.

```typescript
spinner.stop();
```

### Properties

All options can be updated dynamically via properties:

```typescript
// Change spinner type
spinner.name = "line";

// Update color
spinner.color = "green";

// Or use a color generator
spinner.color = createPulse(["red", "yellow", "green"]);

// Update background color
spinner.backgroundColor = "blue";

// Change frames
spinner.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

// Adjust interval
spinner.interval = 100;
```

## Available Spinners

The library includes 80+ spinners from [cli-spinners](https://github.com/sindresorhus/cli-spinners). Popular choices include:

- `dots` - Simple dots (⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
- `dots2` - Alternative dots
- `dots3` through `dots12` - Various dot styles
- `line` - Rotating line (- \\ | /)
- `pipe` - Simple pipe animation
- `star` - Rotating star
- `arc` - Arc animation
- `circle` - Circle segments
- `squareCorners` - Rotating square corners
- `circleQuarters` - Quarter circles
- `circleHalves` - Half circles
- `bouncingBar` - Bouncing bar
- `bouncingBall` - Bouncing ball
- `arrow` - Arrow animations
- `hamburger` - Hamburger menu animation
- `growVertical` / `growHorizontal` - Growing bars
- `balloon` / `balloon2` - Balloon animations
- `noise` / `bounce` - Various effects
- `boxBounce` - Bouncing box
- `weather` - Weather icons
- `moon` - Moon phases
- `runner` - Running character
- `pong` - Pong animation
- `shark` - Shark animation
- `dqpb` - Letter rotation

See the full list at [cli-spinners](https://github.com/sindresorhus/cli-spinners#readme).

## Custom Spinners

Create your own spinner with custom frames:

```typescript
const spinner = new SpinnerRenderable(renderer, {
  frames: ["◐", "◓", "◑", "◒"],
  interval: 80,
  color: "magenta",
});
```

## Color Options

Colors can be specified in multiple formats:

```typescript
// Named colors
spinner.color = "red";
spinner.color = "cyan";

// RGB values
spinner.color = { r: 255, g: 100, b: 50 };

// Hex colors
spinner.color = "#ff6432";
```

### Dynamic Color Effects

The `color` property also accepts a `ColorGenerator` function for dynamic color effects:

```typescript
import { SpinnerRenderable, type ColorGenerator } from "@cyberstrike/spinner";

// Custom color generator
const customColorGen: ColorGenerator = (
  frameIndex,
  charIndex,
  totalFrames,
  totalChars
) => {
  // Return different colors based on frame/character position
  return frameIndex % 2 === 0 ? "cyan" : "magenta";
};

const spinner = new SpinnerRenderable(renderer, {
  name: "dots",
  color: customColorGen,
});
```

### Built-in Color Generators

#### `createPulse(colors, speed?)`

Creates a pulsing effect that cycles through colors:

```typescript
import { SpinnerRenderable, createPulse } from "@cyberstrike/spinner";

const spinner = new SpinnerRenderable(renderer, {
  name: "dots",
  color: createPulse(["red", "orange", "yellow"], 0.5),
});
```

**Parameters:**

- `colors`: Array of colors to cycle through
- `speed`: Animation speed multiplier (default: 1.0)

#### `createWave(colors)`

Creates a wave pattern that moves across characters:

```typescript
import { SpinnerRenderable, createWave } from "@cyberstrike/spinner";

const spinner = new SpinnerRenderable(renderer, {
  name: "dots",
  color: createWave(["#ff0000", "#00ff00", "#0000ff"]),
});
```

**Parameters:**

- `colors`: Array of colors for the wave gradient

## Examples

Check out the `examples/` directory for complete working examples:

- [`examples/index.ts`](examples/index.ts) - Core example
- [`examples/solid.tsx`](examples/solid.tsx) - SolidJS example

## Peer Dependencies

- `@cyberstrike/tui-core` (required)
- `@cyberstrike/tui-solid` (optional, for SolidJS support)

## Development

```bash
# Install dependencies
bun install

# Build the library
bun run build

# Lint code
bun run lint

# Auto-fix linting issues
bun run lint:fix
```

## License

MIT

## Credits

- Built on [Cyberstrike TUI](https://github.com/CyberStrikeus/cyberstrike.io)
- Spinners from [cli-spinners](https://github.com/sindresorhus/cli-spinners) by Sindre Sorhus

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
