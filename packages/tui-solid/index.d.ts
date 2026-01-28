import { CliRenderer, type CliRendererConfig } from "@cyberstrike/tui-core";
import { type TestRendererOptions } from "@cyberstrike/tui-core/testing";
import type { JSX } from "./jsx-runtime";
export declare const render: (node: () => JSX.Element, rendererOrConfig?: CliRenderer | CliRendererConfig) => Promise<void>;
export declare const testRender: (node: () => JSX.Element, renderConfig?: TestRendererOptions) => Promise<{
    renderer: import("@cyberstrike/tui-core/testing").TestRenderer;
    mockInput: import("@cyberstrike/tui-core/testing").MockInput;
    mockMouse: import("@cyberstrike/tui-core/testing").MockMouse;
    renderOnce: () => Promise<void>;
    captureCharFrame: () => string;
    captureSpans: () => import("@cyberstrike/tui-core").CapturedFrame;
    resize: (width: number, height: number) => void;
}>;
export * from "./src/reconciler";
export * from "./src/elements";
export * from "./src/types/elements";
export { type JSX };
