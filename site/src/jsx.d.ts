declare namespace JSX {
  type Element = import("@asymmetric-effort/specifyjs").SpecElement;
  interface IntrinsicElements {
    [elemName: string]: any;
  }
  interface ElementChildrenAttribute {
    children: {};
  }
}
