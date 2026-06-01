import { defineConfig } from "vite";
import { readFileSync } from "fs";
import { resolve } from "path";
import { specifyJsSeoPlugin } from "@asymmetric-effort/specifyjs/build";

const version = readFileSync(resolve(__dirname, "../VERSION"), "utf-8").trim();

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(version),
  },
  esbuild: {
    jsxFactory: "createElement",
    jsxFragment: "Fragment",
    jsxImportSource: "@asymmetric-effort/specifyjs",
  },
  build: {
    outDir: "dist",
  },
  plugins: [
    specifyJsSeoPlugin({
      siteUrl: "https://leakdetector.asymmetric-effort.com",
      title: "leakdetector",
      description:
        "A zero-dependency Go CLI tool for detecting leaked secrets and sensitive information in git repositories.",
      routes: ["/", "/usage", "/configuration", "/rules", "/output"],
      author: "Asymmetric Effort, LLC",
      license: "MIT",
      repository: "https://github.com/asymmetric-effort/leakdetector",
      robotsRules: ["User-agent: *", "Allow: /"],
      jsonLd: {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        name: "leakdetector",
        applicationCategory: "SecurityApplication",
        operatingSystem: "Linux, macOS, Windows",
        license: "https://opensource.org/licenses/MIT",
        url: "https://leakdetector.asymmetric-effort.com",
        description:
          "A zero-dependency Go CLI tool for detecting leaked secrets and sensitive information in git repositories.",
        author: {
          "@type": "Organization",
          name: "Asymmetric Effort, LLC",
        },
      },
    }),
  ],
});
