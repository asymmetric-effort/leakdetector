import { test, expect } from "@playwright/test";

const BASE_URL = process.env.PDV_URL || "https://leakdetector.asymmetric-effort.com";

test.describe("leakdetector site PDV", () => {
  test("home page loads with logo, title, and teal theme", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".hero");

    // Logo is present and reasonably sized (not full screen).
    const logo = page.locator(".hero-logo");
    await expect(logo).toBeVisible();
    const box = await logo.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBeLessThanOrEqual(120);
    expect(box!.height).toBeLessThanOrEqual(120);

    // Title is present.
    const h1 = page.locator(".hero h1");
    await expect(h1).toContainText("leakdetector");

    // Badges are present.
    const badges = page.locator(".badge");
    expect(await badges.count()).toBeGreaterThanOrEqual(3);

    // Teal primary color applied (not black and white).
    const primaryColor = await page.evaluate(() => {
      return getComputedStyle(document.documentElement)
        .getPropertyValue("--primary")
        .trim();
    });
    expect(primaryColor).toBe("#5eead4");

    // Background is dark.
    const bgColor = await page.evaluate(() => {
      return getComputedStyle(document.documentElement)
        .getPropertyValue("--bg")
        .trim();
    });
    expect(bgColor).toBe("#0d1117");
  });

  test("favicon is set", async ({ page }) => {
    await page.goto(BASE_URL);
    const favicon = page.locator('link[rel="icon"]');
    await expect(favicon).toHaveAttribute("href", "/logo.png");
  });

  test("navigation links work", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".nav");

    const navLinks = page.locator(".nav-links a");
    const count = await navLinks.count();
    expect(count).toBeGreaterThanOrEqual(4);

    // Click Usage link.
    await page.click('.nav-links a[href="#/usage"]');
    await page.waitForSelector(".section h2");
    await expect(page.locator("h1")).toContainText("Usage");

    // Click Configuration link.
    await page.click('.nav-links a[href="#/configuration"]');
    await page.waitForSelector(".section h2");
    await expect(page.locator("h1")).toContainText("Configuration");

    // Click Rules link.
    await page.click('.nav-links a[href="#/rules"]');
    await page.waitForSelector(".section h2");
    await expect(page.locator("h1")).toContainText("Rules");

    // Click Output link.
    await page.click('.nav-links a[href="#/output"]');
    await page.waitForSelector(".section h2");
    await expect(page.locator("h1")).toContainText("Output");

    // Click Home link.
    await page.click('.nav-brand');
    await page.waitForSelector(".hero");
    await expect(page.locator(".hero h1")).toContainText("leakdetector");
  });

  test("nav brand has logo image", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".nav-brand img");
    const navLogo = page.locator(".nav-brand img");
    await expect(navLogo).toBeVisible();
    const box = await navLogo.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBeLessThanOrEqual(32);
    expect(box!.height).toBeLessThanOrEqual(32);
  });

  test("footer contains version and copyright", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".footer");
    const footer = page.locator(".footer");
    await expect(footer).toContainText("MIT License");
    await expect(footer).toContainText("Asymmetric Effort");
    await expect(footer).toContainText("v");
  });

  test("code blocks have proper styling", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector("pre");
    const pre = page.locator("pre").first();
    const bg = await pre.evaluate((el) => getComputedStyle(el).backgroundColor);
    // Should have dark code background, not white.
    expect(bg).not.toBe("rgb(255, 255, 255)");
  });

  test("feature cards are visible on home page", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".feature-card");
    const cards = page.locator(".feature-card");
    expect(await cards.count()).toBeGreaterThanOrEqual(4);
  });

  test("SEO meta tags are present", async ({ page }) => {
    await page.goto(BASE_URL);
    const description = page.locator('meta[name="description"]');
    await expect(description).toHaveAttribute(
      "content",
      /zero-dependency.*Go.*CLI.*secrets/i
    );
  });

  test("robots.txt is accessible", async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/robots.txt`);
    expect(response?.status()).toBe(200);
    const text = await response?.text();
    expect(text).toContain("Sitemap:");
  });

  test("sitemap.xml is accessible", async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/sitemap.xml`);
    expect(response?.status()).toBe(200);
    const text = await response?.text();
    expect(text).toContain("<urlset");
    expect(text).toContain("leakdetector.asymmetric-effort.com");
  });
});
