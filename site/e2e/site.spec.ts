import { test, expect } from "@playwright/test";

const BASE_URL =
  process.env.PDV_URL || "https://leakdetector.asymmetric-effort.com";

test.describe("leakdetector site PDV", () => {
  test("home page loads with logo, title, and teal theme", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".hero", { timeout: 15000 });

    // Logo is present and reasonably sized (not full screen).
    const logo = page.locator(".hero-logo");
    await expect(logo).toBeVisible();
    const box = await logo.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBeLessThanOrEqual(110);
    expect(box!.height).toBeLessThanOrEqual(110);

    // Title is present.
    await expect(page.locator(".hero h1")).toContainText("leakdetector");

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
    await page.waitForSelector(".hero", { timeout: 15000 });
    const favicon = page.locator('link[rel="icon"]');
    await expect(favicon).toHaveAttribute("href", "/logo.png");
  });

  test("navigation renders and routes work", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".nav", { timeout: 15000 });

    const navLinks = page.locator(".nav-links a");
    expect(await navLinks.count()).toBeGreaterThanOrEqual(4);

    // Click through each nav link and verify content loads.
    for (const route of ["usage", "configuration", "rules", "output"]) {
      await page.click(`.nav-links a[href="#/${route}"]`);
      await page.waitForSelector(".section", { timeout: 10000 });
      const sections = page.locator(".section h2");
      expect(await sections.count()).toBeGreaterThanOrEqual(1);
    }

    // Navigate back to home.
    await page.goto(`${BASE_URL}/#/`);
    await page.waitForSelector(".hero", { timeout: 15000 });
    await expect(page.locator(".hero h1")).toContainText("leakdetector");
  });

  test("footer contains version and copyright", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".footer", { timeout: 15000 });
    const footer = page.locator(".footer");
    await expect(footer).toContainText("MIT License");
    await expect(footer).toContainText("Asymmetric Effort");
  });

  test("code blocks have dark background", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector("pre", { timeout: 15000 });
    const pre = page.locator("pre").first();
    const bg = await pre.evaluate((el) => getComputedStyle(el).backgroundColor);
    // Should not be white.
    expect(bg).not.toBe("rgb(255, 255, 255)");
  });

  test("feature cards are visible on home page", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".feature-card", { timeout: 15000 });
    const cards = page.locator(".feature-card");
    expect(await cards.count()).toBeGreaterThanOrEqual(4);
  });

  test("SEO meta tags are present", async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForSelector(".hero", { timeout: 15000 });
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
