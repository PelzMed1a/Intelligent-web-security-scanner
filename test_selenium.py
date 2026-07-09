from crawler.selenium_renderer import SeleniumRenderer

renderer = SeleniumRenderer()

html = renderer.render("https://example.com")

print("=" * 60)
print(html[:500])
print("=" * 60)

renderer.close()
