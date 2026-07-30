from crawler.selenium_renderer import SeleniumRenderer

renderer = SeleniumRenderer(headless=False)

html = renderer.render("http://localhost:3000")

print("=" * 60)
print(html[:2000])
print("=" * 60)

renderer.close()
