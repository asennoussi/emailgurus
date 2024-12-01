
from django import template
from bs4 import BeautifulSoup
register = template.Library()

@register.simple_tag
def generate_toc(content):
    soup = BeautifulSoup(content, 'html.parser')
    headings = soup.find_all(['h2', 'h3', 'h4'])
    toc = '<ul class="toc-list">'
    
    for heading in headings:
        # Create an ID if none exists
        if not heading.get('id'):
            heading['id'] = heading.text.lower().replace(' ', '-')
        
        # Add appropriate class based on heading level
        level_class = f"toc-level-{heading.name[1]}"
        
        toc += f'<li class="{level_class}"><a href="#{heading["id"]}">{heading.text}</a></li>'
    
    toc += '</ul>'
    return toc