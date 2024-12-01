from django.db import models
from wagtail.models import Page
from wagtail.fields import RichTextField
from wagtail.admin.panels import FieldPanel
from wagtail.images.models import Image
from wagtail.snippets.models import register_snippet
from modelcluster.fields import ParentalKey
from modelcluster.tags import ClusterTaggableManager
from taggit.models import TaggedItemBase

class ArticlePageTag(TaggedItemBase):
    content_object = ParentalKey(
        'ArticlePage',
        related_name='tagged_items',
        on_delete=models.CASCADE
    )

class ArticlePage(Page):
    date = models.DateField("Post date")
    intro = models.CharField(max_length=250)
    body = RichTextField(blank=True)
    author = models.ForeignKey(
        'Author',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='articles'
    )
    tags = ClusterTaggableManager(through=ArticlePageTag, blank=True)

    content_panels = Page.content_panels + [
        FieldPanel('date'),
        FieldPanel('intro'),
        FieldPanel('body'),
        FieldPanel('author'),
        FieldPanel('tags'),
    ]

@register_snippet
class Author(models.Model):
    name = models.CharField(max_length=100)
    bio = models.TextField(blank=True)
    photo = models.ForeignKey(
        Image,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='+'
    )

    panels = [
        FieldPanel('name'),
        FieldPanel('bio'),
        FieldPanel('photo'),
    ]

    def __str__(self):
        return self.name