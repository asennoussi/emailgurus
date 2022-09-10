from django.contrib import admin
from .models import FilteredEmails, Jobs

# Register your models here.
admin.site.register(FilteredEmails)
admin.site.register(Jobs)
