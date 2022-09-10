from django.contrib import admin

from .models import CustomUser, LinkedAccounts, deletedAccounts
# Register your models here.


class DeletedAccountsAdmin(admin.ModelAdmin):
    readonly_fields = ('deleted_on',)


admin.site.register(LinkedAccounts)
admin.site.register(deletedAccounts, DeletedAccountsAdmin)
admin.site.register(CustomUser)
