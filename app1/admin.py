from django.contrib import admin
from .models import CustomUser, Usermember, Department, Usermember2, Request

# Register your models here.

admin.site.register(CustomUser)
admin.site.register(Usermember)
admin.site.register(Department)
admin.site.register(Usermember2)
admin.site.register(Request)