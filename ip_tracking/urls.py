from django.urls import path, re_path
from . import views

urlpatterns = [
    path('sensitive-login', views.sensitive_login_view, name='sensitive_login'),
]