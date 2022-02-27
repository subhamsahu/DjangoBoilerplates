from django.urls import path, include

API_VER='v1'

urlpatterns = [
    path('user/', include(f'apps.{API_VER}.user.urls')),
    path('store/', include(f'apps.{API_VER}.store.urls')),
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.jwt')),

]