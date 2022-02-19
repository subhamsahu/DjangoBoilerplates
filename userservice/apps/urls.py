from django.urls import path, include

API_VER='v1'

urlpatterns = [
    path('user/', include(f'apps.{API_VER}.user.urls')),
    # path('store/', include('apps.store.urls')),

]