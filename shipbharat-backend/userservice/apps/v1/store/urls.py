from django.urls import path, include
from .views import StoreListAPIView, StoreDetailAPIView

urlpatterns = [
    path('', StoreListAPIView.as_view(), name="store-list-create"),
    path('<int:id>', StoreDetailAPIView.as_view(), name="store-detail-delete"),

]