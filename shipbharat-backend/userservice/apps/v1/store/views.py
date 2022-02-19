from django.shortcuts import render
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from .serializers import StoreSerializer
from .models import Store
from rest_framework import permissions
from .permissions import IsOwner


class StoreListAPIView(ListCreateAPIView):
    serializer_class = StoreSerializer
    queryset = Store.objects.all()
    permission_classes = (permissions.IsAuthenticated,IsOwner)

    def perform_create(self, serializer):
        return serializer.save(user=self.request.user)

    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)


class StoreDetailAPIView(RetrieveUpdateDestroyAPIView):
    serializer_class = StoreSerializer
    permission_classes = (permissions.IsAuthenticated, IsOwner,)
    queryset = Store.objects.all()
    lookup_field = "id"

    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)