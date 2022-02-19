from rest_framework import serializers
from .models import Store


class StoreSerializer(serializers.ModelSerializer):

    class Meta:
        model = Store
        fields = ['id','user', 'store_type', 'store_api_key', 'store_api_passcode', 'store_name']