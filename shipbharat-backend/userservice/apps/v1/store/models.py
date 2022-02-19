from django.db import models

# Create your models here.
from django.conf import settings
import uuid

UUID = True


class Store(models.Model):
    Shp = 'Shopify'
    Wcm = 'Woocommerce'
    EXPORT_STORE_CHOICES = [
        ('Shp', 'Shopify'),
        ('Wcm', 'Woocommerce'),
    ]
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=0)
    store_type = models.CharField(
        choices=EXPORT_STORE_CHOICES,
        default=Shp,
        max_length=20
    )
    store_api_key = models.CharField(blank=True, max_length=200)
    store_api_passcode = models.CharField(blank=True, max_length=200)
    store_name = models.CharField(blank=True, max_length=200)
    is_active = models.BooleanField(default=False)
    shiprocket_channel_id = models.CharField(blank=True, max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def get_store_name_from_url(self):
        if self.store_type == "Shp":
            return str(self.store_name).split('.')[0]
        return self.store_name

    def __str__(self) -> str:
        return self.store_name
