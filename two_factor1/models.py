from django.db import models
from django.conf import settings


class TrustedDevice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    hashed_info = models.CharField(max_length=255)

    class Meta:
        unique_together = ('user', 'hashed_info')
