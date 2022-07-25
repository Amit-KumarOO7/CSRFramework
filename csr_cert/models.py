from django.db import models
from ca_intermediate.models import RootCAIM

# Create your models here.
class CSR(models.Model):
    name = models.CharField(max_length=48,null=True)
    common_name = models.CharField(max_length=264,null=True)
    csr = models.TextField(unique=True, blank=True)
    set_issuer = models.ForeignKey(RootCAIM,on_delete=models.CASCADE,null=True, blank=True)
    certificate = models.TextField(unique=True)
    key = models.TextField(blank=True)

