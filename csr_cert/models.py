from django.db import models

# Create your models here.
class CSR(models.Model):
    csr = models.TextField(unique=True)
    set_issuer = models.ForeignKey('self',on_delete=models.CASCADE,null=True, blank=True)
    certificate = models.TextField(unique=True)
    key = models.TextField(unique=True)

