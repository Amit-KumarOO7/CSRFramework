# Generated by Django 4.0.6 on 2022-07-25 06:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('csr_cert', '0005_alter_csr_certificate'),
    ]

    operations = [
        migrations.AlterField(
            model_name='csr',
            name='certificate',
            field=models.TextField(unique=True),
        ),
    ]
