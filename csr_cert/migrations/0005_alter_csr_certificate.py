# Generated by Django 4.0.6 on 2022-07-25 05:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('csr_cert', '0004_alter_csr_key'),
    ]

    operations = [
        migrations.AlterField(
            model_name='csr',
            name='certificate',
            field=models.TextField(),
        ),
    ]
