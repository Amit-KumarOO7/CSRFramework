from django.shortcuts import render

# Create your views here.
from unicodedata import name
from wsgiref.util import request_uri
from django.shortcuts import redirect, render
from django.views.generic import TemplateView
import pkg_resources
from .forms import RootCAIMForm
from .models import RootCAIM
import OpenSSL.crypto as crypto

# Create your views here.
class IndexView(TemplateView):
    template_name = 'index.html'

def RootCAIMView(request):
    form = RootCAIMForm()
    gen_cert = "NaN"
    if request.method == 'POST':
        form = RootCAIMForm(request.POST)
        
        if form.is_valid():
            print('Setting up Root CA/IM!!')
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA,2048)
            cert = crypto.X509()
            cert.get_subject().CN = form.cleaned_data['common_name']
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(form.cleaned_data['validity_time']*365*86400)
            cert.get_subject().C = form.cleaned_data['country_code']
            cert.get_subject().ST = form.cleaned_data['state']
            cert.get_subject().O = form.cleaned_data['org_name']
            cert.get_subject().OU = form.cleaned_data['org_unit']
            cert.set_pubkey(key)
            if form.cleaned_data['set_issuer'] == None:
                cert.set_issuer(cert.get_subject())
                cert.sign(key,"sha256")
            else:
                obj = RootCAIM.objects.get(name=form.cleaned_data['set_issuer'])
                issuerCert = crypto.load_certificate(crypto.FILETYPE_PEM, obj.certificate)
                issuerKey = crypto.load_privatekey(crypto.FILETYPE_PEM,obj.key)
                cert.set_issuer(issuerCert.get_subject())
                cert.sign(issuerKey,"sha256")
            form.instance.certificate = crypto.dump_certificate(crypto.FILETYPE_PEM,cert).decode()
            form.instance.key = crypto.dump_privatekey(crypto.FILETYPE_PEM,key).decode()
            form.save()
            gen_cert = crypto.dump_certificate(crypto.FILETYPE_PEM,cert).decode()
    return render(request,'caim_page.html', {'form':form, 'cert': gen_cert})

