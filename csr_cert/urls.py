from django.urls import path
from . import views

app_name = 'csr_cert'

urlpatterns = [
    path('csr/',views.CSRView,name='csr'),
    path('cssr/',views.CSSRView,name='cssr'),
    path('certChain/<id>',views.getCertChain,name='certChain'),
    path('certs/',views.CertListView.as_view(),name='certs'),
    path('certs/<int:pk>',views.CertDetailView.as_view(),name='cert-detail')
]