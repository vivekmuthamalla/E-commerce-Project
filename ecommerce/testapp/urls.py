from django.urls import path
from testapp import views
urlpatterns = [
    path('',views.index),
    path('contact/',views.contact,name="contact"),
    path('about/',views.about,name="about"),

]
