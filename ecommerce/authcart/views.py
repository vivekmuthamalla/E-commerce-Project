from django.shortcuts import render,redirect,HttpResponse
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from .utils import TokenGenerator,generate_token
from django.utils.encoding import force_bytes,force_str,DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.tokens import default_token_generator
from captcha.fields import CaptchaField
import json
# Create your views here.
def signup(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('pass1')
        confirm_password = request.POST.get('pass2')

        if password != confirm_password:
            messages.warning(request, "Password does not match")
            return render(request, 'signup.html')

        try:
            if User.objects.get(username=email):
                messages.info(request, "Email is already taken")
                return render(request, 'signup.html')

        except User.DoesNotExist:
            user = User.objects.create_user(email, email=email, password=password)
            user.is_active = False
            user.save()

            email_subject = "Activate Your Account"
            message = render_to_string('activate.html', {
                'user': user,
                'domain': request.get_host(),
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user)
            })

            email_message = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [email],
            )
            email_message.send()
            messages.success(request, "Activate Your Account by clicking the link in your email")
            return redirect('/auth/login/')

    return render(request, "signup.html")

class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account activated Successfully")
            return redirect('/auth/login')
        return render(request,'activatefail.html')



def handlelogin(request):
    if request.method=='POST':
        username=request.POST['email']
        userpassword=request.POST['pass1']
        myuser=authenticate(username=username,password=userpassword)

        if myuser is not None:
            login(request,myuser)
            messages.success(request,"login success")
            return redirect('/')
        
        else:
            messages.error(request,"Invalid Credentials")
            return redirect('/auth/login')
    return render(request,'login.html')






def handlelogout(request):
    logout(request)
    messages.warning(request,"Logout successfully!")
    return redirect('/auth/login')