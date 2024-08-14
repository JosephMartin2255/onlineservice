from django.shortcuts import render,redirect,get_object_or_404
from .models import Usermember, CustomUser, Department
from .models import PendingWorker
from app1.models import Usermember2
from .models import WorkerRequest
from .models import Request
from .models import Review
from .models import AcceptedRequest
from django.contrib.auth.models import User
from .forms import WorkerSignupForm
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.http import JsonResponse
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.db import IntegrityError
from django.db.models import Count
import os
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.http import HttpResponse
from django.contrib.staticfiles import storage
from django.contrib.auth import get_user_model
from django.contrib.auth import update_session_auth_hash
import re
from django.conf import settings
import random
import string

# <---------login page -------->

def homepage(request):
    return render(request, 'homepage.html')

def loginpage1(request):
    return render(request, 'loginpage1.html')

def logincreate(request):
    username_error = None
    password_error = None
    
    if request.method == 'POST':
        Username = request.POST.get('Uname')
        Password = request.POST.get('Pwd')
        user = authenticate(username=Username, password=Password)
        
        if user is not None:
            login(request, user)
            if user.user_type == '1':
                return redirect('adminhome')
            elif user.user_type == '2':
                # Check if the user is a worker
                try:
                    worker = Usermember.objects.get(user=user)
                    if worker.is_approved and not worker.is_pending:
                        return redirect('workerhome')
                    else:
                        messages.error(request, 'Your worker account is not yet approved or is pending.')
                        return redirect(reverse('loginpage1'))
                except Usermember.DoesNotExist:
                    messages.error(request, 'You are not authorized to access this page.')
                    return redirect(reverse('loginpage1'))
            elif user.user_type == '3':
                # Check if the user is a regular user
                return redirect('userhome')
              
        else:
            if not CustomUser.objects.filter(username=Username).exists():
                username_error = 'Please enter a valid username'
            if CustomUser.objects.filter(username=Username).exists() and not CustomUser.objects.filter(username=Username, password=Password).exists():
                password_error = 'Please enter a valid password'
            if not CustomUser.objects.filter(username=Username).exists() and not CustomUser.objects.filter(username=Username, password=Password).exists():
                password_error = 'Please enter a valid password'
                username_error = 'Please enter a valid username'

    return render(request, 'loginpage1.html', {'username_error': username_error, 'password_error': password_error})

def validate_username(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        try:
            CustomUser.objects.get(username=username)
            return JsonResponse({'valid': True})
        except CustomUser.DoesNotExist:
            return JsonResponse({'valid': False})
    return JsonResponse({'valid': False})

def generate_random_password():
    # Generate a 6-digit random password
    characters = string.ascii_letters + string.digits
    random_password = ''.join(random.choice(characters) for i in range(6))
    return random_password

def forgotpassword(request):
    success_message = None
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')

        # Assuming username and email are required fields
        if username and email:
            try:
                user = CustomUser.objects.get(username=username)
                # Generate a random password
                new_password = generate_random_password()

                # Update user's password
                user.set_password(new_password)
                user.save()

                # Send email with new password
                subject = 'Password Reset'
                message = f'Your new password is: {new_password}'
                from_email = settings.EMAIL_HOST_USER  # Update with your email settings
                to_email = [email]
                send_mail(subject, message, from_email, to_email)

                # Set success message
                success_message = "The new password will be sent to your email account."
            except CustomUser.DoesNotExist:
                pass  # Handle case where username does not exist

    return render(request, 'forgotpassword.html', {'success_message': success_message})






# <-----------Admin Module ---------->





def adminhome(request):
    pending_count = Usermember.objects.filter(is_approved=False, is_pending=True).count()
    preferred_dept_count = PendingWorker.objects.count()  # Assuming you have a model PendingWorker for preferred department requests
    total_pending_count = pending_count + preferred_dept_count
    return render(request, 'adminhome.html', {
        'pending_count': pending_count,
        'preferred_dept_count': preferred_dept_count,
        'total_pending_count': total_pending_count
    })



def newdepartment(request):
    success_message = ""
    if request.method == 'POST':
        department_name = request.POST.get('department')
        if department_name:
            Department.objects.get_or_create(name=department_name)
            success_message = "Department added successfully."

    pending_count = Usermember.objects.filter(is_approved=False, is_pending=True).count()
    preferred_dept_count = PendingWorker.objects.count()  # Assuming you have a model PendingWorker for preferred department requests
    total_pending_count = pending_count + preferred_dept_count
    
    return render(request, 'newdepartment.html', {
        'pending_count': pending_count,
        'preferred_dept_count': preferred_dept_count,
        'total_pending_count': total_pending_count,
        'success_message': success_message
    })



def notifications(request):
    pending_count = Usermember.objects.filter(is_approved=False, is_pending=True).count()
    preferred_dept_count = PendingWorker.objects.count()  # Assuming you have a model PendingWorker for preferred department requests
    total_pending_count = pending_count + preferred_dept_count
    return render(request, 'notifications.html', {
        'pending_count': pending_count,
        'preferred_dept_count': preferred_dept_count,
        'total_pending_count': total_pending_count
    })



def preferreddept(request):
    special_dept_workers = PendingWorker.objects.all()
    return render(request, 'preferreddept.html', {'special_dept_workers': special_dept_workers})

def preferreddept_allow(request, worker_id):
    special_dept_worker = get_object_or_404(PendingWorker, id=worker_id)
    
    if special_dept_worker.username:
        user, created = CustomUser.objects.get_or_create(
            username=special_dept_worker.username,
            defaults={
                'email': special_dept_worker.email,
                'first_name': special_dept_worker.first_name,
                'last_name': special_dept_worker.last_name,
                'user_type': 2  # Set user_type to 2 for workers
            }
        )
        
        if not created:
            user.email = special_dept_worker.email
            user.first_name = special_dept_worker.first_name
            user.last_name = special_dept_worker.last_name
            user.user_type = 2
            user.save()
    else:
        messages.error(request, "Username not provided for the worker.")
        return redirect('preferreddept')

    usermember, member_created = Usermember.objects.get_or_create(
        user=user,
        defaults={
            'age': special_dept_worker.age,
            'number': special_dept_worker.contact,
            'experience': special_dept_worker.experience,
            'department': special_dept_worker.department,
            'image': special_dept_worker.image,
            'is_approved': False,
            'is_pending': True,
            'status': 'pending'
        }
    )
    
    if not member_created:
        usermember.age = special_dept_worker.age
        usermember.number = special_dept_worker.contact
        usermember.experience = special_dept_worker.experience
        usermember.department = special_dept_worker.department
        usermember.image = special_dept_worker.image
        usermember.is_approved = False
        usermember.is_pending = True
        usermember.status = 'pending'
        usermember.save()

    Department.objects.get_or_create(name=special_dept_worker.department)

    send_mail(
        'Approval Successful',
        'Your new department has been approved. Please wait for the admin approval.',
        'josephm2255@gmail.com',  # From email
        [special_dept_worker.email],
        fail_silently=False,
    )

    special_dept_worker.delete()
    
    return redirect(reverse('preferreddept') + f'?special_dept_worker_id={user.id}')

def preferreddept_clear(request, worker_id):
    special_dept_worker = get_object_or_404(PendingWorker, id=worker_id)
    send_mail(
        'Disapprove your department',
        'Your new department has been disapproved. Please contact admin for more information.',
        'josephm2255@gmail.com',  # From email
        [special_dept_worker.email],
        fail_silently=False,
    )
    special_dept_worker.delete()
    return redirect('preferreddept')




def viewworkers(request):
    workers = Usermember.objects.all()
    special_dept_worker_id = request.GET.get('special_dept_worker_id')
    special_dept_worker = None
    if special_dept_worker_id:
        special_dept_worker = get_object_or_404(Usermember, user_id=special_dept_worker_id)
    
    pending_count = Usermember.objects.filter(is_approved=False, is_pending=True).count()
    preferred_dept_count = PendingWorker.objects.count()
    total_pending_count = pending_count + preferred_dept_count
    
    return render(request, 'viewworkers.html', {
        'workers': workers,
        'special_dept_worker': special_dept_worker,
        'pending_count': pending_count,
        'preferred_dept_count': preferred_dept_count,
        'total_pending_count': total_pending_count
    })

def delete_worker(request, user_id):
    user1 = get_object_or_404(CustomUser, id=user_id)
    user2 = get_object_or_404(Usermember, user=user1)

    # Delete records from both models
    user1.delete()
    user2.delete()

    return redirect('viewworkers')




def viewusers(request):
    users = Usermember2.objects.all()
    pending_count = Usermember.objects.filter(is_approved=False, is_pending=True).count()
    preferred_dept_count = PendingWorker.objects.count()  
    total_pending_count = pending_count + preferred_dept_count
    return render(request, 'viewusers.html', {
        'users': users,
        'pending_count': pending_count,
        'preferred_dept_count': preferred_dept_count,
        'total_pending_count': total_pending_count
    })

def delete_user(request, user_id):
    user = Usermember2.objects.get(pk=user_id)
    user.user.delete()  # Delete associated user
    user.delete()  # Delete Usermember2 instance
    return redirect('viewusers')

def approvedworkers(request):
    approved_workers = Usermember.objects.filter(is_approved=True)
    pending_count = Usermember.objects.filter(is_approved=False, is_pending=True).count()
    preferred_dept_count = PendingWorker.objects.count() 
    total_pending_count = pending_count + preferred_dept_count
    return render(request, 'approvedworkers.html', {
        'approved_workers': approved_workers,
        'pending_count': pending_count,
        'preferred_dept_count': preferred_dept_count,
        'total_pending_count': total_pending_count
    })





def user_details(request, worker_id):
    user = get_object_or_404(CustomUser, id=worker_id)
    usermember2 = Usermember2.objects.filter(user=user).first()
    accepted_requests = AcceptedRequest.objects.filter(worker=user)
    pending_count = Usermember.objects.filter(is_approved=False, is_pending=True).count()
    preferred_dept_count = PendingWorker.objects.count() 
    total_pending_count = pending_count + preferred_dept_count
    
    # Fetch the requests assigned to the specific worker
    assigned_requests = Request.objects.filter(worker=user)

    context = {
        'user': user,
        'usermember2': usermember2,
        'accepted_requests': accepted_requests,
        'assigned_requests': assigned_requests,  # Pass assigned requests to the template
        'total_pending_count': total_pending_count
    }
    return render(request, 'user_details.html', context)

def approvedisapprove(request):
    pending_workers = Usermember.objects.filter(is_approved=False, is_pending=True)
    pending_count = Usermember.objects.filter(is_approved=False, is_pending=True).count()
    preferred_dept_count = PendingWorker.objects.count() 
    total_pending_count = pending_count + preferred_dept_count
    return render(request, 'approvedisapprove.html', {
        'pending_workers': pending_workers,
        'pending_count': pending_count,
        'preferred_dept_count': preferred_dept_count,
        'total_pending_count': total_pending_count
    })

import logging
logger = logging.getLogger(__name__)
def approve_worker(request, user_id):
    worker = get_object_or_404(Usermember, user__id=user_id)
    
    worker.is_approved = True
    worker.is_pending = False
    worker.save()

    user = worker.user
    password = get_random_string(6, allowed_chars='0123456789')
    user.set_password(password)
    user.save()
    
    logger.info(f"Password for {user.email} is set to {password}")

    try:
        send_mail(
            'Approval Successful',
            f'Your registration has been approved. Your password is {password}.',
            'josephm2255@gmail.com',  # From email
            [user.email],
            fail_silently=False,
        )
        logger.info(f"Approval email sent to {user.email}")
        # messages.success(request, f"Worker {user.get_full_name()} approved successfully.")
    except Exception as e:
        logger.error(f"Failed to send approval email to {user.email}. Error: {e}")
       # messages.error(request, f"Failed to send approval email to {user.get_full_name()}. Error: {e}")

    return redirect('approvedisapprove')


def disapprove_worker(request, user_id):
    worker = get_object_or_404(Usermember, user__id=user_id)
    worker.status = 'disapproved'
    worker.is_approved = False
    worker.is_pending = False
    worker.save()
    
    # Send email notification
    send_mail(
        'Disapproval Notice',
        'Your registration has been disapproved. Please contact support for more information.',
        'josephm2255@gmail.com',  # From email
        [worker.user.email],
        fail_silently=False,
    )
    
    # messages.info(request, f"The worker '{worker.user.username}' has been disapproved.")
    return redirect('approvedisapprove')



def viewimages(request, usermember_id):
    usermember = get_object_or_404(Usermember, id=usermember_id)
    return render(request, 'viewimages.html', {'usermember': usermember})





# <------------worker Module --------->





def workersignup(request):
    if request.method == 'POST':
        form = WorkerSignupForm(request.POST, request.FILES)
        if form.is_valid():
            department = form.cleaned_data.get('department')
            supporting_images = form.cleaned_data.get('supporting_images')
            
            if department == 'other':
                image = form.cleaned_data.get('image')
                image_name = default_storage.save(image.name, image)
                # Save the worker details in the PendingWorker model
                PendingWorker.objects.create(
                    first_name=form.cleaned_data.get('first_name'),
                    last_name=form.cleaned_data.get('last_name'),
                    email=form.cleaned_data.get('email'),
                    age=form.cleaned_data.get('age'),
                    contact=form.cleaned_data.get('contact'),
                    experience=form.cleaned_data.get('experience'),
                    department=form.cleaned_data.get('other_department'),
                    image=image_name,
                    username=form.cleaned_data.get('username'),  # Save username
                    supporting_images=supporting_images  # Save supporting documents
                )
                messages.info(request, "Please wait for admin approval for the new department.")
                return redirect('workersignup')
            else:
                user = form.save(commit=False)
                password = get_random_string(6, allowed_chars='0123456789')
                user.set_password(password)
                user.user_type = '2'
                user.save()
                Usermember.objects.create(
                    user=user,
                    age=form.cleaned_data.get('age'),
                    number=form.cleaned_data.get('contact'),
                    experience=form.cleaned_data.get('experience'),
                    department=department,
                    image=form.cleaned_data.get('image'),
                    supporting_images=supporting_images  # Save supporting documents
                )
                messages.success(request, "Your registration is successful. Please wait for admin approval.")
                return redirect('workersignup')
    else:
        form = WorkerSignupForm()
    return render(request, 'workersignup.html', {'form': form})





def workerhome(request):
    User = get_user_model()
    try:
        usermember = Usermember.objects.get(user=request.user)
    except Usermember.DoesNotExist:
        usermember = None
    
    if usermember:
        worker = request.user
        pending_requests_count = Request.objects.filter(worker=worker, status='pending').count()
    else:
        pending_requests_count = 0
    
    return render(request, 'workerhome.html', {'pending_requests_count': pending_requests_count})



def workernotifications(request):
    worker = request.user
    pending_requests_count = Request.objects.filter(worker=worker, status='pending').count()
    return render(request, 'workernotifications.html', {'pending_requests_count': pending_requests_count})


    
 
def workerreviews(request):
    User = get_user_model()
    try:
        usermember = Usermember.objects.get(user=request.user)
    except Usermember.DoesNotExist:
        usermember = None
    
    if usermember:
        worker = request.user
        pending_requests_count = Request.objects.filter(worker=worker, status='pending').count()
    else:
        pending_requests_count = 0

    # Get the worker and their reviews
    worker = Usermember.objects.get(user=request.user)
    reviews = Review.objects.filter(worker=worker)
    
    return render(request, 'workerreviews.html', {
        'reviews': reviews, 
        'pending_requests_count': pending_requests_count
    })
  
    



def workerpassword(request):
    User = get_user_model()
    try:
        usermember = Usermember.objects.get(user=request.user)
    except Usermember.DoesNotExist:
        usermember = None
    
    if usermember:
        worker = request.user
        pending_requests_count = Request.objects.filter(worker=worker, status='pending').count()

    else:
        pending_requests_count = 0
    
    return render(request, 'workerpassword.html', {'pending_requests_count': pending_requests_count})

def workerpassword1(request):
    error_messages = {
        'currentPassword_error': [],
        'newPassword_error': [],
        'confirmPassword_error': [],
    }

    if request.method == 'POST':
        current_password = request.POST.get('currentPassword')
        new_password = request.POST.get('newPassword')
        confirm_password = request.POST.get('confirmPassword')

        user = request.user

      
        if not user.check_password(current_password):
            error_messages['currentPassword_error'].append('Incorrect current password.')

      
        if new_password != confirm_password:
            error_messages['confirmPassword_error'].append('New password and confirm password do not match.')

     
        is_valid, password_error = validate_password(new_password)
        if not is_valid:
            error_messages['newPassword_error'].append(password_error)

       
        if user.check_password(new_password):
            error_messages['newPassword_error'].append('New password cannot be the same as the old password.')

       
        if all(not error_messages[key] for key in error_messages):
            user.set_password(new_password)
            user.save()

          
            update_session_auth_hash(request, user)

            messages.success(request, 'Password reset successfully!')
            return redirect('workerpassword')  

    
    return render(request, 'workerpassword.html', error_messages)

def validate_password(password):
    errors = []

    if len(password) < 6 or len(password) > 15:
        errors.append("be between 6 and 15 characters long")
    if not re.search(r'[A-Z]', password):
        errors.append("include at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        errors.append("include at least one lowercase letter")
    if not re.search(r'\d', password):
        errors.append("include at least one digit")
    if not re.search(r'[\W_]', password):
        errors.append("include at least one special character")

    if errors:
        error_message = "Password must " + ", ".join(errors) + "."
        return False, error_message
    return True, ""

def workerprofile(request):
    User = get_user_model()
    try:
        usermember = Usermember.objects.get(user=request.user)
    except Usermember.DoesNotExist:
        usermember = None
    
    if usermember:
       
        
        worker = request.user
        age = usermember.age
        number = usermember.number
        department = usermember.department
        pending_requests_count = Request.objects.filter(worker=worker, status='pending').count()
    else:
        age = None
        number = None
        department = None
        pending_requests_count = 0
    
    return render(request, 'workerprofile.html', {
        'pending_requests_count': pending_requests_count,
        'age': age,
        'number': number,
        'department': department,
        'usermember': usermember  
    })



def workerprofile1(request):
    user = request.user
    usermember = get_object_or_404(Usermember, user=user)

    if request.method == 'POST':
      
        email = request.POST.get('email')

       
        if CustomUser.objects.exclude(id=user.id).filter(email=email).exists():
            email_error = 'This email address is already registered.'
        else:
            email_error = None

         
            user.first_name = request.POST.get('first_name')
            user.last_name = request.POST.get('last_name')
            user.email = email
            user.save()

            usermember.age = request.POST.get('age')
            usermember.number = request.POST.get('number')
            usermember.experience = request.POST.get('experience')
            usermember.department = request.POST.get('department')
            if request.FILES.get('image'):
                usermember.image = request.FILES.get('image')
            usermember.save()

           
            messages.success(request, 'Your profile has been updated successfully.')

            
            return redirect('workerprofile')

        
        return render(request, 'workerprofile.html', {'user': user, 'usermember': usermember, 'email_error': email_error})

    return render(request, 'workerprofile.html', {'user': user, 'usermember': usermember})




def worker_accept(request):
    worker = request.user

    
    user_requests = Request.objects.filter(worker=worker)
    pending_requests_count = user_requests.filter(status='pending').count()
    
    return render(request, 'workeraccept.html', {'requests': user_requests, 'pending_requests_count': pending_requests_count})





def confirm_request(request, request_id):
    user_request = get_object_or_404(Request, id=request_id)
    user_request.status = 'confirmed'
    user_request.confirmed_by = request.user
    user_request.save()

    usermember2 = Usermember2.objects.filter(user=user_request.user).first()

    AcceptedRequest.objects.create(
        user=user_request.user,
        usermember2=usermember2,
        worker=request.user,
        request=user_request
    )

    send_mail(
        'Service Accepted',
        'The worker has accepted your service.',
        'your-email@example.com',
        [user_request.user.email],
        fail_silently=False,
    )
    return redirect('workeraccept')

def delete_request(request, request_id):
    user_request = get_object_or_404(Request, id=request_id)
    
 
    send_mail(
        'Service Not Accepted',
        'The worker has not accepted your service.',
        'your-email@example.com',
        [user_request.user.email],
        fail_silently=False,
    )
    
  
    user_request.delete()
    
   
    #messages.success(request, 'The user has been notified of the rejection and the request has been deleted.')
    
  
    return redirect('workeraccept')


def toggle_completion(request, request_id):
    user_request = get_object_or_404(Request, id=request_id)
    user_request.completed = not user_request.completed
    user_request.save()
    if user_request.completed:
        send_mail(
            'Work Completed',
            'The worker has completed the service.',
            'your-email@example.com',
            [user_request.user.email],
            fail_silently=False,
        )
        #messages.success(request, 'The user has been notified of the completion.')
    return redirect('workeraccept')





# <----------User Module --------->



def usersignup(request):
    return render(request, 'usersignup.html')


def userreg1(request):
    if request.method == "POST":
        user_fname = request.POST['fname']
        user_lname = request.POST['lname']
        user_uname = request.POST['uname']
        user_age = request.POST['age']
        user_email = request.POST['email']
        user_number = request.POST['number']
        user_image = request.FILES.get('image')
        user_address = request.POST.get('address')  
        user_date = request.POST.get('date')       
        user_type = 3  # Set user_type to 3

        errors = {}
        fname_pattern = re.compile(r'^[A-Za-z]{3,}$')
        lname_pattern = re.compile(r'^[A-Za-z]{3,}$')
        uname_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{3,}$')
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@(gmail|email)\.com$')
        number_pattern = re.compile(r'^\d{10}$')

        if not fname_pattern.match(user_fname):
            errors['fnameError'] = 'First name must contain only alphabets and be at least 3 characters long.'
        if not lname_pattern.match(user_lname):
            errors['lnameError'] = 'Last name must contain only alphabets and be at least 3 characters long.'
        if not uname_pattern.match(user_uname):
            errors['unameError'] = 'Username must contain at least 3 alphabets, 1 digit, 1 uppercase, 1 lowercase, and 1 special character.'
        if not email_pattern.match(user_email):
            errors['emailError'] = 'Email must be a valid Gmail or Email address.'
        if not number_pattern.match(user_number):
            errors['numberError'] = 'Contact number must be exactly 10 digits long.'

        try:
            CustomUser.objects.get(username=user_uname)
            errors['unameError'] = 'Username already exists.'
        except CustomUser.DoesNotExist:
            pass
        
        try:
            CustomUser.objects.get(email=user_email)
            errors['emailError'] = 'Email already exists.'
        except CustomUser.DoesNotExist:
            pass

        if errors:
            data = {
                'fname': user_fname,
                'lname': user_lname,
                'uname': user_uname,
                'age': user_age,
                'email': user_email,
                'number': user_number,
                'address': user_address,  
                'date': user_date          
            }
            return render(request, 'usersignup.html', {'errors': errors, 'data': data})

      
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=6))

        try:
           
            new_user = CustomUser.objects.create_user(
                first_name=user_fname,
                last_name=user_lname,
                username=user_uname,
                email=user_email,
                password=password,
                user_type=user_type  
            )

          
            member = Usermember2(user=new_user, age=user_age, number=user_number, image=user_image,
                                address=user_address, date=user_date)  
            member.save()

            
            send_mail(
                'Registration Successful',
                f'Your new password is: {password}',
                'josephm2255@gmail.com',  # From email
                [user_email],  # To email using user's email
                fail_silently=False,
            )

            success_message = 'Your registration is successful. You will receive a new password through your email.'
            return render(request, 'usersignup.html', {'success_message': success_message})

        except IntegrityError:
            errors['unameError'] = 'Username or Email already exists.'
            data = {
                'fname': user_fname,
                'lname': user_lname,
                'uname': user_uname,
                'age': user_age,
                'email': user_email,
                'number': user_number,
                'address': user_address,  
                'date': user_date          
            }
            return render(request, 'usersignup.html', {'errors': errors, 'data': data})

    return redirect('usersignup')






def userhome(request):
 
    approved_workers = Usermember.objects.filter(is_approved=True)
    
   
    department_counts = approved_workers.values('department').annotate(count=Count('department'))
    
   
    department_styles = {}
    
    
    departments = ['Plumber', 'Carpenter', 'Electrician', 'Welder', 'Painter', 'Cleaning']
    
    
    for dept in departments:
        
        count = next((item['count'] for item in department_counts if item['department'] == dept), 0)
        
        if count > 0:
           
            department_styles[dept] = {
                'background_color': 'green',
                'text_color': 'white'
            }
        else:
         
            department_styles[dept] = {
                'background_color': 'red',
                'text_color': 'white'
            }
    
   
    department_counts_final = {dept: next((item['count'] for item in department_counts if item['department'] == dept), 0) for dept in departments}
    
   
    return render(request, 'userhome.html', {
        'department_counts': department_counts_final,
        'department_styles': department_styles,
        'departments': departments  
    })


def userrequest(request):
    approved_workers = Usermember.objects.filter(is_approved=True)
    department_counts = approved_workers.values('department').annotate(count=Count('department'))

    return render(request, 'userrequest.html', {'workers': approved_workers, 'department_counts': department_counts})

def supporting_image(request, worker_id):
    worker = get_object_or_404(Usermember, id=worker_id)
    return render(request, 'supporting_image.html', {'worker': worker})


from .forms import RequestForm

def requestform(request):
    if request.method == 'POST':
        form = RequestForm(request.POST)
        if form.is_valid():
            department = form.cleaned_data['department']
            service = form.cleaned_data['service']
            user = request.user

            
            try:
                usermember2 = Usermember2.objects.get(user=user)
            except Usermember2.DoesNotExist:
                usermember2 = None

            
            worker = CustomUser.objects.filter(usermember__department=department).first()

            if worker:
                new_request = Request.objects.create(
                    user=user,
                    department=department,
                    service=service,
                    usermember2=usermember2,
                    worker=worker,
                )
                messages.success(request, 'Form submitted successfully!')
            else:
                messages.error(request, 'No worker found for the specified department.')

            return redirect('requestform')

    else:
        form = RequestForm()

    return render(request, 'requestform.html', {'form': form})





def userabout(request):
    return render(request, 'userabout.html')


def useraccount(request):
    user = request.user
    if user.is_authenticated and user.user_type == '3':
        user_profile = Usermember2.objects.get(user=user)
        context = {
            'user': user,
            'user_profile': user_profile
        }
        return render(request, 'useraccount.html', context)
    else:
        return redirect('useraccount')  


def userprofile(request):
    user_profile = get_object_or_404(Usermember2, user=request.user)
    form_data = {
        'first_name': request.user.first_name,
        'last_name': request.user.last_name,
        'username': request.user.username,
        'email': request.user.email,
        'age': user_profile.age,
        'number': user_profile.number,
        'image': user_profile.image.url if user_profile.image else None
    }
    context = {
        'form_data': form_data,
        'error_messages': {}
    }
    return render(request, 'userprofile.html', context)



def userprofile1(request):
    user = request.user
    user_profile = Usermember2.objects.get(user=user)  
    
    if request.method == 'POST':
        form_data = {
            'first_name': request.POST['first_name'],
            'last_name': request.POST['last_name'],
            'username': request.POST['username'],
            'email': request.POST['email'],
            'age': request.POST['age'],
            'number': request.POST['number'],
        }
        
       
        errors = {}

     
        if not form_data['first_name'].strip() or not form_data['first_name'].isalpha() or len(form_data['first_name']) < 3:
            errors['first_name'] = "First name should only include alphabets and be at least 3 characters long."
        
        
        if not form_data['last_name'].strip() or not form_data['last_name'].isalpha() or len(form_data['last_name']) < 3:
            errors['last_name'] = "Last name should only include alphabets and be at least 3 characters long."
        
      
        username = form_data['username']
        username_errors = []
        if len(username) < 6 or len(username) > 15:
            username_errors.append("Username should be between 6 to 15 characters.")
        if not any(char.islower() for char in username):
            username_errors.append("Username should contain at least one lowercase letter.")
        if not any(char.isupper() for char in username):
            username_errors.append("Username should contain at least one uppercase letter.")
        if not any(char.isdigit() for char in username):
            username_errors.append("Username should contain at least one digit.")
        if not any(char in '@$!%*?&' for char in username):
            username_errors.append("Username should contain at least one special character (@, $, !, %, *, ?, &).")
        
       
        if CustomUser.objects.filter(username=username, user_type=3).exists():
            username_errors.append("This Username already exists.")
        
        if username_errors:
            errors['username'] = " ".join(username_errors)

     
        try:
            age = int(form_data['age'])
            if age < 18:
                errors['age'] = "Age should be at least 18."
        except ValueError:
            errors['age'] = "Age should be a valid number."

  
        email = form_data['email']
        if not email.strip() or not email.endswith(('@gmail.com', '@email.com')):
            errors['email'] = "Email should be of format '@gmail.com' or '@email.com.'"

     
        if CustomUser.objects.filter(email=email, user_type=3).exists():
            errors['email'] = "This email already exists ."

       
        number = form_data['number']
        if not number.isdigit() or len(number) != 10:
            errors['number'] = "Contact number should be exactly 10 digits."

       
        if 'image' not in request.FILES:
            errors['image'] = "Please select an image."
        else:
            image = request.FILES['image']
            if not image.name.lower().endswith(('.jpg', '.jpeg', '.png')):
                errors['image'] = "Profile image must be in JPEG, JPG, or PNG format."

        if errors:
            
            #messages.error(request, "Please correct the errors below.")
            return render(request, 'userprofile.html', {'form_data': form_data, 'error_messages': errors})
        else:
            # Update user and user_profile
            user.first_name = form_data['first_name']
            user.last_name = form_data['last_name']
            user.username = form_data['username']
            user.email = form_data['email']
            user.save()

            user_profile.age = form_data['age']
            user_profile.number = form_data['number']
            if 'image' in request.FILES:
                user_profile.image = request.FILES['image']
            user_profile.save()

            messages.success(request, 'Profile updated successfully!')
            return redirect('userprofile')  
    else:
        form_data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'email': user.email,
            'age': user_profile.age,
            'number': user_profile.number,
        }
        return render(request, 'userprofile.html', {'form_data': form_data})




def userpassword(request):
    return render(request,'userpassword.html')

def userpassword1(request):
    context = {
        'currentPassword': '',
        'currentPassword_error': [],
        'newPassword_error': [],
        'confirmPassword_error': [],
    }
    
    if request.method == 'POST':
        current_password = request.POST['currentPassword']
        new_password = request.POST['newPassword']
        confirm_password = request.POST['confirmPassword']

       
        context['currentPassword'] = current_password

        user = request.user

        if not user.check_password(current_password):
            context['currentPassword_error'].append('Your current password is incorrect.')
        else:
           
            new_password_errors = []

            if not (6 <= len(new_password) <= 15):
                new_password_errors.append('between 6 to 15 characters long')
            if not any(char.isupper() for char in new_password):
                new_password_errors.append('at least one uppercase letter')
            if not any(char.islower() for char in new_password):
                new_password_errors.append('at least one lowercase letter')
            if not any(char.isdigit() for char in new_password):
                new_password_errors.append('at least one digit')
            if not any(char in '!@#$%^&*()_+-={}[]:;"\'|<>,.?/~' for char in new_password):
                new_password_errors.append('at least one special character')

            if new_password_errors:
                context['newPassword_error'].append('New password must be ' + ', '.join(new_password_errors) + '.')

           
            if new_password != confirm_password:
                context['confirmPassword_error'].append('New password and confirm password must match.')

        if not context['currentPassword_error'] and not context['newPassword_error'] and not context['confirmPassword_error']:
            user.set_password(new_password)
            user.save()

            
            update_session_auth_hash(request, user)

            messages.success(request, 'Your password has been successfully updated.')
            return redirect('userpassword')

    return render(request, 'userpassword.html', context)


def userreviews(request, worker_id):
    worker = get_object_or_404(Usermember, id=worker_id)
    
    if request.method == 'POST':
        username = request.POST.get('username')
        review_text = request.POST.get('review')
        ratings = int(request.POST.get('ratings'))
        suggestions = request.POST.get('suggestions', '')
        
        user = get_object_or_404(Usermember2, user=request.user)
        
        Review.objects.create(
            worker=worker,
            user=user,
            username=username,
            review_text=review_text,
            ratings=ratings,
            suggestions=suggestions
        )
        
        messages.success(request, 'Your review has been submitted successfully.')
        return redirect('userreviews', worker_id=worker_id)
    
    return render(request, 'userreviews.html', {'worker': worker})







def logout1(request):
    return render(request,'loginpage1.html')


