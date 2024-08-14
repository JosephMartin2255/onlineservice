from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
# Create your models here.

class CustomUser(AbstractUser):
    user_type = models.CharField(default=1, max_length=10)


class Usermember(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True)
    age = models.IntegerField()
    number = models.CharField(max_length=255, null=True)
    experience = models.IntegerField()
    department = models.CharField(max_length=255, null=True)
    image = models.ImageField(blank=True, upload_to="image/", null=True)
    supporting_images = models.ImageField(blank=True, upload_to="image/", null=True)
    is_approved = models.BooleanField(default=False)
    is_pending = models.BooleanField(default=True)
   
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('disapproved', 'Disapproved'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    def __str__(self):
        return self.user.username


class Department(models.Model):
    name = models.CharField(max_length=255, unique=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, related_name='department_requests')

    def __str__(self):
        return self.name
    


class PendingWorker(models.Model):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.EmailField()
    age = models.IntegerField()
    contact = models.CharField(max_length=10)
    experience = models.IntegerField()
    department = models.CharField(max_length=100)
    image = models.ImageField(upload_to="temp_images/")
    timestamp = models.DateTimeField(auto_now_add=True)
    username = models.CharField(max_length=150, default='')
    supporting_images = models.ImageField(blank=True, upload_to="image/", null=True)  # Add this line

    def __str__(self):
        return f"{self.first_name} {self.last_name}"




class ProfileUpdater:
    def __init__(self, user):
        self.user = user
        try:
            self.usermember = Usermember.objects.get(user=user)
        except Usermember.DoesNotExist:
            self.usermember = None

    def update_profile(self, first_name, last_name, email, age, number, experience, department, image=None):
        self.user.first_name = first_name
        self.user.last_name = last_name
        self.user.email = email
        self.user.save()

        if self.usermember:
            self.usermember.age = age
            self.usermember.number = number
            self.usermember.experience = experience
            self.usermember.department = department
            if image:
                self.usermember.image = image
            self.usermember.save()

        return self.user, self.usermember

class Usermember2(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True)
    age = models.IntegerField()
    number = models.CharField(max_length=255, null=True)
    image = models.ImageField(blank=True, upload_to="image/", null=True)
    address = models.TextField(null=True)  # New field for address
    date = models.DateField(null=True)      # New field for date




class WorkerRequest(models.Model):
    worker = models.ForeignKey(Usermember, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    address = models.TextField()
    date = models.DateField()
    age = models.IntegerField()
    email = models.EmailField()
    contact_number = models.CharField(max_length=15)
    department = models.CharField(max_length=255)
    service = models.CharField(max_length=255)
    photo = models.ImageField(upload_to="request_photos/", null=True, blank=True)
    status = models.CharField(max_length=50, default='Pending')
    completed = models.BooleanField(default=False)

class Review(models.Model):
    worker = models.ForeignKey(Usermember, on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(Usermember2, on_delete=models.CASCADE, related_name='reviews')
    username = models.CharField(max_length=255)
    review_text = models.TextField()
    ratings = models.IntegerField()
    suggestions = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.username} - {self.worker}"
    




class Request(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    usermember2 = models.ForeignKey(Usermember2, on_delete=models.CASCADE, null=True)
    worker = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='worker_requests', null=True)  # Add this field
    department = models.CharField(max_length=255)
    service = models.CharField(max_length=255)
    confirmed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='confirmed_requests')
    created_at = models.DateTimeField(auto_now_add=True)
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('deleted', 'Deleted'),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    completed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.department} - {self.service}"


class AcceptedRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True)
    usermember2 = models.ForeignKey(Usermember2, on_delete=models.CASCADE, null=True)
    worker = models.ForeignKey(CustomUser, related_name='accepted_requests', on_delete=models.CASCADE, null=True)
    request = models.ForeignKey(Request, on_delete=models.CASCADE)
    accepted_at = models.DateTimeField(auto_now_add=True)
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('deleted', 'Deleted'),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    completed = models.BooleanField(default=False)
