from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, validate_email, FileExtensionValidator
from .models import WorkerRequest

from .models import CustomUser, Department, Usermember

class WorkerSignupForm(forms.ModelForm):
    age = forms.IntegerField(required=True)
    contact = forms.CharField(
        max_length=10,
        required=True,
        validators=[RegexValidator(r'^\d{10}$', 'Enter a valid 10-digit contact number.')]
    )
    experience = forms.IntegerField(required=True, label='Experience (years)')
    department = forms.ChoiceField(choices=[], required=True)
    other_department = forms.CharField(
        max_length=100,
        required=False,
        label='Specify other department',
        widget=forms.TextInput(attrs={'style': 'display:none;'})
    )
    email = forms.EmailField(required=True, validators=[validate_email]) 
    image = forms.ImageField(required=True, validators=[FileExtensionValidator(['jpg', 'jpeg', 'png'])])
    supporting_images = forms.ImageField(
        required=True,  # Change to True if this field is required
        validators=[FileExtensionValidator(['jpg', 'jpeg', 'png'])],
        label='Supporting images'
    )

    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'username', 'email']
        help_texts = {
            'username': None,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        predefined_choices = [
            ('', 'Select department'),
            ('carpenter', 'Carpenter'),
            ('electrician', 'Electrician'),
            ('plumbing', 'Plumbing'),
            ('welder', 'Welder'),
        ]
        
        additional_departments = list(Department.objects.values_list('name', flat=True))
        additional_choices = [(dept, dept) for dept in additional_departments]
        additional_choices.append(('other', 'Other'))
        
        self.fields['department'].choices = predefined_choices + additional_choices

    def clean(self):
        cleaned_data = super().clean()
        department = cleaned_data.get('department')
        other_department = cleaned_data.get('other_department')
        
        if department == 'other' and not other_department:
            self.add_error('other_department', "Please specify the other department.")
        return cleaned_data
    
    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')
        if not first_name.isalpha():
            raise ValidationError("Invalid value, Please enter alphabetic characters only.")
        return first_name
    
    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name')
        if not last_name.isalpha():
            raise ValidationError("Invalid value, Please enter alphabetic characters only.")
        return last_name
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        error_messages = []

        if CustomUser.objects.filter(username=username).exists():
            error_messages.append("This username is already taken.")

        if len(username) < 3:
            error_messages.append("Include minimum 3 characters,")
        if not any(char.isdigit() for char in username):
            error_messages.append("1 digit,")
        if not any(char.islower() for char in username):
            error_messages.append("1 lowercase letter,")
        if not any(char.isupper() for char in username):
            error_messages.append("1 uppercase letter,")
        if not any(char in "!@#$%^&*()-_+=<>?/\\:;" for char in username):
            error_messages.append("1 special character.")

        if error_messages:
            raise ValidationError(" ".join(error_messages))

        return username
        
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError("This email is already registered.")
        return email
    
    def clean_age(self):
        age = self.cleaned_data.get('age')
        if age < 18 or age > 60:
            raise ValidationError("Eligible age to register as a worker is between 18 and 60 only.")
        return age
    
    def clean_contact(self):
        contact = self.cleaned_data.get('contact')
        if not contact.isdigit():
            raise ValidationError("Invalid value, Please enter digits only.")
        return contact
    
    def clean_experience(self):
        experience = self.cleaned_data.get('experience')
        if experience < 3:
            raise ValidationError("Minimum 3 years of experience is required to register as a worker.")
        return experience
    
    def clean_department(self):
        department = self.cleaned_data.get('department')
        if not department:
            raise ValidationError("Please select a department.")
        return department
    
    def clean_other_department(self):
        other_department = self.cleaned_data.get('other_department')
        if not other_department:
            return other_department
        if not other_department.replace(' ', '').isalpha():
            raise ValidationError("Invalid value, Please enter alphabetic characters only.")
        return other_department
    
    def clean_image(self):
        image = self.cleaned_data.get('image')
        if not image:
            raise ValidationError("Please select an image.")
        return image
    
    def clean_supporting_images(self):
        supporting_images = self.cleaned_data.get('supporting_images')
        return supporting_images
    



def validate_first_name(value):
    errors = []
    
    if len(value) < 3:
        errors.append('3 characters long')
    
    if not value.isalpha():
        errors.append('only alphabets')
    
    if errors:
        raise ValidationError('Must have ' + ' and '.join(errors))

def validate_last_name(value):
    errors = []
    if len(value) < 3:
        errors.append('3 characters long')
    
    if not value.isalpha():
        errors.append('only alphabets')
    
    if errors:
        raise ValidationError('Must have ' + ' and '.join(errors))


def validate_address(value):
    if len(value) > 50:
        raise ValidationError('Address must not exceed 50 characters.')
    

def validate_age(value):
    errors = []
    if int(value) < 18:
        errors.append('18 years old.')
    if not value.isdigit():
        errors.append('only digits.')
    if errors:
        raise ValidationError('Must have ' + ' and '.join(errors))
    
    

def validate_contact_number(value):
    errors = []
    if len(value) > 10:
        errors.append('maximum 10 digits')
    if not value.isdigit():
        errors.append('only digits.')
    if errors:
        raise ValidationError('Must have ' + ' and '.join(errors))
    

def validate_service(value):
    errors =[]
    if len(value) > 10:
        errors.append('maximum 10 characters.')
    if not value.isalpha():
        errors.append('only alphabets')
    if errors:
        raise ValidationError('Must have ' + ' and '.join(errors))



class RequestForm(forms.Form):
    department = forms.CharField(max_length=255, required=True)
    service = forms.CharField(max_length=255, required=True)

   


