from .models import UserModel
from django.contrib.auth.hashers import make_password

EMAIL = "superadmin@yopmail.com"
PASSWORD = "test@123"

def create_default_profile(**kwargs):
    try:
        if not UserModel.objects.filter(email=EMAIL,is_superuser=True).exists():
            user = UserModel(
                email = EMAIL,
                first_name = "Super",
                last_name = "Admin",
                password = make_password(PASSWORD),
                is_active = True,
                is_staff = True,
                is_superuser = True,
            )
            user.save()
            print("Superuser is successfully created!")
    except Exception as e:
        print(str(e))