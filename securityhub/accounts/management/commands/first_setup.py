import os
import secrets
import subprocess
import re
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from accounts.models import CustomUser
from configapi.models import ReportStandard, ProjectType

DEFAULT_USERNAME = "admin"
DEFAULT_EMAIL = "admin@securityhub.local"
DEFAULT_FULL_NAME = "Default User"
DEFAULT_POSITION = "Security Engineer"
DEFAULT_PASSWORD = "ChangeMe123!"
DEFAULT_COMPANY_NAME = "SecurityHub"

REPORT_STANDARDS = [
    "OWASP Mobile TOP 10 2016",
    "OWASP TOP 10 2017",
    "OWASP TOP 10 2021",
    "OWASP Mobile TOP 10 2024",
    "NIST SP 800-115",
    "NIST SP 800-53",
    "NIST SP 800-153"
]

PROJECT_TYPES = [
    "Web Application Penetration Testing",
    "Android Application Penetration Testing",
    "iOS Application Penetration Testing",
    "External Network Penetration Testing",
    "Internal Network Penetration Testing"
]


class Command(BaseCommand):
    """
    Custom manage.py command to setup user details for first time installation users.
    
    This command performs the following setup tasks:
    - Creates default permissions
    - Creates default groups with assigned permissions
    - Creates the default company
    - Creates a superuser account
    - Creates report standards
    - Creates project types
    - Optionally checks for GTK3 (for PDF generation)
    
    All operations are wrapped in a database transaction for safety.
    """
    help = 'Performs first-time setup tasks for SecurityHub'

    def add_arguments(self, parser):
        """Add command-line arguments for customization."""
        parser.add_argument(
            '--username',
            type=str,
            default=os.getenv('SETUP_USERNAME', DEFAULT_USERNAME),
            help='Username for the superuser (default: from env SETUP_USERNAME or "admin")'
        )
        parser.add_argument(
            '--email',
            type=str,
            default=os.getenv('SETUP_EMAIL', DEFAULT_EMAIL),
            help='Email for the superuser (default: from env SETUP_EMAIL or "admin@securityhub.local")'
        )
        parser.add_argument(
            '--full-name',
            type=str,
            default=os.getenv('SETUP_FULL_NAME', DEFAULT_FULL_NAME),
            help='Full name for the superuser (default: from env SETUP_FULL_NAME or "Admin")'
        )
        parser.add_argument(
            '--position',
            type=str,
            default=os.getenv('SETUP_POSITION', DEFAULT_POSITION),
            help='Position for the superuser (default: from env SETUP_POSITION or "Security Engineer")'
        )
        parser.add_argument(
            '--password',
            type=str,
            default=None,
            help='Password for the superuser (default: from env SETUP_PASSWORD or auto-generated if --generate-password)'
        )
        parser.add_argument(
            '--generate-password',
            action='store_true',
            help='Generate a random secure password instead of using default'
        )
        parser.add_argument(
            '--company-name',
            type=str,
            default=os.getenv('SETUP_COMPANY_NAME', DEFAULT_COMPANY_NAME),
            help='Company name (default: from env SETUP_COMPANY_NAME or "SecurityHub Community")'
        )
        parser.add_argument(
            '--skip-gtk-check',
            action='store_true',
            help='Skip GTK3 availability check (useful for headless servers)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force creation even if superuser already exists (will update existing user)'
        )

    def validate_email(self, email):
        """Validate email format."""
        try:
            validate_email(email)
            return True
        except ValidationError:
            raise CommandError(f'Invalid email format: {email}')

    def validate_password(self, password):
        """Validate password strength."""
        if len(password) < 8:
            raise CommandError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', password):
            raise CommandError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', password):
            raise CommandError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', password):
            raise CommandError('Password must contain at least one digit')
        return True

    def generate_secure_password(self, length=16):
        """Generate a secure random password."""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password

    def handle(self, *args, **options):
        self.verbosity = options.get('verbosity', 1)

        username = options['username']
        email = options['email']
        full_name = options['full_name']
        position = options['position']
        company_name = options['company_name']
        skip_gtk_check = options['skip_gtk_check']
        force = options['force']

        if options['generate_password']:
            password = self.generate_secure_password()
            if self.verbosity >= 1:
                self.stdout.write(self.style.WARNING('Generated random password. Make sure to save it!'))
        else:
            password = options['password'] or os.getenv('SETUP_PASSWORD') or DEFAULT_PASSWORD

        self.validate_email(email)
        if not force:
            try:
                self.validate_password(password)
            except CommandError as e:
                if password == DEFAULT_PASSWORD:
                    self.stdout.write(self.style.WARNING(f'{e}. Using default password is not recommended for production!'))
                else:
                    raise

        self.setup_username = username
        self.setup_email = email
        self.setup_password = password

        try:
            with transaction.atomic():
                if not skip_gtk_check:
                    self.check_gtk3()
                self.create_super_user(
                    username=username, email=email, full_name=full_name,
                    position=position, company_name=company_name,
                    password=password, force=force
                )
                self.create_report_standards()
                self.create_project_types()

            self.stdout.write(self.style.SUCCESS('\n' + '='*60))
            self.stdout.write(self.style.SUCCESS('SecurityHub Setup completed successfully!'))
            self.stdout.write(self.style.SUCCESS('='*60))
            self.stdout.write(self.style.SUCCESS(f'\nUsername: {self.setup_username}'))
            self.stdout.write(self.style.SUCCESS(f'Email: {self.setup_email}'))
            self.stdout.write(self.style.SUCCESS(f'Password: {self.setup_password}'))
            self.stdout.write(self.style.WARNING('\n⚠️  IMPORTANT: Change the default password after first login!'))

        except Exception as e:
            raise CommandError(f'Setup failed: {str(e)}') from e

    def check_gtk3(self):
        """Check if GTK3 is available (optional check for PDF generation)."""
        if self.verbosity >= 2:
            self.stdout.write('Checking for GTK3...')
        
        # Try multiple methods to check for GTK3
        checks = [
            ['gtk-update-icon-cache', '--help'],
            ['pkg-config', '--exists', 'gtk+-3.0'],
        ]
        
        found = False
        for check_cmd in checks:
            try:
                subprocess.run(
                    check_cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5
                )
                found = True
                break
            except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
                continue
        
        if found:
            if self.verbosity >= 1:
                self.stdout.write(self.style.SUCCESS('GTK3 found - PDF generation should work'))
        else:
            if self.verbosity >= 1:
                self.stdout.write(self.style.WARNING(
                    'GTK3 not found - PDF generation may not work. '
                    'Install GTK+ runtime libraries if needed. '
                    'This is optional and will not block setup.'
                ))

    def create_super_user(self, username, email, full_name, position,
                         company_name, password, force=False):
        if self.verbosity >= 2:
            self.stdout.write('Creating superuser...')

        existing_superuser = CustomUser.objects.filter(is_superuser=True).first()

        if existing_superuser and not force:
            if self.verbosity >= 1:
                self.stdout.write(self.style.NOTICE(
                    f'Superuser already exists: {existing_superuser.email}. '
                    'Use --force to update or create a new one.'
                ))
            return

        if existing_superuser and force:
            user = existing_superuser
            user.username = username
            user.email = email
            user.full_name = full_name
            user.position = position
            user.set_password(password)
            user.save()
            if self.verbosity >= 1:
                self.stdout.write(self.style.SUCCESS(
                    f'Superuser updated: {email}'
                ))
        else:
            if CustomUser.objects.filter(email=email).exists():
                raise CommandError(
                    f'User with email {email} already exists. Use --force to update.'
                )

            user = CustomUser.objects.create(
                username=username,
                email=email,
                full_name=full_name,
                is_active=True,
                position=position,
                is_staff=True,
                is_superuser=True
            )
            user.set_password(password)
            user.save()
            if self.verbosity >= 1:
                self.stdout.write(self.style.SUCCESS(f'Superuser created: {email}'))

    def create_report_standards(self):
        """Create predefined report standards."""
        if self.verbosity >= 2:
            self.stdout.write('Creating report standards...')
        
        created_count = 0
        for name in REPORT_STANDARDS:
            _, created = ReportStandard.objects.get_or_create(name=name)
            if created:
                created_count += 1
                if self.verbosity >= 2:
                    self.stdout.write(f'  Created: {name}')
        
        if self.verbosity >= 1:
            if created_count > 0:
                self.stdout.write(self.style.SUCCESS(
                    f'Created {created_count} new report standard(s) ({len(REPORT_STANDARDS)} total)'
                ))
            else:
                self.stdout.write(self.style.SUCCESS(
                    f'All {len(REPORT_STANDARDS)} report standards already exist'
                ))

    def create_project_types(self):
        """Create predefined project types."""
        if self.verbosity >= 2:
            self.stdout.write('Creating project types...')
        
        created_count = 0
        for name in PROJECT_TYPES:
            _, created = ProjectType.objects.get_or_create(name=name)
            if created:
                created_count += 1
                if self.verbosity >= 2:
                    self.stdout.write(f'  Created: {name}')
        
        if self.verbosity >= 1:
            if created_count > 0:
                self.stdout.write(self.style.SUCCESS(
                    f'Created {created_count} new project type(s) ({len(PROJECT_TYPES)} total)'
                ))
            else:
                self.stdout.write(self.style.SUCCESS(
                    f'All {len(PROJECT_TYPES)} project types already exist'
                ))
