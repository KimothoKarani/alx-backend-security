from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from django.forms import ValidationError
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = "Adds an IP address to the blacklist to prevent access."

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help="The IP address to block (IPv4 or IPv6).")

    def handle(self, *args, **options):
        ip_address = options['ip_address']

        # Validate IP address format
        try:
            validate_ipv4_address(ip_address)
        except ValidationError:
            try:
                validate_ipv6_address(ip_address)
            except ValidationError:
                raise CommandError(f'"{ip_address}" is not a valid IPv4 or IPv6 address.')

        try:
            blocked_ip, created = BlockedIP.objects.get_or_create(ip_address=ip_address)
            if created:
                self.stdout.write(self.style.SUCCESS(f'Successfully blocked IP: "{ip_address}"'))
            else:
                self.stdout.write(self.style.WARNING(f'IP: "{ip_address}" is already in the blacklist.'))
        except Exception as e:
            raise CommandError(f'Error blocking IP "{ip_address}": {e}')
