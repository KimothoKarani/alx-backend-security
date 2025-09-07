from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP
from django.contrib.gis.geoip2 import GeoIP2 # Import GeoIP2
from django.core.cache import cache # Import Django's cache
import logging

logger = logging.getLogger(__name__)

class IPLoggingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip = None
        country = None
        city = None

        # django-ipgeolocation will have processed the request and potentially
        # set request.geolocation if its middleware runs before this one.
        if hasattr(request, 'geolocation') and request.geolocation and request.geolocation.ip:
            ip = request.geolocation.ip
        else:
            # Fallback if django-ipgeolocation somehow didn't provide it
            # or if its middleware isn't active/properly configured.
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0].strip()
            else:
                ip = request.META.get('REMOTE_ADDR')

        if not ip:
            logger.warning("Could not determine IP address for request path: %s", request.path)
            return None # Continue processing without IP if it can't be determined

        # Check if the IP is blocked
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP address has been blocked.")

        # --- Geolocation Logic ---
        cache_key = f"geolocation_{ip}"
        cached_geo_data = cache.get(cache_key)

        if cached_geo_data:
            country = cached_geo_data.get('country')
            city = cached_geo_data.get('city')
            # logger.debug(f"Geolocation for IP {ip} fetched from cache.")
        else:
            try:
                g = GeoIP2()
                # Use g.city() for more detailed information including city
                geo_data = g.city(ip)
                if geo_data:
                    country = geo_data.get('country_name')
                    city = geo_data.get('city')
                    # Cache the results for 24 hours (86400 seconds defined in settings)
                    cache.set(cache_key, {'country': country, 'city': city})
                    # logger.debug(f"Geolocation for IP {ip} fetched via GeoIP2 and cached.")
                else:
                    logger.info(f"Could not geolocate IP: {ip}. No GeoIP2 data found.")
            except Exception as e:
                # GeoIP2 might raise an exception for private IPs or invalid IPs
                logger.error(f"Error during GeoIP2 lookup for IP {ip}: {e}")

        # Log the request with geolocation data
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=country,
            city=city
        )
        return None