from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit

# This function determines the rate limit based on authentication status
def get_rate_for_sensitive_view(request):
    if request.user.is_authenticated():
        return '10/m' # 10 requests/minute for authenticated users
    return '5/m'

@ratelimit(key='ip', rate=get_rate_for_sensitive_view, method='GET', block=True)
def sensitive_login_view(request):
    """
    A dummy sensitive view to demonstrate IP-based rate limiting.
    In a real application, this will be login form display or API endpoint.
    """
    if request.user.is_authenticated:
        message = "Welcome, {request.user.username}! This view is rate-limited to 10 requests/minute for you."
    else:
        message = "Welcome, anonymous user! This view is rate-limited to 5 requests/minute for your IP."

    return HttpResponse(message)
