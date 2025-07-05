import requests
from urllib.parse import urlparse

def analyze_security_headers(url):
    
    print(f"\n--- Analyzing: {url} ---")
    headers_found = {}
    recommendations = []

    try:
        # Make a HEAD request first to get headers without downloading full content.
        # If HEAD fails or doesn't provide full headers, fall back to GET.
        response = requests.head(url, allow_redirects=True, timeout=10)
        # If HEAD doesn't return many headers or redirects are complex, try GET
        if not response.headers.get('content-type'): # Simple check if headers are sparse
             response = requests.get(url, allow_redirects=True, timeout=10)

        # Ensure we're working with the final URL after redirects
        final_url = response.url
        print(f"  Reached final URL: {final_url}")

        headers = {k.lower(): v for k, v in response.headers.items()} # Normalize headers to lowercase

        # Define security headers to check and their ideal values/checks
        security_header_checks = {
            'strict-transport-security': {
                'present': False,
                'status': 'Missing',
                'value': None,
                'check_func': lambda v: 'Good: Long max-age, includes subdomains' if 'max-age=' in v and int(v.split('max-age=')[1].split(';')[0]) >= 31536000 and 'includesubdomains' in v.lower() else 'Warning: Weak HSTS or short max-age',
                'recommendation': 'Implement/strengthen HSTS to force HTTPS and protect against SSL stripping.'
            },
            'content-security-policy': {
                'present': False,
                'status': 'Missing',
                'value': None,
                'check_func': lambda v: 'Good: Comprehensive policy detected' if len(v) > 20 else 'Warning: Weak or partial CSP', # Simple length check for comprehensiveness
                'recommendation': 'Implement a comprehensive CSP to prevent XSS and data injection.'
            },
            'x-frame-options': {
                'present': False,
                'status': 'Missing',
                'value': None,
                'check_func': lambda v: 'Good: DENY/SAMEORIGIN' if v.lower() in ['deny', 'sameorigin'] else 'Warning: Weak X-Frame-Options',
                'recommendation': 'Implement X-Frame-Options to prevent clickjacking.'
            },
            'x-content-type-options': {
                'present': False,
                'status': 'Missing',
                'value': None,
                'check_func': lambda v: 'Good: nosniff' if v.lower() == 'nosniff' else 'Warning: Missing nosniff',
                'recommendation': 'Implement X-Content-Type-Options: nosniff to prevent MIME-sniffing.'
            },
            'referrer-policy': {
                'present': False,
                'status': 'Missing',
                'value': None,
                'check_func': lambda v: 'Good: Strict policy (no-referrer, same-origin, strict-origin-when-cross-origin)' if v.lower() in ['no-referrer', 'same-origin', 'strict-origin-when-cross-origin'] else 'Warning: Weak or absent Referrer-Policy',
                'recommendation': 'Implement a strict Referrer-Policy to control referrer information leakage.'
            },
            'permissions-policy': { # Formerly Feature-Policy
                'present': False,
                'status': 'Missing',
                'value': None,
                'check_func': lambda v: 'Good: Permissions Policy defined' if v else 'Warning: Permissions Policy missing or empty',
                'recommendation': 'Implement Permissions-Policy to control browser features.'
            },
            'x-xss-protection': { # Deprecated but still seen
                'present': False,
                'status': 'Missing',
                'value': None,
                'check_func': lambda v: 'Good: 1; mode=block' if v == '1; mode=block' else 'Warning: Weak X-XSS-Protection',
                'recommendation': 'Consider comprehensive CSP instead of relying on X-XSS-Protection.'
            },
            'server': { # Information Disclosure
                'present': False,
                'status': 'Hidden', # Default assumes hidden or generic by Cloudflare
                'value': None,
                'check_func': lambda v: 'Generic/Cloudflare' if 'cloudflare' in v.lower() or v.lower() == 'server' else f'Detailed: {v}',
                'recommendation': 'Minimize or obscure Server header information.'
            },
            'x-powered-by': { # Information Disclosure
                'present': False,
                'status': 'Hidden', # Default assumes hidden
                'value': None,
                'check_func': lambda v: f'Detailed: {v}',
                'recommendation': 'Minimize or obscure X-Powered-By header information.'
            }
        }

        # Check for each security header
        for header_name, details in security_header_checks.items():
            if header_name in headers:
                details['present'] = True
                details['value'] = headers[header_name]
                details['status'] = details['check_func'](headers[header_name])
            else:
                details['status'] = 'Missing'
            headers_found[header_name] = details

        # Generate recommendations based on findings
        for header_name, details in headers_found.items():
            if header_name not in ['server', 'x-powered-by'] and not details['present']:
                recommendations.append(details['recommendation'])
            elif header_name in ['server', 'x-powered-by'] and 'Detailed:' in details['status']:
                recommendations.append(details['recommendation'])
            elif header_name == 'strict-transport-security' and 'Warning' in details['status']:
                recommendations.append(details['recommendation'])
            elif header_name == 'content-security-policy' and 'Warning' in details['status']:
                recommendations.append(details['recommendation'])
            elif header_name == 'x-frame-options' and 'Warning' in details['status']:
                recommendations.append(details['recommendation'])
            elif header_name == 'referrer-policy' and 'Warning' in details['status']:
                recommendations.append(details['recommendation'])
            # Add more specific checks for 'Warning' status as needed for other headers

    except requests.exceptions.RequestException as e:
        print(f"  Error accessing {url}: {e}")
        return None, None
    except Exception as e:
        print(f"  An unexpected error occurred for {url}: {e}")
        return None, None

    return headers_found, recommendations

def main():
    # List of CybeReady URLs identified in Phase 1
    target_urls = [
        "https://www.cybeready.com/",
        "https://dashboard.cybeready.com/",
        "https://auth.cybeready.com/",
        "https://go.cybeready.com/",
        "https://support.cybeready.com/"
        # Add more URLs as needed from your Phase 1 findings
    ]

    all_results = {}
    for url in target_urls:
        headers_info, current_recommendations = analyze_security_headers(url)
        if headers_info:
            all_results[url] = {
                'headers': headers_info,
                'recommendations': current_recommendations
            }

    print("\n\n--- Summary of All Analyzed URLs ---")
    for url, data in all_results.items():
        print(f"\nURL: {url}")
        print("  Header Status:")
        for header, details in data['headers'].items():
            value_display = details['value'] if details['value'] else 'N/A'
            print(f"    - {header.ljust(25)}: {details['status'].ljust(40)} (Value: {value_display})")
        if data['recommendations']:
            print("\n  Specific Recommendations:")
            for rec in data['recommendations']:
                print(f"    - {rec}")
        else:
            print("\n  No specific recommendations for security headers found for this URL.")

if __name__ == "__main__":
    main()